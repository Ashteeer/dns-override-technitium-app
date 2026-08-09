#!/usr/bin/env bash
# Установка приложения DNS Override в Technitium DNS Server. Одной командой,
# без сборки: скрипт качает готовый zip из последнего GitHub-релиза и заливает
# его через API Technitium.
#
#   curl -fsSL https://raw.githubusercontent.com/Ashteeer/dns-override-technitium-app/main/deploy/install.sh \
#     | sudo bash -s -- --password ПАРОЛЬ_АДМИНКИ
#
# Скрипт рассчитан на полностью новую машину:
#   1. системные пакеты (curl, ca-certificates, acl);
#   2. Technitium DNS Server, если его нет (официальный установщик);
#   3. каталог /etc/dns-override с правами на чтение/запись для Technitium;
#   4. скачивание DnsOverrideApp.zip из релиза и install/update через API.
#
# Правилами управляет Telegram-бот — он компилирует /etc/dns-override/ruleset.dat:
#   https://github.com/Ashteeer/dns-override-telegram-bot
# Если нужен и бот, ставьте сразу его установщиком: он поставит приложение сам.

set -euo pipefail

APP_REPO=${APP_REPO:-Ashteeer/dns-override-technitium-app}
APP_NAME=${APP_NAME:-DNS Override}
SHARED_DIR=${SHARED_DIR:-/etc/dns-override}
SHARED_GROUP=${SHARED_GROUP:-dns-override}
DNS_UNIT=${DNS_UNIT:-dns.service}
DNS_SERVICE_USER=${DNS_SERVICE_USER:-}
DNS_INSTALLER_URL=${DNS_INSTALLER_URL:-https://download.technitium.com/dns/install.sh}
DEFAULT_API_URL=http://127.0.0.1:5380

API_URL=""
API_TOKEN=""
API_USER=""
API_PASSWORD=""
REF=""
WITH_DNS_SERVER=1
INSECURE=0

TMP_DIR=""
DNS_JUST_INSTALLED=0
APT_UPDATED=0

note() { printf '    %s\n' "$*"; }
warn() { printf '    ⚠️  %s\n' "$*" >&2; }
die()  { echo "$*" >&2; exit 1; }

# return 0 обязателен: код последней команды в ловушке EXIT становится кодом
# выхода скрипта, и без него даже `--help` завершался бы единицей.
cleanup() { [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

usage() {
    cat <<'EOF'
Установка приложения DNS Override в Technitium DNS Server (без сборки).

  curl -fsSL https://raw.githubusercontent.com/Ashteeer/dns-override-technitium-app/main/deploy/install.sh \
    | sudo bash -s -- --password ПАРОЛЬ_АДМИНКИ

Опции:
  --api IP:PORT        адрес админки Technitium; схему можно опустить,
                       подставится http:// (по умолчанию 127.0.0.1:5380)
  --token TOKEN        постоянный API-токен Technitium
  --user USER          логин админки (по умолчанию admin)
  --password PASS      пароль админки (по умолчанию admin — как у свежей установки)
  --name NAME          имя приложения в админке (по умолчанию «DNS Override»)
  --ref TAG            какую версию ставить (тег релиза). По умолчанию последний
  --no-dns-server      не устанавливать Technitium DNS Server, даже если его нет
  --insecure           не проверять TLS-сертификат админки (для https с самоподписанным)
  -h, --help           эта справка

Переопределяются переменными окружения:
  APP_REPO APP_NAME SHARED_DIR SHARED_GROUP DNS_UNIT DNS_SERVICE_USER
  DNS_INSTALLER_URL
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-dns-server) WITH_DNS_SERVER=0; shift ;;
        --insecure)      INSECURE=1; shift ;;
        --api)           [[ $# -ge 2 ]] || die "--api: не указано значение"; API_URL="$2"; shift 2 ;;
        --api=*)         API_URL="${1#*=}"; shift ;;
        --token)         [[ $# -ge 2 ]] || die "--token: не указано значение"; API_TOKEN="$2"; shift 2 ;;
        --token=*)       API_TOKEN="${1#*=}"; shift ;;
        --user)          [[ $# -ge 2 ]] || die "--user: не указано значение"; API_USER="$2"; shift 2 ;;
        --user=*)        API_USER="${1#*=}"; shift ;;
        --password)      [[ $# -ge 2 ]] || die "--password: не указано значение"; API_PASSWORD="$2"; shift 2 ;;
        --password=*)    API_PASSWORD="${1#*=}"; shift ;;
        --name)          [[ $# -ge 2 ]] || die "--name: не указано значение"; APP_NAME="$2"; shift 2 ;;
        --name=*)        APP_NAME="${1#*=}"; shift ;;
        --ref)           [[ $# -ge 2 ]] || die "--ref: не указано значение"; REF="$2"; shift 2 ;;
        --ref=*)         REF="${1#*=}"; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               die "неизвестный аргумент: $1 (см. --help)" ;;
    esac
done

if [[ -n "$API_URL" ]]; then
    [[ "$API_URL" =~ ^https?:// ]] || API_URL="http://$API_URL"
    API_URL="${API_URL%/}"
    [[ "$API_URL" =~ ^https?://[^/[:space:]]+$ ]] || \
        die "--api: ожидался IP:PORT или http[s]://host:port, получено '$API_URL'"
fi

[[ $EUID -eq 0 ]] || die "нужны права root: запускайте через sudo"

# --------------------------------------------------------------------- утилиты

apt_install() {
    if [[ $APT_UPDATED -eq 0 ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        APT_UPDATED=1
    fi
    apt-get install -y -qq "$@"
}

urlencode() {
    local s=$1 out="" c i
    for (( i = 0; i < ${#s}; i++ )); do
        c=${s:i:1}
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *)               out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

CURL_OPTS=(-fsSL --max-time 120)
api_curl() {
    local opts=("${CURL_OPTS[@]}")
    [[ $INSECURE -eq 1 ]] && opts+=(--insecure)
    curl "${opts[@]}" "$@"
}

# Значение строкового поля JSON верхнего уровня — без jq, его тут может не быть.
json_field() {
    grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -n1 | cut -d'"' -f4
}

api_ok() { grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; }

api_error() {
    local msg
    msg=$(printf '%s' "$1" | json_field errorMessage)
    printf '%s' "${msg:-непонятный ответ API: ${1:0:200}}"
}

# --------------------------------------------------------------------- пакеты

echo "==> пакеты"
apt_install curl ca-certificates acl

# ------------------------------------------------------- Technitium DNS Server

echo "==> Technitium DNS Server"
if systemctl cat "$DNS_UNIT" >/dev/null 2>&1; then
    note "$DNS_UNIT уже есть — пропускаю"
elif [[ $WITH_DNS_SERVER -eq 0 ]]; then
    die "$DNS_UNIT не найден, а установка отключена (--no-dns-server)"
else
    note "не найден — ставлю официальным установщиком Technitium"
    curl -fsSL "$DNS_INSTALLER_URL" | bash || die "установка Technitium DNS Server не удалась"
    systemctl cat "$DNS_UNIT" >/dev/null 2>&1 \
        || die "$DNS_UNIT не появился после установки — проверьте вывод выше"
    DNS_JUST_INSTALLED=1
    note "установлен, админка: http://<ip>:5380 (логин admin, пароль admin)"
fi

API_URL=${API_URL:-$DEFAULT_API_URL}
API_USER=${API_USER:-admin}
# У свежей установки Technitium пара admin/admin — с ней и работаем, пока
# пользователь не сменил пароль и не передал его через --password.
API_PASSWORD=${API_PASSWORD:-admin}

# ------------------------------------------------------------ каталог правил

echo "==> каталог правил $SHARED_DIR"
getent group "$SHARED_GROUP" >/dev/null || groupadd --system "$SHARED_GROUP"
install -d -m 2770 -g "$SHARED_GROUP" "$SHARED_DIR"

detect_dns_user() {
    if [[ -n "$DNS_SERVICE_USER" ]]; then
        echo "$DNS_SERVICE_USER"
        return
    fi
    # Пустой User= в unit-файле означает root.
    local from_unit
    from_unit=$(systemctl show -p User --value "$DNS_UNIT" 2>/dev/null || true)
    echo "${from_unit:-root}"
}

DNS_USER=$(detect_dns_user)
if [[ "$DNS_USER" == "root" ]]; then
    note "Technitium работает от root — доступ уже есть, ACL не нужен"
elif ! id -u "$DNS_USER" >/dev/null 2>&1; then
    warn "пользователь '$DNS_USER' из $DNS_UNIT не существует — доступ не настроен"
else
    usermod -aG "$SHARED_GROUP" "$DNS_USER" || warn "usermod для $DNS_USER не сработал"
    # ACL действует немедленно, перезапускать dns.service не нужно.
    # Приложению нужна запись: оно создаёт runtime-state.json.
    setfacl -m "u:${DNS_USER}:rwx" -m "d:u:${DNS_USER}:rw-" "$SHARED_DIR"
    for existing in "$SHARED_DIR"/*; do
        [[ -e "$existing" ]] || continue
        setfacl -m "u:${DNS_USER}:rw-" "$existing"
    done
    note "ACL выставлен для пользователя '$DNS_USER'"
fi

# ---------------------------------------------------------- запись из-под systemd

# ACL решает вопрос прав, но не вопрос монтирования. Если в dns.service стоит
# ProtectSystem=full или strict, systemd монтирует /etc внутрь сервиса только
# для чтения, и приложение получает «Read-only file system» при записи
# runtime-state.json — при любых ACL. Лечится единственным способом:
# ReadWritePaths с нужным каталогом.
#
# Кладём отдельным drop-in, а не правкой dns.service: официальный установщик
# Technitium перезаписывает юнит на каждом обновлении, а этот каталог не трогает.
DROPIN_DIR="/etc/systemd/system/${DNS_UNIT}.d"
DROPIN="$DROPIN_DIR/10-dns-override.conf"
DROPIN_CHANGED=0

if systemctl cat "$DNS_UNIT" >/dev/null 2>&1; then
    TMP_DROPIN=$(mktemp)
    cat > "$TMP_DROPIN" <<EOF
# Создано установщиком DNS Override. Нужен, чтобы приложение могло писать
# runtime-state.json при ProtectSystem= в юните DNS-сервера.
[Service]
ReadWritePaths=$SHARED_DIR
EOF
    if [[ -f "$DROPIN" ]] && cmp -s "$TMP_DROPIN" "$DROPIN"; then
        note "drop-in $DROPIN уже на месте"
    elif [[ -f "$DROPIN" ]] && grep -q "^ReadWritePaths=$SHARED_DIR$" "$DROPIN"; then
        # Файл мог создать бот — там ещё AmbientCapabilities. Не затираем.
        note "drop-in $DROPIN уже содержит ReadWritePaths"
    else
        install -d -m 0755 "$DROPIN_DIR"
        install -m 0644 "$TMP_DROPIN" "$DROPIN"
        systemctl daemon-reload
        DROPIN_CHANGED=1
        note "записан $DROPIN"
    fi
    rm -f "$TMP_DROPIN"
fi

# --------------------------------------------------------------- релиз с GitHub

echo "==> релиз $APP_REPO"
if [[ -n "$REF" ]]; then
    RELEASE_API="https://api.github.com/repos/$APP_REPO/releases/tags/$REF"
else
    RELEASE_API="https://api.github.com/repos/$APP_REPO/releases/latest"
fi

RELEASE_JSON=$(curl -fsSL "$RELEASE_API") || die "не удалось получить релиз: $RELEASE_API"
TAG=$(printf '%s' "$RELEASE_JSON" | json_field tag_name)
ZIP_URL=$(printf '%s' "$RELEASE_JSON" \
    | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*\.zip"' \
    | head -n1 | cut -d'"' -f4)
[[ -n "$ZIP_URL" ]] || die "в релизе ${TAG:-?} нет zip-ассета"

TMP_DIR=$(mktemp -d)
ZIP_PATH="$TMP_DIR/DnsOverrideApp.zip"
note "качаю $TAG: $(basename "$ZIP_URL")"
curl -fsSL -o "$ZIP_PATH" "$ZIP_URL" || die "не скачался $ZIP_URL"
note "$(stat -c '%s' "$ZIP_PATH") байт"

# ------------------------------------------------------------------ токен API

echo "==> API Technitium ($API_URL)"
# После свежей установки веб-сервис поднимается не мгновенно.
for _ in $(seq 1 30); do
    if api_curl -o /dev/null --max-time 2 "$API_URL/api/user/login" 2>/dev/null; then
        break
    fi
    sleep 2
done

if [[ -z "$API_TOKEN" ]]; then
    CREDS="user=$(urlencode "$API_USER")&pass=$(urlencode "$API_PASSWORD")"
    # createToken — рекомендованный способ в свежих версиях, login оставлен запасным.
    for path_and_args in \
        "api/user/createToken?$CREDS&tokenName=dns-override-installer" \
        "api/user/login?$CREDS&includeInfo=false"
    do
        RESP=$(api_curl "$API_URL/$path_and_args" 2>/dev/null) || continue
        API_TOKEN=$(printf '%s' "$RESP" | json_field token)
        if [[ -n "$API_TOKEN" ]]; then
            break
        fi
    done
    [[ -n "$API_TOKEN" ]] || die "не удалось получить токен: проверьте --user/--password или передайте --token"
    note "токен получен"
fi

NAME_Q=$(urlencode "$APP_NAME")

# --------------------------------------------------------- установка/обновление

RESP=$(api_curl "$API_URL/api/apps/list?token=$(urlencode "$API_TOKEN")") \
    || die "apps/list недоступен"
printf '%s' "$RESP" | api_ok || die "apps/list: $(api_error "$RESP")"

if printf '%s' "$RESP" | grep -q "\"name\"[[:space:]]*:[[:space:]]*\"$APP_NAME\""; then
    ACTION=update
    note "приложение уже установлено — обновляю"
else
    ACTION=install
    note "приложение не установлено — первая установка"
fi

RESP=$(api_curl -X POST -F "file=@$ZIP_PATH;type=application/zip" \
    "$API_URL/api/apps/$ACTION?token=$(urlencode "$API_TOKEN")&name=$NAME_Q") \
    || die "apps/$ACTION: запрос не прошёл"
printf '%s' "$RESP" | api_ok || die "apps/$ACTION: $(api_error "$RESP")"

VERSION=$(api_curl "$API_URL/api/apps/list?token=$(urlencode "$API_TOKEN")" \
    | grep -o "\"name\"[[:space:]]*:[[:space:]]*\"$APP_NAME\"[^}]*" | json_field version)

echo
echo "Готово: «$APP_NAME» ${VERSION:+версии $VERSION }установлено ($TAG)."
STEP=1
echo "$STEP. Настройки приложения: админка → Apps → $APP_NAME → Config."; STEP=$((STEP + 1))
echo "$STEP. Правила приложение читает из $SHARED_DIR/ruleset.dat."
echo "   Этот файл компилирует Telegram-бот:"
echo "   https://github.com/Ashteeer/dns-override-telegram-bot"
STEP=$((STEP + 1))
if [[ $DROPIN_CHANGED -eq 1 ]]; then
    echo "$STEP. Перезапустите DNS-сервер — без этого drop-in не действует и"
    echo "   приложение не сможет записать runtime-state.json:"
    echo "   systemctl restart $DNS_UNIT"
    STEP=$((STEP + 1))
fi
if [[ $DNS_JUST_INSTALLED -eq 1 ]]; then
    echo "$STEP. Смените пароль admin в админке Technitium (http://<ip>:5380)."
fi
