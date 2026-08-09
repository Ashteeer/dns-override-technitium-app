# Сборка и установка приложения

Целевая платформа — Ubuntu 24.04 LTS+. Сборка локальная, CI/CD не используется.

## Установка без сборки

Готовый `DnsOverrideApp.zip` лежит ассетом в каждом релизе — собирать его
пользователю не нужно. Одна команда на чистой машине:

```bash
curl -fsSL https://raw.githubusercontent.com/Ashteeer/dns-override-technitium-app/main/deploy/install.sh | sudo bash -s -- --password ПАРОЛЬ_АДМИНКИ
```

[`deploy/install.sh`](../deploy/install.sh) ставит пакеты (`curl`,
`ca-certificates`, `acl`), при отсутствии — сам Technitium DNS Server, создаёт
`/etc/dns-override` с ACL для пользователя Technitium, качает zip из последнего
релиза и заливает его в `apps/install` (или `apps/update`, если приложение уже
стоит). Опции — `--api`, `--token`, `--user`, `--password`, `--name`, `--ref`,
`--no-dns-server`, `--insecure`.

Тот же результат даёт установщик бота: он ставит приложение через API сам.
Ручные варианты — в разделе [Установка](#установка) ниже.

Всё, что следует дальше, нужно только для разработки приложения.

## Требования

- .NET SDK 10.0+ (`apt install dotnet-sdk-10.0` или `dotnet-install.sh`)
- git, zip

## Зависимости сборки

Приложения Technitium собираются не из NuGet, а против исходников сервера:
`ProjectReference` на `DnsServerCore.ApplicationCommon.csproj` и `Reference` на
`TechnitiumLibrary.dll` и `TechnitiumLibrary.Net.dll`. Поэтому рядом нужны два
репозитория Technitium:

```
~/dev/
├── DnsServer/                      git clone https://github.com/TechnitiumSoftware/DnsServer
├── TechnitiumLibrary/              git clone https://github.com/TechnitiumSoftware/TechnitiumLibrary
└── dns-override-technitium-app/
```

`TechnitiumLibrary` нужно **собрать до** приложения: `DnsServerCore.ApplicationCommon`
ссылается на готовые `TechnitiumLibrary/bin/*.dll`, а не на проекты.
В конфигурации `Release` вывод как раз идёт в `TechnitiumLibrary/bin/`:

```bash
dotnet build TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release
```

Путь к обоим репозиториям определяется в `Directory.Build.props` в таком порядке:

1. переменная окружения `TECHNITIUM_SRC` (или `-p:TechnitiumSrc=...`);
2. каталог рядом с репозиторием — `../DnsServer`;
3. каталог на уровень выше — `../../DnsServer` (раскладка umbrella-воркспейса).

Если ни один вариант не подошёл, сборка падает с явным сообщением, а не с
«не найден тип `IDnsApplication`».

Версию `DnsServer` брать ту же, что установлена на сервере: контракт
`IDnsApplication` между мажорными версиями меняется. Проверено на
`DnsServer` 15.4 (`DnsServerCore.ApplicationCommon` 10.1) и `TechnitiumLibrary.Net` 14.3.

## Сборка

```bash
./build/build.sh
```

На Windows-хосте разработки — то же самое:

```powershell
.\build\build.ps1
```

Скрипт делает `dotnet publish -c Release -f net10.0` в `build/publish/`
и упаковывает `build/out/DnsOverrideApp.zip`.

В zip кладутся ровно четыре файла:

| Файл | Назначение |
|---|---|
| `DnsOverrideApp.dll` | сборка приложения |
| `DnsOverrideApp.deps.json` | **обязателен**: сервер ищет приложения перебором `*.deps.json` в каталоге приложения и грузит одноимённый `.dll`. Без него приложение не будет найдено |
| `dnsApp.config` | стартовый конфиг-указатель на `ruleset.dat`, см. [`ruleset-loading.md §1`](ruleset-loading.md#1-конфигурация-самого-приложения) |
| `README.md` | описание, видимое в админке Technitium |

Библиотеки `DnsServerCore.ApplicationCommon.dll` и `TechnitiumLibrary.*.dll`
в zip **не кладутся** — они уже загружены сервером (`Private=false` в csproj).
Если положить — приложение не загрузится из-за конфликта типов.

## Установка

Скриптом (без сборки) — см. [выше](#установка-без-сборки). Вручную:

через админку: **Apps → Install** → выбрать `DnsOverrideApp.zip`.

Через API:

```bash
curl -F "file=@build/out/DnsOverrideApp.zip" \
  "http://127.0.0.1:5380/api/apps/install?token=API_TOKEN&name=DNS%20Override"
```

Обновление — тот же zip на `/api/apps/update`. Сервер выгружает старую сборку,
загружает новую и вызывает `InitializeAsync` — рестарт `dns.service` не нужен.
Существующий `dnsApp.config` при обновлении **не перезаписывается**: сервер
пропускает эту запись архива, если файл уже есть.

## Подготовка каталога правил

Каталог создают оба установщика — и [`deploy/install.sh`](../deploy/install.sh)
этого репозитория, и установщик бота: они выставляют POSIX ACL, которые
действуют немедленно, без перезапуска `dns.service`. Вручную:

```bash
sudo groupadd -f dns-override
sudo usermod -aG dns-override dns                 # пользователь Technitium
sudo usermod -aG dns-override dns-override-bot    # пользователь бота
sudo install -d -o root -g dns-override -m 0770 /etc/dns-override
```

В каталоге живут ровно два файла: `ruleset.dat` (пишет бот) и `runtime-state.json`
(пишет приложение). Для первого запуска можно положить пример из
`config-examples/ruleset.dat`, поправив `targets` под свою сеть, — дальше файл
полностью перегенерирует бот.

Права нужны обе стороны: приложению — чтение `ruleset.dat` и запись
`runtime-state.json` (плюс `runtime-state.json.tmp` в том же каталоге).

Если в юните DNS-сервера есть `ProtectSystem=full` или `strict`, одних прав мало:
systemd монтирует `/etc` внутрь сервиса только для чтения, и приложение получает
`Read-only file system` при любых ACL. Нужен drop-in — установщик кладёт его сам:

```ini
# /etc/systemd/system/dns.service.d/10-dns-override.conf
[Service]
ReadWritePaths=/etc/dns-override
```

Отдельный файл, а не правка `dns.service`: установщик Technitium перезаписывает
юнит при обновлении, а этот каталог не трогает. Применяется только после
`systemctl restart dns` — `daemon-reload` недостаточно.

Запись `runtime-state.json` необязательна: без неё приложение работает как
обычно, а бот просто не видит применённую ревизию. Совсем выключить —
`"runtimeStatePath": ""` в `dnsApp.config`.

## Тесты

```bash
dotnet test
```

95 тестов; что именно они покрывают — [`ruleset-loading.md §6`](ruleset-loading.md#6-тесты).
Тестам, в отличие от приложения, библиотеки Technitium копируются в выходной
каталог (`Private=true`), иначе тестовый хост их не найдёт.

## Диагностика

| Симптом | Куда смотреть |
|---|---|
| Приложение не появилось в админке | в zip нет `DnsOverrideApp.deps.json`, либо в него попали `TechnitiumLibrary.*.dll`; далее — логи Technitium `/etc/dns/logs/` |
| Приложение есть, но правила не применяются | `/etc/dns-override/runtime-state.json` → `errors`, `appliedRevision` |
| `appliedRevision` = `null` | файл ни разу не загрузился: нет прав, нет файла, выключен `enabled` в `dnsApp.config` |
| `runtime-state.json` не появляется, в логе `Read-only file system` | каталог закрыт на запись самим systemd — нужен drop-in с `ReadWritePaths` и перезапуск `dns.service`. В боте: «🧰 Сервис» → «🔐 Права доступа» |
| `runtime-state.json` не появляется, в логе `Access … is denied` | нет ACL: `setfacl -m u:<пользователь dns.service>:rwx /etc/dns-override` |
| `appliedRevision` отстаёт от `revision` в файле | права на файл; на bind-mount/NFS не работает inotify — сработает страховочный опрос (60 с) |
| Конфиг из админки не сохраняется | приложение отвергло JSON; текст ошибки — в логе Technitium |
| Непонятно, почему домен подменяется | `python3 tools/check-ruleset.py /etc/dns-override/ruleset.dat --query имя.домена` — покажет победившее правило |
| Нужны логи совпадений | пересобрать ruleset с `engine.logMatches: true` и `logSampleRate: 1.0`, затем вернуть обратно |
| Старые ответы после смены правил | кэш сбрасывает бот, а не приложение — [`ruleset-loading.md §7`](ruleset-loading.md#7-сброс-кэша-dns-делается-вручную-из-бота) |
