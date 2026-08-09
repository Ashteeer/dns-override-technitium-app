#!/usr/bin/env bash
#
# Локальная сборка приложения и упаковка в zip для Technitium DNS Server.
# CI/CD не используется — сборка идёт на машине разработчика/сервере.
#
# Требуется: .NET SDK 10.0+, zip, склонированные и собранные репозитории
# TechnitiumSoftware/DnsServer и TechnitiumSoftware/TechnitiumLibrary
# (см. docs/build-and-install.md). Путь к ним — переменная TECHNITIUM_SRC.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/src/DnsOverrideApp/DnsOverrideApp.csproj"
PUBLISH="$ROOT/build/publish"
OUT="$ROOT/build/out"
ZIP="$OUT/DnsOverrideApp.zip"

# Содержимое zip. Библиотеки DnsServerCore.ApplicationCommon.dll и
# TechnitiumLibrary.*.dll НЕ кладутся — они уже загружены сервером, копия
# приводит к конфликту типов. DnsOverrideApp.deps.json обязателен: сервер ищет
# приложения именно по файлам *.deps.json в каталоге приложения.
FILES=(DnsOverrideApp.dll DnsOverrideApp.deps.json dnsApp.config README.md)

command -v dotnet >/dev/null || { echo "не найден dotnet SDK" >&2; exit 1; }
command -v zip    >/dev/null || { echo "не найден zip (apt install zip)" >&2; exit 1; }

rm -rf "$PUBLISH" "$OUT"
mkdir -p "$OUT"

dotnet publish "$PROJECT" -c Release -f net10.0 -o "$PUBLISH" --nologo

for file in "${FILES[@]}"; do
    [ -f "$PUBLISH/$file" ] || { echo "нет файла $file в $PUBLISH" >&2; exit 1; }
done

( cd "$PUBLISH" && zip -q -X "$ZIP" "${FILES[@]}" )

VERSION="$(grep -oP '(?<=<Version>)[^<]+' "$PROJECT" | head -1)"

echo
echo "версия:  $VERSION"
echo "архив:   $ZIP ($(du -h "$ZIP" | cut -f1))"
zip -sf "$ZIP"
