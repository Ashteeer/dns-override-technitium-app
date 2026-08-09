# DNS Override — приложение для Technitium DNS Server

Приложение (DNS App) для [Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer).
Перехватывает входящие запросы и либо отвечает адресами из конфигурации (**override**),
либо отдаёт запрос на обычный резолв апстримами Technitium (**passthru**).

- Стек: C# / .NET 10, `IDnsApplication` + `IDnsAuthoritativeRequestHandler`
- Платформа: Ubuntu 24.04 LTS+
- Горячая перезагрузка правил без рестарта DNS-сервера

Приложение читает **один файл** — `/etc/dns-override/ruleset.dat`. Правила в нём уже
окончательные: их собирает и разрешает конфликты бот. Приложение не знает ни об
источниках правил, ни о приоритетах, ни о том, пришло правило от пользователя
или из внешнего списка.

Вся его логика: прочитать файл, найти самое длинное совпадение по суффиксу домена,
собрать ответ.

## Быстрый старт

Одна команда на чистом сервере Ubuntu 24.04+. Компилировать ничего не нужно —
скрипт качает готовый zip из последнего релиза:

```bash
curl -fsSL https://raw.githubusercontent.com/Ashteeer/dns-override-technitium-app/main/deploy/install.sh | sudo bash -s -- --password ПАРОЛЬ_АДМИНКИ
```

Скрипт рассчитан на полностью новую машину:

1. ставит системные пакеты: `curl`, `ca-certificates`, `acl`;
2. ставит **Technitium DNS Server**, если его нет (официальный установщик,
   он же подтягивает .NET); у свежей установки логин и пароль — `admin`/`admin`,
   тогда `--password` можно не передавать;
3. создаёт `/etc/dns-override` и выдаёт Technitium доступ туда через POSIX ACL;
4. качает `DnsOverrideApp.zip` из последнего GitHub-релиза и ставит его через
   API (`apps/install`, либо `apps/update`, если приложение уже есть).

Правила приложение только исполняет — компилирует их
[Telegram-бот](https://github.com/Ashteeer/dns-override-telegram-bot).
**Если нужен и бот, ставьте сразу его** — он поставит приложение сам и спросит
всё необходимое:

```bash
curl -fsSL https://raw.githubusercontent.com/Ashteeer/dns-override-telegram-bot/main/deploy/install.sh | sudo bash
```

### Опции установщика

| Опция | Что делает |
|---|---|
| `--api IP:PORT` | адрес админки Technitium; схему можно опустить (по умолчанию `127.0.0.1:5380`) |
| `--token TOKEN` | постоянный API-токен вместо логина с паролем |
| `--user USER` | логин админки (по умолчанию `admin`) |
| `--password PASS` | пароль админки (по умолчанию `admin` — как у свежей установки) |
| `--name NAME` | имя приложения в админке (по умолчанию «DNS Override») |
| `--ref TAG` | поставить конкретный релиз; по умолчанию последний |
| `--no-dns-server` | не ставить Technitium DNS Server, даже если его нет |
| `--insecure` | не проверять TLS-сертификат админки |
| `--help` | справка |

Ручные варианты установки (админка → **Apps → Install**, `curl` в `/api/apps/install`)
описаны в [Сборке и установке](docs/build-and-install.md).

## Структура

```
DnsOverrideApp.slnx           решение: приложение + тесты
Directory.Build.props         поиск исходников Technitium (TECHNITIUM_SRC)
src/DnsOverrideApp/
├── App.cs                    IDnsApplication + IDnsAuthoritativeRequestHandler
├── AppConfig.cs              разбор dnsApp.config
├── RulesetLoader.cs          watcher на каталог + дебаунс + страховочный опрос
├── ResponseBuilder.cs        сборка ответа по target и qtypePolicy
├── RuntimeStateWriter.cs     обратный канал runtime-state.json (tmp + rename)
├── Stats.cs                  счётчики запросов
└── Ruleset/                  разбор и поиск по ruleset.dat
    ├── RulesetParser.cs      проверки формата, sha256, count, порядка
    ├── RulesetSnapshot.cs    byte[] + смещения строк, бинарный поиск
    ├── RulesetHeader.cs      заголовок: engine, targets, qtypePolicy
    ├── TargetSpec.cs         адреса, ttl, rotation, emptyFamilyPolicy
    └── DomainKey.cs          QNAME → rdomain без аллокаций
tests/DnsOverrideApp.Tests/   88 тестов (xUnit)
deploy/install.sh             установка готового релиза в Technitium
build/                        build.sh, build.ps1 → build/out/DnsOverrideApp.zip
docs/                         документация, специфичная для приложения
```

## Документация

- [Сборка и установка](docs/build-and-install.md)
- [Загрузка и горячая перезагрузка ruleset](docs/ruleset-loading.md) — когда, как часто, что при ошибках
- [Формат `ruleset.dat`](docs/ruleset-format.md) — контракт, общий с ботом
- [Семантика правил](docs/rule-matching.md) — wildcard/apex, алгоритм поиска

## Сборка (только для разработки)

Пользователю собирать приложение не нужно: готовый zip лежит в каждом релизе,
а `deploy/install.sh` качает его сам.

```bash
./build/build.sh          # → build/out/DnsOverrideApp.zip
dotnet test               # 88 тестов
```

Нужны .NET SDK 10, склонированные рядом `TechnitiumSoftware/DnsServer` и
собранный `TechnitiumSoftware/TechnitiumLibrary` — подробности в
[Сборке и установке](docs/build-and-install.md).

## Лицензия

**GNU GPL v3** — [`LICENSE`](LICENSE). Приложение собирается против
`DnsServerCore.ApplicationCommon` и `TechnitiumLibrary` из
[Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer),
распространяемых под GPL-3.0, и является производной работой, поэтому лицензия
та же. Telegram-бот от этого кода не зависит и живёт под MIT в своём репозитории.

Technitium DNS Server © Shreyas Zare (Technitium).

## Статус

Приложение реализовано и собирается локально: `build/out/DnsOverrideApp.zip`,
88 тестов зелёные. На живом Technitium DNS Server ещё не проверялось.

Кэш DNS-сервера приложение не сбрасывает — интерфейс приложений Technitium такой
операции не предоставляет. Сброс делается вручную кнопкой в боте и целиком
([`ruleset-loading.md §7`](docs/ruleset-loading.md#7-сброс-кэша-dns-делается-вручную-из-бота)).
