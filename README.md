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
tests/DnsOverrideApp.Tests/   87 тестов (xUnit)
build/                        build.sh, build.ps1 → build/out/DnsOverrideApp.zip
docs/                         документация, специфичная для приложения
```

## Документация

- [Сборка и установка](docs/build-and-install.md)
- [Загрузка и горячая перезагрузка ruleset](docs/ruleset-loading.md) — когда, как часто, что при ошибках
- [Формат `ruleset.dat`](docs/ruleset-format.md) — контракт, общий с ботом
- [Семантика правил](docs/rule-matching.md) — wildcard/apex, алгоритм поиска

## Сборка

```bash
./build/build.sh          # → build/out/DnsOverrideApp.zip
dotnet test               # 87 тестов
```

Нужны склонированные рядом `TechnitiumSoftware/DnsServer` и собранный
`TechnitiumSoftware/TechnitiumLibrary` — подробности в
[Сборка и установка](docs/build-and-install.md).

## Лицензия

**GNU GPL v3** — [`LICENSE`](LICENSE). Приложение собирается против
`DnsServerCore.ApplicationCommon` и `TechnitiumLibrary` из
[Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer),
распространяемых под GPL-3.0, и является производной работой, поэтому лицензия
та же. Telegram-бот от этого кода не зависит и живёт под MIT в своём репозитории.

Technitium DNS Server © Shreyas Zare (Technitium).

## Статус

Приложение реализовано и собирается локально: `build/out/DnsOverrideApp.zip`,
87 тестов зелёные. На живом Technitium DNS Server ещё не проверялось.

Кэш DNS-сервера приложение не сбрасывает — интерфейс приложений Technitium такой
операции не предоставляет. Сброс делается вручную кнопкой в боте и целиком
([`ruleset-loading.md §7`](docs/ruleset-loading.md#7-сброс-кэша-dns-делается-вручную-из-бота)).
