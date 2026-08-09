# Архитектура DNS Override

## Цель

Управляемая подмена DNS-ответов на Technitium DNS Server: домены из списка получают
заданный IPv4/IPv6, всё остальное резолвится штатно. Управление — из Telegram-бота,
в перспективе — из web-ui.

## Разделение обязанностей

| | Бот — **компилятор** | Приложение — **исполнитель** |
|---|---|---|
| Каталог | [`dns-override-telegram-bot/`](https://github.com/Ashteeer/dns-override-telegram-bot) | [`dns-override-technitium-app/`](../) |
| Стек | см. открытый вопрос в `CLAUDE.md` | C# / .NET 10 |
| Знает об источниках и приоритетах | ✅ | ❌ |
| Скачивает и парсит списки | ✅ | ❌ |
| Разрешает конфликты правил | ✅ | ❌ |
| Нормализует домены правил | ✅ | ❌ |
| Ищет самый длинный суффикс | ❌ | ✅ |
| Формирует DNS-ответ | ❌ | ✅ |

Вся связь между ними — **один файл** `/etc/dns-override/ruleset.dat` со скомпилированными
окончательными правилами. Логика слияния может меняться сколько угодно — приложение
при этом не трогается. Обоснование — [`decisions.md`](decisions.md).

## Поток данных

```
   ┌──────────────┐   HTTPS GET (раз в X часов / по команде)
   │ внешние      │◀─────────────────────────────────┐
   │ списки       │                                  │
   └──────────────┘                          ┌───────────────┐
                                             │ Telegram Bot  │
   Telegram ─── команды ──────────────────▶  │  (компилятор) │
                                             └───────┬───────┘
                      внутреннее состояние бота      │ компиляция
                      /var/lib/dns-override-bot/ ────┤ + атомарная запись
                      (правила, источники, кэш)      ▼
                                        /etc/dns-override/ruleset.dat
                                                     │ watcher + дебаунс 500 мс
                                                     │ страховочный stat раз в 60 с
                                                     ▼
   DNS-клиент ─── запрос ──▶ Technitium DNS ──▶ ┌──────────────────┐
                                                │ DNS Override App │
                                                └────────┬─────────┘
                                        override │                │ passthru (null)
                                                 ▼                ▼
                                        ответ из target    обычный резолв Technitium
```

Обратный канал: приложение пишет `runtime-state.json`, бот читает его для `/status`
и чтобы убедиться, что `appliedRevision` догнал `revision` записанного файла.
Канал вспомогательный: его недоступность приложение переживает молча — один
раз пишет в журнал, при возможности откатывается на каталог приложения и
продолжает пробовать основной путь (D24).

Кэш Technitium автоматически не сбрасывается. Приложение этого не умеет в принципе:
в его интерфейсе (`IDnsServer`, `IDnsCache`) операции сброса нет — только
`QueryAsync` и `CacheResponse`. Сброс делает оператор кнопкой в боте
(«🧰 Сервис → 🧹 Сбросить весь кэш DNS» → `POST /api/cache/flush`), и всегда целиком.

## Точка интеграции с Technitium

Приложение реализует `IDnsApplication` + `IDnsAuthoritativeRequestHandler`
+ `IDnsApplicationPreference`:

```csharp
Task<DnsDatagram?> ProcessRequestAsync(
    DnsDatagram request, IPEndPoint remoteEP,
    DnsTransportProtocol protocol, bool isRecursionAllowed);
```

- `return null` → Technitium резолвит запрос обычным путём (**passthru**);
- `return DnsDatagram` → ответ отдаётся клиенту как есть (**override**).

Обработчики приложений вызываются на авторитативной фазе — после поиска
в локальных зонах и **до** рекурсии, для каждого стандартного запроса класса `IN`.
`IDnsApplicationPreference.Preference` задаёт порядок среди установленных
приложений (меньше — раньше; без интерфейса сервер считает 100), у DNS Override
по умолчанию `20` и настраивается в `dnsApp.config`.

Целевой фреймворк `net10.0` — как у штатных приложений Technitium (`Apps/*`
в репозитории `TechnitiumSoftware/DnsServer`). Сборка против
`DnsServerCore.ApplicationCommon` и библиотек `TechnitiumLibrary.*`.

## Развёртывание (Ubuntu 24.04+)

| Что | Куда |
|---|---|
| Technitium DNS Server | `/etc/dns/`, сервис `dns.service` |
| Приложение | `/etc/dns/apps/DNS Override/` — ставится zip'ом через админку или API |
| `ruleset.dat`, `runtime-state.json` | `/etc/dns-override/` |
| Бот | `/opt/dns-override-bot/`, сервис `dns-override-bot.service` |
| Внутреннее состояние бота | `/var/lib/dns-override-bot/` |
| Секреты бота | `/etc/dns-override-bot/bot.env` (0600, вне git) |

### Права на `/etc/dns-override`

Каталог общий: бот пишет `ruleset.dat`, приложение — `runtime-state.json`,
и каждый читает файл другого. Настраивается автоматически скриптом
[`deploy/install.sh`](https://github.com/Ashteeer/dns-override-telegram-bot/blob/main/deploy/install.sh):

| Слой | Что делает |
|---|---|
| владелец и setgid | `dns-override-bot:dns-override`, режим `2770` — новые файлы наследуют группу |
| членство в группе | пользователь Technitium добавляется в `dns-override` (`usermod -aG`) |
| **POSIX ACL** | `setfacl` на каталог + default-записи для новых файлов |
| **drop-in systemd** | `ReadWritePaths=/etc/dns-override` для `dns.service` |

ACL — основной механизм, членство в группе оставлено запасным. Причина: дополнительные
группы читаются процессом **при старте**, поэтому после `usermod` Technitium пришлось бы
перезапускать, а ACL действует немедленно.

Drop-in решает другую задачу и ACL не заменяет. При `ProtectSystem=full` (или
`strict`) в юните DNS-сервера systemd монтирует `/etc` внутрь сервиса только для
чтения, и запись падает с `Read-only file system` при любых правах. Файл
`/etc/systemd/system/dns.service.d/10-dns-override.conf` живёт отдельно от
`dns.service`, поэтому переживает обновление Technitium; применяется он только
при **перезапуске** сервиса. Там же выдаётся `AmbientCapabilities=CAP_NET_ADMIN`,
если на сервере стоит DNS IPCollector с его `ipset` (D27).

```bash
setfacl -m u:dns:rwx              -m d:u:dns:rw-              /etc/dns-override
setfacl -m u:dns-override-bot:rwx -m d:u:dns-override-bot:rw- /etc/dns-override
```

`rwx` на самом каталоге нужен обеим сторонам: приложению — чтобы создать
`runtime-state.json`, боту — чтобы положить `ruleset.dat.tmp` перед `rename()`.
`default`-записи (`d:`) выдают доступ файлам, которые появятся позже.

Пользователь Technitium определяется скриптом из `systemctl show -p User dns.service`;
пустое значение означает `root` — тогда никакие права выдавать не нужно.
Переопределяется переменной `DNS_SERVICE_USER`.

## Документы

| Документ | О чём |
|---|---|
| [`decisions.md`](decisions.md) | принятые решения и отвергнутые альтернативы |
| [`ruleset-format.md`](ruleset-format.md) | **контракт**: формат `ruleset.dat` |
| [`rule-matching.md`](rule-matching.md) | что делает бот, что делает приложение, семантика wildcard/apex |
| [`schema/ruleset-header.schema.json`](schema/ruleset-header.schema.json) | JSON Schema заголовка |
| [`../tools/check-ruleset.py`](../tools/check-ruleset.py) | валидатор файла + отладка запросов |
| [`ruleset-loading.md`](ruleset-loading.md) | как приложение читает и перезагружает файл |
| [`ruleset-compile.md`](https://github.com/Ashteeer/dns-override-telegram-bot/blob/main/docs/ruleset-compile.md) | как бот собирает файл |
| [`list-sync.md`](https://github.com/Ashteeer/dns-override-telegram-bot/blob/main/docs/list-sync.md) | скачивание и парсинг внешних списков |
