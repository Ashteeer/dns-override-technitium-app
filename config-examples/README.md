# Примеры файлов, с которыми работает приложение

Зеркало каталога `/etc/dns-override/` плюс конфиг самого приложения Technitium.

| Файл | Кто пишет | Кто читает | Что это |
|---|---|---|---|
| `ruleset.dat` | бот | приложение | **единственный конфиг правил.** Скомпилированный, окончательный. Формат — [`docs/ruleset-format.md`](../docs/ruleset-format.md) |
| `runtime-state.json` | приложение | бот | состояние приложения для `/status`. Не конфиг |
| `dnsApp.config` | админка Technitium | приложение | указатель на `ruleset.dat`, аварийный `enabled`, `appPreference` и параметры watcher'а. Живёт в каталоге приложения, не в `/etc/dns-override/` |

Внутреннее состояние бота (правила пользователя, описания источников, кэш скачанных
списков) контрактом **не является** и лежит в
[`state-examples/`](https://github.com/Ashteeer/dns-override-telegram-botstate-examples/).

## Проверить файл

```bash
python3 tools/check-ruleset.py config-examples/ruleset.dat
```

## Посмотреть, что будет с конкретным доменом

```bash
python3 tools/check-ruleset.py config-examples/ruleset.dat --query test.google.com www.example.org
```
