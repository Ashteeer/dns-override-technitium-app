/*
DNS Override — приложение для Technitium DNS Server.

Запись runtime-state.json: обратный канал приложение → бот (docs/ruleset-loading.md §5).

Канал вспомогательный. DNS-ответы от него не зависят вообще: файл нужен только
для того, чтобы бот показал в «📊 Статус», какую ревизию правил приложение
реально применило, когда оно её применило и сколько запросов подменило.
Поэтому любая ошибка записи здесь — не авария, а сообщение оператору.

Три правила, из-за которых этот класс существует отдельно от RuntimeStateWriter:

1. **Не спамить.** Файл переписывается после каждой загрузки правил и раз в
   watch.pollIntervalSec (по умолчанию — раз в минуту). Один и тот же сбой,
   напечатанный 1440 раз в сутки, забивает журнал сервера. Сообщение печатается
   при смене текста ошибки — то есть один раз на проблему и один раз на её
   исчезновение.
2. **Не терять состояние.** Если каталог из конфига недоступен (смонтирован
   только для чтения, нет ACL), файл пишется в каталог самого приложения —
   тот, куда Technitium и так пишет dnsApp.config. Бот его оттуда не читает,
   но состояние видно оператору и в веб-консоли.
3. **Самовосстанавливаться.** Основной путь пробуется на каждой записи, а не
   один раз при старте: как только оператор выдаст права, канал вернётся в
   штатный каталог сам, без перезапуска DNS-сервера.
*/

using System;
using System.IO;

namespace DnsOverride
{
    sealed class RuntimeStateChannel
    {
        #region variables

        readonly string _primaryPath;
        readonly string _fallbackPath;
        readonly ILogSink _log;

        // Состояние сбоя хранится отдельно для каждого пути: удачная запись в
        // запасной каталог не должна «прощать» основному его ошибку и разрешать
        // напечатать её ещё раз на следующей минуте.
        string _primaryError = "";
        string _fallbackError = "";
        bool _onFallback;

        #endregion

        #region constructor

        /// <param name="primaryPath">runtimeStatePath из dnsApp.config; пустой — канал выключен.</param>
        /// <param name="fallbackPath">Каталог приложения; куда писать, если основной путь недоступен.</param>
        public RuntimeStateChannel(string primaryPath, string fallbackPath, ILogSink log)
        {
            _primaryPath = primaryPath ?? "";
            _fallbackPath = fallbackPath ?? "";
            _log = log;

            if (string.Equals(_fallbackPath, _primaryPath, StringComparison.Ordinal))
                _fallbackPath = "";
        }

        #endregion

        #region public

        /// <summary>Пустой runtimeStatePath в конфиге полностью выключает запись.</summary>
        public bool Enabled
        { get { return _primaryPath.Length > 0; } }

        /// <summary>Куда файл пишется сейчас. Пустая строка — канал выключен.</summary>
        public string EffectivePath
        { get { return _onFallback ? _fallbackPath : _primaryPath; } }

        /// <summary>Записать состояние. Исключений не бросает никогда.</summary>
        public void Write(RuntimeStateData data, Stats stats)
        {
            if (!Enabled)
                return;

            bool primaryWasBroken = _primaryError.Length > 0;

            // Основной путь пробуется каждый раз, а не один раз при старте: как
            // только оператор выдаст доступ, канал вернётся сам.
            if (TryWrite(_primaryPath, ref _primaryError, data, stats))
            {
                if (_onFallback)
                {
                    _onFallback = false;
                    _log.Write("DNS Override: доступ к " + _primaryPath + " восстановлен — состояние снова пишется туда.");
                }
                else if (primaryWasBroken)
                {
                    _log.Write("DNS Override: запись " + _primaryPath + " заработала.");
                }

                return;
            }

            if (_fallbackPath.Length == 0)
                return;

            if (!TryWrite(_fallbackPath, ref _fallbackError, data, stats))
                return;

            if (!_onFallback)
            {
                _onFallback = true;
                _log.Write("DNS Override: состояние временно пишется в " + _fallbackPath
                    + ". Бот читает его по пути из своего RUNTIME_STATE_PATH, поэтому в «📊 Статус» приложение будет выглядеть молчащим,"
                    + " пока не появится доступ к основному каталогу.");
            }
        }

        #endregion

        #region private

        /// <summary>Пишет файл; сбой печатает только при смене его текста — раз в минуту одно и то же не нужно.</summary>
        bool TryWrite(string path, ref string lastError, RuntimeStateData data, Stats stats)
        {
            try
            {
                RuntimeStateWriter.Write(path, data, stats);
                lastError = "";
                return true;
            }
            catch (Exception ex)
            {
                string signature = ex.GetType().Name + "|" + ex.Message;

                if (!string.Equals(signature, lastError, StringComparison.Ordinal))
                {
                    lastError = signature;

                    _log.Write("DNS Override: не удалось записать " + path + " — " + ex.Message
                        + " Подмена DNS работает как обычно, недоступен только обратный канал к боту. " + Hint(ex));
                }

                return false;
            }
        }

        static string Hint(Exception ex)
        {
            if (ex is UnauthorizedAccessException)
                return "Похоже на права доступа: выдайте их кнопкой «🔐 Права доступа» в боте либо вручную — setfacl -m u:<пользователь dns.service>:rwx <каталог>.";

            if (ex is DirectoryNotFoundException)
                return "Каталога нет: создайте его и выдайте доступ пользователю dns.service.";

            if (ex is IOException)
                return "Если это «Read-only file system», каталог закрыт на запись самим systemd: нужен ReadWritePaths=<каталог> в drop-in для dns.service. Всё это делает кнопка «🔐 Права доступа» в боте.";

            return "Отключить запись совсем можно, очистив runtimeStatePath в dnsApp.config.";
        }

        #endregion
    }
}
