/*
DNS Override — приложение для Technitium DNS Server.

Загрузка и горячая перезагрузка ruleset.dat (docs/ruleset-loading.md §2–§5).

Три триггера чтения файла: старт приложения, событие watcher'а с дебаунсом и
страховочный опрос по таймеру. DNS-запрос файл не читает никогда.

Watcher вешается на КАТАЛОГ, а не на файл: бот пишет .tmp и делает rename(),
то есть подменяет inode — подписка на сам файл после первой же записи следит
за удалённым inode и больше не срабатывает.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DnsOverride.Ruleset;

namespace DnsOverride
{
    sealed class RulesetLoader : IDisposable
    {
        #region constants

        const int ReadRetryCount = 3;
        const int ReadRetryDelayMs = 100;

        public const string TriggerInit = "init";
        public const string TriggerWatcher = "watcher";
        public const string TriggerPoll = "poll";

        #endregion

        #region variables

        readonly AppConfig _config;
        readonly ILogSink _log;
        readonly Stats _stats;
        readonly RuntimeStateData _state;
        readonly RuntimeStateChannel _runtimeState;
        readonly SemaphoreSlim _gate = new SemaphoreSlim(1, 1);
        readonly object _stateLock = new object();

        RulesetSnapshot? _snapshot;

        FileSystemWatcher? _watcher;
        Timer? _debounceTimer;
        Timer? _pollTimer;

        DateTime _seenModifiedUtc;
        long _seenLength = -1;

        bool _disposed;

        #endregion

        #region constructor

        public RulesetLoader(AppConfig config, ILogSink log, Stats stats, RuntimeStateData state, RuntimeStateChannel runtimeState)
        {
            _config = config;
            _log = log;
            _stats = stats;
            _state = state;
            _runtimeState = runtimeState;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            _watcher?.Dispose();
            _watcher = null;

            _debounceTimer?.Dispose();
            _debounceTimer = null;

            _pollTimer?.Dispose();
            _pollTimer = null;

            // _gate намеренно не освобождается: загрузка может быть в полёте,
            // а ObjectDisposedException в фоне ничего не улучшит.
        }

        #endregion

        #region public

        /// <summary>Первичная загрузка + подписка на изменения. Ошибка чтения не мешает старту.</summary>
        public async Task StartAsync()
        {
            await LoadAsync(TriggerInit);

            StartWatcher();

            _debounceTimer = new Timer(OnDebounceElapsed, null, Timeout.Infinite, Timeout.Infinite);

            int pollMs = _config.PollIntervalSec * 1000;
            _pollTimer = new Timer(OnPollElapsed, null, pollMs, pollMs);
        }

        /// <summary>Текущий снапшот; null — файл ещё ни разу не загрузился.</summary>
        public RulesetSnapshot? Snapshot
        { get { return Volatile.Read(ref _snapshot); } }

        /// <summary>Чтение и разбор файла. Любая ошибка оставляет в силе прошлый снапшот.</summary>
        public async Task<bool> LoadAsync(string trigger)
        {
            await _gate.WaitAsync().ConfigureAwait(false);

            try
            {
                Stopwatch stopwatch = Stopwatch.StartNew();

                FileInfo info = new FileInfo(_config.RulesetPath);

                if (!info.Exists)
                {
                    if (Volatile.Read(ref _snapshot) is null)
                        RecordError("ruleset не найден: " + _config.RulesetPath + " — все запросы уходят в passthru.");

                    // Файл, пропавший после успешной загрузки, — обычная фаза rename():
                    // снапшот сохраняется, ошибка не пишется.
                    WriteRuntimeState();
                    return false;
                }

                DateTime modifiedUtc = info.LastWriteTimeUtc;
                long length = info.Length;

                byte[] raw = await ReadWithRetryAsync(_config.RulesetPath).ConfigureAwait(false);

                RulesetSnapshot snapshot = RulesetParser.Parse(raw, modifiedUtc);

                Volatile.Write(ref _snapshot, snapshot);

                _seenModifiedUtc = modifiedUtc;
                _seenLength = length;

                stopwatch.Stop();

                lock (_stateLock)
                {
                    _state.LastLoadAtUtc = DateTime.UtcNow;
                    _state.LastLoadDurationMs = stopwatch.ElapsedMilliseconds;
                    _state.LastLoadTrigger = trigger;
                    _state.AppliedRevision = snapshot.Header.Revision;
                    _state.RulesLoaded = snapshot.Count + snapshot.Header.Policy.Count;
                    _state.TargetsLoaded = snapshot.Header.Targets.Length;
                    _state.SnapshotBytes = snapshot.SizeBytes;
                    _state.RulesetModifiedUtc = modifiedUtc;
                    _state.Errors.Clear();
                }

                foreach (string warning in snapshot.Header.Warnings)
                    _log.Write("DNS Override: " + warning);

                _log.Write("DNS Override: ruleset загружен (" + trigger + "): revision " + snapshot.Header.Revision
                    + ", правил " + snapshot.Count
                    + ", targets " + snapshot.Header.Targets.Length
                    + ", " + stopwatch.ElapsedMilliseconds + " мс.");

                // Кэш DNS-сервера здесь намеренно не трогается: интерфейс приложения
                // (IDnsServer, IDnsCache) операции сброса не предоставляет, а сам сброс
                // оператор делает вручную кнопкой в боте.

                WriteRuntimeState();
                return true;
            }
            catch (RulesetFormatException ex)
            {
                RecordError("ruleset отвергнут: " + ex.Message);
                _log.Write("DNS Override: ruleset отвергнут (" + trigger + "): " + ex.Message + " Продолжает работать предыдущий снапшот.");

                // Не перечитывать один и тот же битый файл каждую минуту: следующая
                // попытка будет после того, как бот перезапишет файл.
                RememberSeen();
                WriteRuntimeState();
                return false;
            }
            catch (UnauthorizedAccessException ex)
            {
                RecordError("нет прав на чтение " + _config.RulesetPath + ": " + ex.Message);
                _log.Write("DNS Override: нет прав на чтение ruleset — проверьте ACL на /etc/dns-override.", ex);
                WriteRuntimeState();
                return false;
            }
            catch (Exception ex)
            {
                RecordError("ошибка загрузки ruleset: " + ex.Message);
                _log.Write("DNS Override: ошибка загрузки ruleset (" + trigger + ").", ex);
                WriteRuntimeState();
                return false;
            }
            finally
            {
                _gate.Release();
            }
        }

        /// <summary>
        /// Снять состояние и отдать его в канал. Ошибки записи канал гасит сам:
        /// runtime-state.json — отчёт боту, а не условие работы приложения.
        /// </summary>
        public void WriteRuntimeState()
        {
            RuntimeStateData copy;

            lock (_stateLock)
            {
                copy = new RuntimeStateData()
                {
                    AppVersion = _state.AppVersion,
                    StartedAtUtc = _state.StartedAtUtc,
                    LastLoadAtUtc = _state.LastLoadAtUtc,
                    LastLoadDurationMs = _state.LastLoadDurationMs,
                    LastLoadTrigger = _state.LastLoadTrigger,
                    AppliedRevision = _state.AppliedRevision,
                    RulesLoaded = _state.RulesLoaded,
                    TargetsLoaded = _state.TargetsLoaded,
                    SnapshotBytes = _state.SnapshotBytes,
                    RulesetModifiedUtc = _state.RulesetModifiedUtc,
                    Enabled = _config.Enabled && (Volatile.Read(ref _snapshot)?.Header.Engine.Enabled ?? false),
                    Errors = new List<string>(_state.Errors)
                };
            }

            _runtimeState.Write(copy, _stats);
        }

        #endregion

        #region private

        void StartWatcher()
        {
            string? directory = Path.GetDirectoryName(Path.GetFullPath(_config.RulesetPath));
            string fileName = Path.GetFileName(_config.RulesetPath);

            if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
            {
                _log.Write("DNS Override: каталог " + directory + " не существует — работает только страховочный опрос раз в " + _config.PollIntervalSec + " с.");
                return;
            }

            try
            {
                FileSystemWatcher watcher = new FileSystemWatcher(directory, fileName)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };

                watcher.Created += OnFileEvent;
                watcher.Changed += OnFileEvent;
                watcher.Renamed += OnFileEvent;
                watcher.Error += OnWatcherError;
                watcher.EnableRaisingEvents = true;

                _watcher = watcher;
            }
            catch (Exception ex)
            {
                _log.Write("DNS Override: не удалось подписаться на изменения " + directory + " — остаётся страховочный опрос.", ex);
            }
        }

        void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            // События приходят пачкой (Created + Renamed + Changed): таймер
            // перезапускается на каждом, загрузка стартует, когда поток утих.
            _debounceTimer?.Change(_config.DebounceMs, Timeout.Infinite);
        }

        void OnWatcherError(object sender, ErrorEventArgs e)
        {
            _log.Write("DNS Override: сбой watcher'а, переподписка.", e.GetException());

            try
            {
                _watcher?.Dispose();
            }
            catch (Exception)
            { }

            _watcher = null;
            StartWatcher();

            _debounceTimer?.Change(_config.DebounceMs, Timeout.Infinite);
        }

        void OnDebounceElapsed(object? state)
        {
            _ = LoadAsync(TriggerWatcher);
        }

        void OnPollElapsed(object? state)
        {
            _ = PollAsync();
        }

        /// <summary>
        /// Страховочный опрос: inotify молчит на bind-mount, docker volume, NFS и SMB.
        /// Один stat в минуту; файл открывается только если (mtime, size) изменились.
        /// </summary>
        async Task PollAsync()
        {
            try
            {
                FileInfo info = new FileInfo(_config.RulesetPath);

                if (info.Exists && ((info.LastWriteTimeUtc != _seenModifiedUtc) || (info.Length != _seenLength)))
                {
                    await LoadAsync(TriggerPoll).ConfigureAwait(false);
                    return;
                }

                WriteRuntimeState();                    // обновить stats даже без перезагрузки
            }
            catch (Exception ex)
            {
                _log.Write("DNS Override: ошибка страховочного опроса.", ex);
            }
        }

        static async Task<byte[]> ReadWithRetryAsync(string path)
        {
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    return await File.ReadAllBytesAsync(path).ConfigureAwait(false);
                }
                catch (Exception ex) when ((attempt < ReadRetryCount) && (ex is FileNotFoundException or IOException))
                {
                    // Окно rename(): файл на мгновение недоступен под своим именем.
                    await Task.Delay(ReadRetryDelayMs).ConfigureAwait(false);
                }
            }
        }

        void RememberSeen()
        {
            try
            {
                FileInfo info = new FileInfo(_config.RulesetPath);

                if (info.Exists)
                {
                    _seenModifiedUtc = info.LastWriteTimeUtc;
                    _seenLength = info.Length;
                }
            }
            catch (Exception)
            { }
        }

        void RecordError(string message)
        {
            lock (_stateLock)
            {
                _state.Errors.Add(RuntimeStateWriter.Iso8601(DateTime.UtcNow) + " " + message);

                while (_state.Errors.Count > RuntimeStateWriter.MaxErrors)
                    _state.Errors.RemoveAt(0);
            }
        }

        #endregion
    }
}
