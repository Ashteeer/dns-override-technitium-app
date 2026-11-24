/*
DNS Override — приложение для Technitium DNS Server.

Точки интеграции: IDnsApplication, IDnsAuthoritativeRequestHandler и IDnsPostProcessor.
Возврат null → Technitium резолвит запрос обычным путём (passthru),
возврат DnsDatagram → ответ уходит клиенту как есть (override).

Приложение читает ruleset.dat, выбирает правило и проверяет белые списки.
Правила собирает и разрешает конфликты бот.
*/

using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Threading.Tasks;
using DnsOverride.Ruleset;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride
{
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference, IDnsPostProcessor
    {
        #region variables

        readonly DateTime _startedAtUtc = DateTime.UtcNow;
        readonly Stats _stats;
        readonly RuntimeStateData _state;

        IDnsServer? _dnsServer;
        ILogSink? _log;
        AppConfig _config = AppConfig.Default;
        RulesetLoader? _loader;
        RuntimeStateChannel? _runtimeState;
        DnsSOARecordData? _soaRecord;

        #endregion

        #region constructor

        public App()
        {
            _stats = new Stats(_startedAtUtc);
            _state = new RuntimeStateData()
            {
                AppVersion = AppVersion,
                StartedAtUtc = _startedAtUtc
            };
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _loader?.Dispose();
            _loader = null;
        }

        #endregion

        #region IDnsApplication

        /// <summary>
        /// Вызывается при старте сервера, при установке/обновлении приложения и при
        /// сохранении dnsApp.config из админки. Исключение отсюда во время сохранения
        /// конфига не даёт серверу записать файл — битый конфиг просто не сохранится.
        /// </summary>
        public async Task InitializeAsync(IDnsServer dnsServer, string? config)
        {
            _dnsServer = dnsServer;
            _log = new DnsServerLogSink(dnsServer);

            if (string.IsNullOrWhiteSpace(config))
            {
                config = AppConfig.DefaultJson;
                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config).ConfigureAwait(false);
            }

            AppConfig parsed = AppConfig.Parse(config);

            _soaRecord = new DnsSOARecordData(dnsServer.ServerDomain, dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, 60);

            _loader?.Dispose();
            _loader = null;
            _config = parsed;

            // Запасной каталог для runtime-state.json — тот, куда сервер и так пишет
            // dnsApp.config. Если основной путь недоступен (read-only монтирование,
            // нет ACL), приложение не падает и не молчит, а пишет состояние сюда.
            _runtimeState = new RuntimeStateChannel(
                parsed.RuntimeStatePath,
                Path.Combine(dnsServer.ApplicationFolder, "runtime-state.json"),
                _log);

            if (!parsed.Enabled)
            {
                dnsServer.WriteLog("DNS Override: приложение выключено в dnsApp.config — все запросы уходят в passthru.");

                _state.Enabled = false;
                _state.LastLoadTrigger = null;

                _runtimeState.Write(_state, _stats);
                return;
            }

            RulesetLoader loader = new RulesetLoader(parsed, _log, _stats, _state, _runtimeState);
            _loader = loader;

            await loader.StartAsync().ConfigureAwait(false);
        }

        public string Description
        { get { return "Подменяет ответы на домены из скомпилированного файла правил /etc/dns-override/ruleset.dat: возвращает заданные IPv4/IPv6 либо NXDOMAIN/NODATA/REFUSED, всё остальное резолвится штатно. Файл правил собирает Telegram-бот и заменяет его атомарно; приложение перечитывает его без перезапуска DNS-сервера."; } }

        #endregion

        #region IDnsApplicationPreference

        public byte Preference
        { get { return _config.AppPreference; } }

        #endregion

        #region IDnsAuthoritativeRequestHandler

        public async Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            _stats.CountQuery();

            RulesetSnapshot? snapshot = _loader?.Snapshot;

            if ((snapshot is null) || !snapshot.Header.Engine.Enabled || (request.Question.Count != 1))
                return Passthru();

            DnsQuestionRecord question = request.Question[0];

            if (question.Class != DnsClass.IN)
                return Passthru();

            BypassPolicy bypass = snapshot.Header.Policy;
            // Без разрешения на рекурсию нельзя перепроверить ответ через DirectQuery.
            // Пропускаем и вложенные вызовы обработчика для целей CNAME/ANAME.
            if (!isRecursionAllowed && (bypass.HasNames || bypass.HasNetworks))
                return Passthru();
            if (bypass.AllowsName(question.Name))
                return Passthru();

            RuleMatch match = snapshot.Match(question.Name);

            int targetIndex;
            ZoneName zone;

            if (match.Found)
            {
                if (match.Action == RuleAction.Passthru)
                {
                    LogMatch(snapshot, question, match, "passthru");
                    return Passthru();
                }

                targetIndex = match.TargetIndex;
                zone = ZoneName.FromRule(snapshot, match.LineIndex);
            }
            else if (bypass.TryMatchRule(question.Name, out targetIndex))
            {
                if (targetIndex < 0)
                    return Passthru();
                zone = ZoneName.FromQuestion(question.Name);
            }
            else
            {
                if (snapshot.Header.Engine.DefaultAction == RuleAction.Passthru)
                    return Passthru();

                targetIndex = snapshot.Header.DefaultTargetIndex;
                zone = ZoneName.FromQuestion(question.Name);
            }

            TargetSpec target = snapshot.Header.Targets[targetIndex];
            QtypeAction policy = snapshot.Header.QtypePolicy.For(question.Type);

            if (bypass.HasNetworks && policy != QtypeAction.Passthru)
            {
                DnsDatagram? original = await QueryOriginalAsync(request, remoteEP).ConfigureAwait(false);
                if (original is null || original.Truncation ||
                    original.RCODE is not (DnsResponseCode.NoError or DnsResponseCode.NxDomain) ||
                    bypass.AllowsAnswer(original))
                    return Passthru(original);
            }

            DnsDatagram? response = ResponseBuilder.Build(request, isRecursionAllowed, _dnsServer!.UdpPayloadSize, _soaRecord!, target, policy, zone, out ResponseKind kind);

            switch (kind)
            {
                case ResponseKind.Overridden:
                    _stats.CountOverridden();
                    break;

                case ResponseKind.NoData:
                    _stats.CountNoData();
                    break;

                case ResponseKind.NxDomain:
                    _stats.CountNxDomain();
                    break;

                case ResponseKind.Refused:
                    _stats.CountRefused();
                    break;

                default:
                    _stats.CountPassthru();
                    break;
            }

            if (match.Found)
                LogMatch(snapshot, question, match, kind.ToString().ToLowerInvariant());

            return response;
        }

        #endregion

        #region IDnsPostProcessor

        public async Task<DnsDatagram?> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            RulesetSnapshot? snapshot = _loader?.Snapshot;
            if ((snapshot is null) || !snapshot.Header.Engine.Enabled || !response.RecursionAvailable ||
                response.Truncation || response.NextDatagram is not null ||
                response.RCODE is not (DnsResponseCode.NoError or DnsResponseCode.NxDomain) ||
                request.OPCODE != DnsOpcode.StandardQuery || request.Question.Count != 1 ||
                request.Question[0].Class != DnsClass.IN || !snapshot.Header.Policy.AllowsName(request.Question[0].Name))
                return response;

            // Passthru позволяет Technitium снова вызвать приложение для цели CNAME.
            // DirectQuery пропускает authoritative handlers на всей цепочке, а
            // постобработка не позволяет серверу снова разворачивать итоговый CNAME.
            DnsDatagram? original = await QueryOriginalAsync(request, remoteEP).ConfigureAwait(false);
            return original ?? new DnsDatagram(request.Identifier, true, request.OPCODE,
                false, false, request.RecursionDesired, true, false, request.CheckingDisabled,
                DnsResponseCode.ServerFailure, request.Question);
        }

        #endregion

        #region internal

        /// <summary>
        /// Внеочередная перезапись runtime-state.json. Штатно файл обновляется после
        /// каждой загрузки правил и раз в <c>watch.pollIntervalSec</c>; этот метод нужен,
        /// чтобы снять состояние в произвольный момент (тесты, ручная диагностика).
        /// </summary>
        internal void WriteRuntimeState()
        {
            if (_loader is not null)
            {
                _loader.WriteRuntimeState();
                return;
            }

            // Приложение выключено в конфиге: загрузчика нет, но состояние есть.
            _runtimeState?.Write(_state, _stats);
        }

        #endregion

        #region private

        DnsDatagram? Passthru(DnsDatagram? response = null)
        {
            _stats.CountPassthru();

            return response;
        }

        async Task<DnsDatagram?> QueryOriginalAsync(DnsDatagram request, IPEndPoint endpoint)
        {
            try
            {
                return await _dnsServer!.DirectQueryAsync(request, endpoint).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                return null;
            }
        }

        void LogMatch(RulesetSnapshot snapshot, DnsQuestionRecord question, RuleMatch match, string outcome)
        {
            EngineSettings engine = snapshot.Header.Engine;

            if (!engine.LogMatches || (engine.LogSampleRate <= 0))
                return;

            if ((engine.LogSampleRate < 1) && (Random.Shared.NextDouble() >= engine.LogSampleRate))
                return;

            _log?.Write("DNS Override: " + question.Name + " " + question.Type
                + " → " + outcome
                + " (правило " + (match.IsApex ? "apex" : "wildcard") + " на " + snapshot.GetRuleDomain(match.LineIndex) + ")");
        }

        /// <summary>
        /// Версия ровно в том виде, в каком её показывает Technitium в разделе Apps
        /// и отдаёт в /api/apps/list: незначащие нули отбрасываются, поэтому сборка
        /// 0.3.0.0 — это «0.3», а не «0.3.0». Бот сравнивает эту строку с тегом
        /// релиза, и любое расхождение в формате означало бы вечное «доступно
        /// обновление» (см. docs/decisions.md, D25).
        /// </summary>
        static string AppVersion
        {
            get
            {
                Version? version = Assembly.GetExecutingAssembly().GetName().Version;

                if (version is null)
                    return "0.0";

                string text = version.Major + "." + version.Minor;

                if (version.Build > 0)
                {
                    text += "." + version.Build;

                    if (version.Revision > 0)
                        text += "." + version.Revision;
                }

                return text;
            }
        }

        #endregion

        #region inner classes

        sealed class DnsServerLogSink : ILogSink
        {
            readonly IDnsServer _dnsServer;

            public DnsServerLogSink(IDnsServer dnsServer)
            {
                _dnsServer = dnsServer;
            }

            public void Write(string message)
            {
                _dnsServer.WriteLog(message);
            }

            public void Write(string message, Exception exception)
            {
                _dnsServer.WriteLog(message, exception);
            }
        }

        #endregion
    }
}
