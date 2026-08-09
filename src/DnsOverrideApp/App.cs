/*
DNS Override — приложение для Technitium DNS Server.

Точка интеграции: IDnsApplication + IDnsAuthoritativeRequestHandler.
Возврат null → Technitium резолвит запрос обычным путём (passthru),
возврат DnsDatagram → ответ уходит клиенту как есть (override).

Вся логика приложения — прочитать ruleset.dat, найти самое длинное совпадение
по суффиксу домена, собрать ответ. Правила собирает и разрешает конфликты бот.
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
    public sealed class App : IDnsApplication, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
    {
        #region variables

        readonly DateTime _startedAtUtc = DateTime.UtcNow;
        readonly Stats _stats;
        readonly RuntimeStateData _state;

        IDnsServer? _dnsServer;
        ILogSink? _log;
        AppConfig _config = AppConfig.Default;
        RulesetLoader? _loader;
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

            if (!parsed.Enabled)
            {
                dnsServer.WriteLog("DNS Override: приложение выключено в dnsApp.config — все запросы уходят в passthru.");

                _state.Enabled = false;
                _state.LastLoadTrigger = null;

                try
                {
                    RuntimeStateWriter.Write(parsed.RuntimeStatePath, _state, _stats);
                }
                catch (Exception ex)
                {
                    dnsServer.WriteLog("DNS Override: не удалось записать " + parsed.RuntimeStatePath + ".", ex);
                }

                return;
            }

            RulesetLoader loader = new RulesetLoader(parsed, _log, _stats, _state);
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

        public Task<DnsDatagram?> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            _stats.CountQuery();

            RulesetSnapshot? snapshot = _loader?.Snapshot;

            if ((snapshot is null) || !snapshot.Header.Engine.Enabled || (request.Question.Count != 1))
                return Passthru();

            DnsQuestionRecord question = request.Question[0];

            if (question.Class != DnsClass.IN)
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
            else
            {
                if (snapshot.Header.Engine.DefaultAction == RuleAction.Passthru)
                    return Passthru();

                targetIndex = snapshot.Header.DefaultTargetIndex;
                zone = ZoneName.FromQuestion(question.Name);
            }

            TargetSpec target = snapshot.Header.Targets[targetIndex];
            QtypeAction policy = snapshot.Header.QtypePolicy.For(question.Type);

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

            return Task.FromResult(response);
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
            _loader?.WriteRuntimeState();
        }

        #endregion

        #region private

        Task<DnsDatagram?> Passthru()
        {
            _stats.CountPassthru();

            return Task.FromResult<DnsDatagram?>(null);
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

        static string AppVersion
        {
            get
            {
                Version? version = Assembly.GetExecutingAssembly().GetName().Version;

                return version is null ? "0.0.0" : version.Major + "." + version.Minor + "." + version.Build;
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
