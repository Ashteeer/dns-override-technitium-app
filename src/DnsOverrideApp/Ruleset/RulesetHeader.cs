/*
DNS Override — приложение для Technitium DNS Server.

Заголовок ruleset.dat — первая строка файла после сигнатуры !DNSOVR1.
Контракт: docs/ruleset-format.md §2, схема: docs/schema/ruleset-header.schema.json.

Неизвестные поля игнорируются намеренно (§6): бот новее приложения должен уметь
добавлять поля, не ломая загрузку.
*/

using System;
using System.Collections.Generic;
using System.Text.Json;

namespace DnsOverride.Ruleset
{
    sealed class RulesetHeader
    {
        #region constants

        public const int SupportedVersion = 2;
        const int MaxTargets = 256;

        #endregion

        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        #endregion

        #region constructor

        RulesetHeader(int version, long revision, string generatedAt, string? generator, int count, string sha256, EngineSettings engine, TargetSpec[] targets, QtypePolicy qtypePolicy, int defaultTargetIndex, IReadOnlyList<string> warnings, BypassPolicy policy)
        {
            Version = version;
            Revision = revision;
            GeneratedAt = generatedAt;
            Generator = generator;
            Count = count;
            Sha256 = sha256;
            Engine = engine;
            Targets = targets;
            QtypePolicy = qtypePolicy;
            DefaultTargetIndex = defaultTargetIndex;
            Warnings = warnings;
            Policy = policy;
        }

        #endregion

        #region public

        public static RulesetHeader Parse(string json)
        {
            JsonDocument document;

            try
            {
                document = JsonDocument.Parse(json, _jsonParseOptions);
            }
            catch (JsonException ex)
            {
                throw new RulesetFormatException("заголовок не разбирается как JSON: " + ex.Message);
            }

            using (document)
            {
                JsonElement root = document.RootElement;
                const string where = "заголовок";

                if (root.ValueKind != JsonValueKind.Object)
                    throw new RulesetFormatException(where + ": ожидался JSON-объект.");

                int version = JsonUtil.RequireInt32(root, "version", where);
                if (version is not (1 or SupportedVersion))
                    throw new RulesetFormatException(where + ": version=" + version + " не поддерживается (приложение понимает 1 и " + SupportedVersion + ").");

                long revision = JsonUtil.RequireInt64(root, "revision", where);
                string generatedAt = JsonUtil.RequireString(root, "generatedAt", where);
                string? generator = JsonUtil.OptionalString(root, "generator", null, where);
                int count = JsonUtil.RequireInt32(root, "count", where);
                if (count < 0)
                    throw new RulesetFormatException(where + ": count отрицателен.");

                string sha256 = JsonUtil.RequireString(root, "sha256", where);
                if (!IsLowerHex(sha256, 64))
                    throw new RulesetFormatException(where + ": sha256 должен быть 64 hex-символами в нижнем регистре.");

                List<string> warnings = new List<string>();

                JsonElement jsonTargets = JsonUtil.RequireProperty(root, "targets", where);
                if (jsonTargets.ValueKind != JsonValueKind.Array)
                    throw new RulesetFormatException(where + ": targets должен быть массивом.");

                int targetCount = jsonTargets.GetArrayLength();
                if (targetCount == 0)
                    throw new RulesetFormatException(where + ": targets пуст.");

                if (targetCount > MaxTargets)
                    throw new RulesetFormatException(where + ": больше " + MaxTargets + " targets.");

                TargetSpec[] targets = new TargetSpec[targetCount];
                int index = 0;

                foreach (JsonElement jsonTarget in jsonTargets.EnumerateArray())
                {
                    targets[index] = TargetSpec.Parse(jsonTarget, index);
                    index++;
                }

                EngineSettings engine = EngineSettings.Parse(JsonUtil.RequireProperty(root, "engine", where));

                int defaultTargetIndex = -1;

                if (engine.DefaultAction == RuleAction.Override)
                {
                    if (engine.DefaultTarget is null)
                        throw new RulesetFormatException(where + ": defaultAction=override требует defaultTarget.");

                    for (int t = 0; t < targets.Length; t++)
                    {
                        if (string.Equals(targets[t].Name, engine.DefaultTarget, StringComparison.Ordinal))
                        {
                            defaultTargetIndex = t;
                            break;
                        }
                    }

                    if (defaultTargetIndex < 0)
                        throw new RulesetFormatException(where + ": defaultTarget '" + engine.DefaultTarget + "' отсутствует в targets.");
                }

                QtypePolicy qtypePolicy = QtypePolicy.Parse(JsonUtil.RequireProperty(root, "qtypePolicy", where), warnings);

                if (version == 1 && root.TryGetProperty("policy", out _))
                    throw new RulesetFormatException(where + ": policy требует version=2.");
                BypassPolicy policy = version == SupportedVersion
                    ? BypassPolicy.Parse(JsonUtil.RequireProperty(root, "policy", where), targetCount)
                    : BypassPolicy.Empty;

                return new RulesetHeader(version, revision, generatedAt, generator, count, sha256, engine, targets, qtypePolicy, defaultTargetIndex, warnings, policy);
            }
        }

        #endregion

        #region private

        static bool IsLowerHex(string value, int length)
        {
            if (value.Length != length)
                return false;

            foreach (char c in value)
            {
                bool ok = ((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f'));

                if (!ok)
                    return false;
            }

            return true;
        }

        #endregion

        #region properties

        public int Version { get; }
        public BypassPolicy Policy { get; }

        public long Revision { get; }

        public string GeneratedAt { get; }

        public string? Generator { get; }

        /// <summary>Число строк правил, заявленное заголовком.</summary>
        public int Count { get; }

        public string Sha256 { get; }

        public EngineSettings Engine { get; }

        public TargetSpec[] Targets { get; }

        public QtypePolicy QtypePolicy { get; }

        /// <summary>Индекс defaultTarget в Targets либо -1, если defaultAction=passthru.</summary>
        public int DefaultTargetIndex { get; }

        /// <summary>Непринципиальные замечания разбора — уходят в лог Technitium.</summary>
        public IReadOnlyList<string> Warnings { get; }

        #endregion
    }

    sealed class EngineSettings
    {
        #region constructor

        EngineSettings(bool enabled, RuleAction defaultAction, string? defaultTarget, bool logMatches, double logSampleRate)
        {
            Enabled = enabled;
            DefaultAction = defaultAction;
            DefaultTarget = defaultTarget;
            LogMatches = logMatches;
            LogSampleRate = logSampleRate;
        }

        #endregion

        #region public

        public static EngineSettings Parse(JsonElement json)
        {
            const string where = "заголовок.engine";

            if (json.ValueKind != JsonValueKind.Object)
                throw new RulesetFormatException(where + ": ожидался объект.");

            string action = JsonUtil.RequireString(json, "defaultAction", where);
            RuleAction defaultAction;

            switch (action)
            {
                case "passthru": defaultAction = RuleAction.Passthru; break;
                case "override": defaultAction = RuleAction.Override; break;
                default: throw new RulesetFormatException(where + ".defaultAction: недопустимое значение '" + action + "'.");
            }

            double sampleRate = JsonUtil.OptionalDouble(json, "logSampleRate", 0, where);
            if ((sampleRate < 0) || (sampleRate > 1))
                throw new RulesetFormatException(where + ".logSampleRate: вне диапазона 0..1.");

            // Полей сброса кэша здесь больше нет: сброс делает оператор кнопкой в боте.
            // Файлы, где ещё лежат flushCacheOnReload / flushScope, грузятся как обычно —
            // неизвестные поля заголовка игнорируются (docs/ruleset-format.md §6).

            return new EngineSettings(
                JsonUtil.OptionalBool(json, "enabled", true, where),
                defaultAction,
                JsonUtil.OptionalString(json, "defaultTarget", null, where),
                JsonUtil.OptionalBool(json, "logMatches", false, where),
                sampleRate);
        }

        #endregion

        #region properties

        /// <summary>false — аварийный полный passthru: файл загружен, но ответы не подменяются.</summary>
        public bool Enabled { get; }

        public RuleAction DefaultAction { get; }

        public string? DefaultTarget { get; }

        public bool LogMatches { get; }

        public double LogSampleRate { get; }

        #endregion
    }
}
