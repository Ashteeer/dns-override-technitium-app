/*
DNS Override — приложение для Technitium DNS Server.

Разбор dnsApp.config. Формат описан в docs/ruleset-loading.md §1: в конфиге
приложения лежит только указатель на ruleset.dat и аварийный тумблер. Все
настройки движка (targets, qtypePolicy, defaultAction) приходят в заголовке
самого ruleset — второго источника настроек нет.
*/

using System;
using System.Text.Json;

namespace DnsOverride
{
    sealed class AppConfig
    {
        #region constants

        public const string DefaultRulesetPath = "/etc/dns-override/ruleset.dat";
        public const string DefaultRuntimeStatePath = "/etc/dns-override/runtime-state.json";
        public const byte DefaultAppPreference = 20;
        public const int DefaultDebounceMs = 500;
        public const int DefaultPollIntervalSec = 60;

        const int MinDebounceMs = 50;
        const int MaxDebounceMs = 60000;
        const int MinPollIntervalSec = 5;
        const int MaxPollIntervalSec = 3600;

        #endregion

        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        #endregion

        #region constructor

        AppConfig(string rulesetPath, string runtimeStatePath, bool enabled, byte appPreference, int debounceMs, int pollIntervalSec)
        {
            RulesetPath = rulesetPath;
            RuntimeStatePath = runtimeStatePath;
            Enabled = enabled;
            AppPreference = appPreference;
            DebounceMs = debounceMs;
            PollIntervalSec = pollIntervalSec;
        }

        #endregion

        #region public

        public static AppConfig Default { get; } = new AppConfig(DefaultRulesetPath, DefaultRuntimeStatePath, true, DefaultAppPreference, DefaultDebounceMs, DefaultPollIntervalSec);

        public static string DefaultJson { get; } = """
{
  "rulesetPath": "/etc/dns-override/ruleset.dat",
  "runtimeStatePath": "/etc/dns-override/runtime-state.json",
  "enabled": true,
  "appPreference": 20,
  "watch": {
    "debounceMs": 500,
    "pollIntervalSec": 60
  }
}
""";

        /// <summary>
        /// Разбирает dnsApp.config. Кидает исключение на некорректном конфиге:
        /// DnsApplication.SetConfigAsync записывает файл только после успешного
        /// InitializeAsync, поэтому битый конфиг из админки просто не сохранится.
        /// </summary>
        public static AppConfig Parse(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json, _jsonParseOptions);
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
                throw new FormatException("dnsApp.config: ожидался JSON-объект.");

            string rulesetPath = GetString(root, "rulesetPath", DefaultRulesetPath);
            if (rulesetPath.Length == 0)
                throw new FormatException("dnsApp.config: rulesetPath не может быть пустым.");

            // Пустая строка — не ошибка, а способ выключить запись runtime-state.json:
            // файл нужен только боту для отчёта о применённой ревизии, и на подмену
            // DNS никак не влияет.
            string runtimeStatePath = GetString(root, "runtimeStatePath", DefaultRuntimeStatePath);

            bool enabled = GetBool(root, "enabled", true);

            int preference = GetInt32(root, "appPreference", DefaultAppPreference);
            if ((preference < 0) || (preference > 255))
                throw new FormatException("dnsApp.config: appPreference должен быть в диапазоне 0..255.");

            int debounceMs = DefaultDebounceMs;
            int pollIntervalSec = DefaultPollIntervalSec;

            if (root.TryGetProperty("watch", out JsonElement watch) && (watch.ValueKind == JsonValueKind.Object))
            {
                debounceMs = Clamp(GetInt32(watch, "debounceMs", DefaultDebounceMs), MinDebounceMs, MaxDebounceMs);
                pollIntervalSec = Clamp(GetInt32(watch, "pollIntervalSec", DefaultPollIntervalSec), MinPollIntervalSec, MaxPollIntervalSec);
            }

            return new AppConfig(rulesetPath, runtimeStatePath, enabled, (byte)preference, debounceMs, pollIntervalSec);
        }

        #endregion

        #region private

        static string GetString(JsonElement parent, string name, string fallback)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                return fallback;

            if (value.ValueKind != JsonValueKind.String)
                throw new FormatException("dnsApp.config: " + name + " должен быть строкой.");

            return value.GetString()!.Trim();
        }

        static bool GetBool(JsonElement parent, string name, bool fallback)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                return fallback;

            if ((value.ValueKind != JsonValueKind.True) && (value.ValueKind != JsonValueKind.False))
                throw new FormatException("dnsApp.config: " + name + " должен быть true или false.");

            return value.GetBoolean();
        }

        static int GetInt32(JsonElement parent, string name, int fallback)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                return fallback;

            if ((value.ValueKind != JsonValueKind.Number) || !value.TryGetInt32(out int number))
                throw new FormatException("dnsApp.config: " + name + " должен быть целым числом.");

            return number;
        }

        static int Clamp(int value, int min, int max)
        {
            if (value < min)
                return min;

            if (value > max)
                return max;

            return value;
        }

        #endregion

        #region properties

        public string RulesetPath { get; }

        public string RuntimeStatePath { get; }

        public bool Enabled { get; }

        public byte AppPreference { get; }

        public int DebounceMs { get; }

        public int PollIntervalSec { get; }

        #endregion
    }
}
