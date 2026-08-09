/*
DNS Override — приложение для Technitium DNS Server.

Обратный канал приложение → бот: runtime-state.json (docs/ruleset-loading.md §5).
Конфигом не является, руками не редактируется. Пишется тем же приёмом, что и
ruleset у бота: .tmp → flush → rename, чтобы бот не прочитал полуфайл.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace DnsOverride
{
    /// <summary>Снимок состояния приложения для записи в runtime-state.json.</summary>
    sealed class RuntimeStateData
    {
        public string AppVersion = "0.0.0";
        public DateTime StartedAtUtc;
        public DateTime? LastLoadAtUtc;
        public long LastLoadDurationMs;
        public string? LastLoadTrigger;
        public long? AppliedRevision;
        public int RulesLoaded;
        public int TargetsLoaded;
        public long SnapshotBytes;
        public DateTime? RulesetModifiedUtc;
        public bool Enabled;
        public List<string> Errors = new List<string>();
    }

    static class RuntimeStateWriter
    {
        #region constants

        /// <summary>Сколько последних ошибок держать в файле.</summary>
        public const int MaxErrors = 10;

        #endregion

        #region public

        public static void Write(string path, RuntimeStateData data, Stats stats)
        {
            string? directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            string temporaryPath = path + ".tmp";

            using (FileStream stream = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(stream, new JsonWriterOptions() { Indented = true }))
                {
                    writer.WriteStartObject();

                    writer.WriteString("appVersion", data.AppVersion);
                    writer.WriteString("startedAt", Iso8601(data.StartedAtUtc));
                    WriteNullableTime(writer, "lastLoadAt", data.LastLoadAtUtc);
                    writer.WriteNumber("lastLoadDurationMs", data.LastLoadDurationMs);

                    if (data.LastLoadTrigger is null)
                        writer.WriteNull("lastLoadTrigger");
                    else
                        writer.WriteString("lastLoadTrigger", data.LastLoadTrigger);

                    if (data.AppliedRevision.HasValue)
                        writer.WriteNumber("appliedRevision", data.AppliedRevision.Value);
                    else
                        writer.WriteNull("appliedRevision");

                    writer.WriteNumber("rulesLoaded", data.RulesLoaded);
                    writer.WriteNumber("targetsLoaded", data.TargetsLoaded);
                    writer.WriteNumber("snapshotBytes", data.SnapshotBytes);
                    WriteNullableTime(writer, "rulesetMTime", data.RulesetModifiedUtc);
                    writer.WriteBoolean("enabled", data.Enabled);

                    writer.WriteStartArray("errors");

                    foreach (string error in data.Errors)
                        writer.WriteStringValue(error);

                    writer.WriteEndArray();

                    writer.WriteStartObject("stats");
                    writer.WriteNumber("queriesTotal", stats.QueriesTotal);
                    writer.WriteNumber("overridden", stats.Overridden);
                    writer.WriteNumber("passthru", stats.Passthru);
                    writer.WriteNumber("nodata", stats.NoData);
                    writer.WriteNumber("nxdomain", stats.NxDomain);
                    writer.WriteNumber("refused", stats.Refused);
                    writer.WriteString("since", Iso8601(stats.SinceUtc));
                    writer.WriteEndObject();

                    writer.WriteEndObject();
                    writer.Flush();
                }

                stream.Flush(true);
            }

            File.Move(temporaryPath, path, true);
        }

        public static string Iso8601(DateTime value)
        {
            return value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        }

        #endregion

        #region private

        static void WriteNullableTime(Utf8JsonWriter writer, string name, DateTime? value)
        {
            if (value.HasValue)
                writer.WriteString(name, Iso8601(value.Value));
            else
                writer.WriteNull(name);
        }

        #endregion
    }
}
