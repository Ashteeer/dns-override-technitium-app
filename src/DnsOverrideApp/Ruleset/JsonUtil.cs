/*
DNS Override — приложение для Technitium DNS Server.

Мелкие помощники разбора заголовка ruleset. Любое отклонение от контракта —
RulesetFormatException: приложение не чинит битый файл, оно его отвергает.
*/

using System.Text.Json;

namespace DnsOverride.Ruleset
{
    static class JsonUtil
    {
        public static JsonElement RequireProperty(JsonElement parent, string name, string where)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                throw new RulesetFormatException(where + ": отсутствует обязательное поле '" + name + "'.");

            return value;
        }

        public static string RequireString(JsonElement parent, string name, string where)
        {
            JsonElement value = RequireProperty(parent, name, where);

            if (value.ValueKind != JsonValueKind.String)
                throw new RulesetFormatException(where + "." + name + ": ожидалась строка.");

            return value.GetString()!;
        }

        public static string? OptionalString(JsonElement parent, string name, string? fallback, string where)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                return fallback;

            if (value.ValueKind != JsonValueKind.String)
                throw new RulesetFormatException(where + "." + name + ": ожидалась строка.");

            return value.GetString();
        }

        public static int RequireInt32(JsonElement parent, string name, string where)
        {
            JsonElement value = RequireProperty(parent, name, where);

            if ((value.ValueKind != JsonValueKind.Number) || !value.TryGetInt32(out int number))
                throw new RulesetFormatException(where + "." + name + ": ожидалось целое число.");

            return number;
        }

        public static long RequireInt64(JsonElement parent, string name, string where)
        {
            JsonElement value = RequireProperty(parent, name, where);

            if ((value.ValueKind != JsonValueKind.Number) || !value.TryGetInt64(out long number))
                throw new RulesetFormatException(where + "." + name + ": ожидалось целое число.");

            return number;
        }

        public static uint OptionalUInt32(JsonElement parent, string name, uint fallback, string where)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                return fallback;

            if ((value.ValueKind != JsonValueKind.Number) || !value.TryGetUInt32(out uint number))
                throw new RulesetFormatException(where + "." + name + ": ожидалось целое неотрицательное число.");

            return number;
        }

        public static bool OptionalBool(JsonElement parent, string name, bool fallback, string where)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                return fallback;

            switch (value.ValueKind)
            {
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                default: throw new RulesetFormatException(where + "." + name + ": ожидалось true или false.");
            }
        }

        public static double OptionalDouble(JsonElement parent, string name, double fallback, string where)
        {
            if (!parent.TryGetProperty(name, out JsonElement value) || (value.ValueKind == JsonValueKind.Null))
                return fallback;

            if ((value.ValueKind != JsonValueKind.Number) || !value.TryGetDouble(out double number))
                throw new RulesetFormatException(where + "." + name + ": ожидалось число.");

            return number;
        }
    }
}
