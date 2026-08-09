/*
DNS Override — приложение для Technitium DNS Server.

qtypePolicy из заголовка ruleset: «тип записи → действие». Ключ '*' обязателен
и работает как значение по умолчанию (docs/rule-matching.md §5).
*/

using System.Collections.Generic;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride.Ruleset
{
    sealed class QtypePolicy
    {
        #region variables

        readonly Dictionary<DnsResourceRecordType, QtypeAction> _map;
        readonly QtypeAction _fallback;

        #endregion

        #region constructor

        QtypePolicy(Dictionary<DnsResourceRecordType, QtypeAction> map, QtypeAction fallback)
        {
            _map = map;
            _fallback = fallback;
        }

        #endregion

        #region public

        public static QtypePolicy Parse(JsonElement json, List<string> warnings)
        {
            const string where = "qtypePolicy";

            if (json.ValueKind != JsonValueKind.Object)
                throw new RulesetFormatException(where + ": ожидался объект.");

            Dictionary<DnsResourceRecordType, QtypeAction> map = new Dictionary<DnsResourceRecordType, QtypeAction>();
            QtypeAction? fallback = null;

            foreach (JsonProperty property in json.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String)
                    throw new RulesetFormatException(where + "." + property.Name + ": ожидалась строка.");

                QtypeAction action = ParseAction(property.Value.GetString()!, where + "." + property.Name);

                if (property.Name == "*")
                {
                    fallback = action;
                    continue;
                }

                // Неизвестное имя типа записи не является ошибкой формата: по §6
                // ruleset-format.md бот новее приложения может добавлять поля.
                if (RecordTypeUtil.TryParse(property.Name, out DnsResourceRecordType type))
                    map[type] = action;
                else
                    warnings.Add("qtypePolicy: неизвестный тип записи '" + property.Name + "' — правило проигнорировано.");
            }

            if (fallback is null)
                throw new RulesetFormatException(where + ": обязателен ключ '*'.");

            return new QtypePolicy(map, fallback.Value);
        }

        public QtypeAction For(DnsResourceRecordType type)
        {
            if (_map.TryGetValue(type, out QtypeAction action))
                return action;

            return _fallback;
        }

        #endregion

        #region private

        static QtypeAction ParseAction(string value, string where)
        {
            switch (value)
            {
                case "target": return QtypeAction.Target;
                case "nodata": return QtypeAction.NoData;
                case "nxdomain": return QtypeAction.NxDomain;
                case "passthru": return QtypeAction.Passthru;
                default: throw new RulesetFormatException(where + ": недопустимое действие '" + value + "'.");
            }
        }

        #endregion

        #region properties

        public QtypeAction Fallback
        { get { return _fallback; } }

        public int ExplicitCount
        { get { return _map.Count; } }

        #endregion
    }
}
