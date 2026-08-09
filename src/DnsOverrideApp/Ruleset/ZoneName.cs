/*
DNS Override — приложение для Technitium DNS Server.

Имя зоны для SOA в отрицательных ответах. Домен правила лежит в буфере снапшота
в обратном порядке меток, разворачивать его нужно только для NODATA/NXDOMAIN —
в горячем пути с адресными ответами строка не создаётся вовсе.
*/

namespace DnsOverride.Ruleset
{
    readonly struct ZoneName
    {
        #region variables

        readonly RulesetSnapshot? _snapshot;
        readonly int _lineIndex;
        readonly string _fallback;

        #endregion

        #region constructor

        ZoneName(RulesetSnapshot? snapshot, int lineIndex, string fallback)
        {
            _snapshot = snapshot;
            _lineIndex = lineIndex;
            _fallback = fallback;
        }

        /// <summary>Зона взята из сработавшего правила.</summary>
        public static ZoneName FromRule(RulesetSnapshot snapshot, int lineIndex)
        {
            return new ZoneName(snapshot, lineIndex, string.Empty);
        }

        /// <summary>Правило не сработало (defaultAction=override) — зоной считается сам QNAME.</summary>
        public static ZoneName FromQuestion(string qname)
        {
            return new ZoneName(null, 0, qname);
        }

        #endregion

        #region properties

        public string Value
        { get { return _snapshot is null ? _fallback : _snapshot.GetRuleDomain(_lineIndex); } }

        #endregion
    }
}
