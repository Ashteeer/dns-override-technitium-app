/*
DNS Override — приложение для Technitium DNS Server.
*/

using System;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride.Ruleset
{
    static class RecordTypeUtil
    {
        /// <summary>
        /// Имя типа записи из qtypePolicy → DnsResourceRecordType. Допускается как
        /// имя (<c>A</c>, <c>HTTPS</c>), так и числовой код (<c>65</c>) — на случай
        /// типов, которых нет в перечислении TechnitiumLibrary.
        /// </summary>
        public static bool TryParse(string name, out DnsResourceRecordType type)
        {
            if (string.IsNullOrEmpty(name) || (name.IndexOf(',') >= 0))
            {
                type = DnsResourceRecordType.Unknown;
                return false;
            }

            return Enum.TryParse(name, true, out type);
        }
    }
}
