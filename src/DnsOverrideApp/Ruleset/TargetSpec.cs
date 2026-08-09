/*
DNS Override — приложение для Technitium DNS Server.

Элемент массива targets[] из заголовка ruleset. Правило ссылается на него
по индексу (решение D3), поэтому имя нужно только для логов и runtime-state.
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride.Ruleset
{
    sealed class TargetSpec
    {
        #region constants

        const uint DefaultTtl = 60;
        const int MaxAddressesPerFamily = 32;
        const int MaxStackOrder = 64;

        #endregion

        #region variables

        readonly DnsResourceRecordData[] _ipv4;
        readonly DnsResourceRecordData[] _ipv6;

        int _rotationCounterV4;
        int _rotationCounterV6;

        #endregion

        #region constructor

        TargetSpec(string name, TargetMode mode, DnsResourceRecordData[] ipv4, DnsResourceRecordData[] ipv6, uint ttl, AddressRotation rotation, EmptyFamilyPolicy emptyFamilyPolicy)
        {
            Name = name;
            Mode = mode;
            _ipv4 = ipv4;
            _ipv6 = ipv6;
            Ttl = ttl;
            Rotation = rotation;
            EmptyFamilyPolicy = emptyFamilyPolicy;
        }

        #endregion

        #region public

        public static TargetSpec Parse(JsonElement json, int index)
        {
            string where = "targets[" + index + "]";

            if (json.ValueKind != JsonValueKind.Object)
                throw new RulesetFormatException(where + ": ожидался объект.");

            string name = JsonUtil.RequireString(json, "name", where);
            TargetMode mode = ParseMode(JsonUtil.RequireString(json, "mode", where), where);

            DnsResourceRecordData[] ipv4 = ParseAddresses(json, "ipv4", AddressFamily.InterNetwork, where);
            DnsResourceRecordData[] ipv6 = ParseAddresses(json, "ipv6", AddressFamily.InterNetworkV6, where);

            if ((mode == TargetMode.Address) && (ipv4.Length == 0) && (ipv6.Length == 0))
                throw new RulesetFormatException(where + ": mode=address без адресов.");

            uint ttl = JsonUtil.OptionalUInt32(json, "ttl", DefaultTtl, where);
            if (ttl > 604800)
                throw new RulesetFormatException(where + ": ttl вне диапазона 0..604800.");

            AddressRotation rotation = ParseRotation(JsonUtil.OptionalString(json, "rotation", "none", where)!, where);
            EmptyFamilyPolicy emptyFamilyPolicy = ParseEmptyFamilyPolicy(JsonUtil.OptionalString(json, "emptyFamilyPolicy", "nodata", where)!, where);

            return new TargetSpec(name, mode, ipv4, ipv6, ttl, rotation, emptyFamilyPolicy);
        }

        /// <summary>
        /// Дописывает адреса запрошенного семейства в ANSWER с учётом rotation.
        /// Возвращает false, если адресов этого семейства в target нет — дальше
        /// решает <see cref="EmptyFamilyPolicy"/>.
        /// </summary>
        public bool TryAppendAddresses(List<DnsResourceRecord> answer, string name, DnsClass @class, DnsResourceRecordType type)
        {
            DnsResourceRecordData[] rdata;
            ref int counter = ref _rotationCounterV4;

            switch (type)
            {
                case DnsResourceRecordType.A:
                    rdata = _ipv4;
                    counter = ref _rotationCounterV4;
                    break;

                case DnsResourceRecordType.AAAA:
                    rdata = _ipv6;
                    counter = ref _rotationCounterV6;
                    break;

                default:
                    return false;
            }

            if (rdata.Length == 0)
                return false;

            if ((rdata.Length == 1) || (Rotation == AddressRotation.None) || (rdata.Length > MaxStackOrder))
            {
                foreach (DnsResourceRecordData item in rdata)
                    answer.Add(new DnsResourceRecord(name, type, @class, Ttl, item));

                return true;
            }

            Span<int> order = stackalloc int[rdata.Length];

            for (int i = 0; i < order.Length; i++)
                order[i] = i;

            if (Rotation == AddressRotation.RoundRobin)
            {
                int start = (int)((uint)Interlocked.Increment(ref counter) % (uint)rdata.Length);

                for (int i = 0; i < order.Length; i++)
                    order[i] = (start + i) % rdata.Length;
            }
            else
            {
                for (int i = order.Length - 1; i > 0; i--)
                {
                    int j = Random.Shared.Next(i + 1);
                    (order[i], order[j]) = (order[j], order[i]);
                }
            }

            foreach (int i in order)
                answer.Add(new DnsResourceRecord(name, type, @class, Ttl, rdata[i]));

            return true;
        }

        #endregion

        #region private

        static TargetMode ParseMode(string value, string where)
        {
            switch (value)
            {
                case "address": return TargetMode.Address;
                case "nxdomain": return TargetMode.NxDomain;
                case "nodata": return TargetMode.NoData;
                case "refused": return TargetMode.Refused;
                default: throw new RulesetFormatException(where + ": недопустимый mode '" + value + "'.");
            }
        }

        static AddressRotation ParseRotation(string value, string where)
        {
            switch (value)
            {
                case "none": return AddressRotation.None;
                case "round-robin": return AddressRotation.RoundRobin;
                case "random": return AddressRotation.Random;
                default: throw new RulesetFormatException(where + ": недопустимый rotation '" + value + "'.");
            }
        }

        static EmptyFamilyPolicy ParseEmptyFamilyPolicy(string value, string where)
        {
            switch (value)
            {
                case "nodata": return EmptyFamilyPolicy.NoData;
                case "passthru": return EmptyFamilyPolicy.Passthru;
                case "answer": return EmptyFamilyPolicy.Answer;
                default: throw new RulesetFormatException(where + ": недопустимый emptyFamilyPolicy '" + value + "'.");
            }
        }

        static DnsResourceRecordData[] ParseAddresses(JsonElement json, string property, AddressFamily family, string where)
        {
            if (!json.TryGetProperty(property, out JsonElement array) || (array.ValueKind == JsonValueKind.Null))
                return Array.Empty<DnsResourceRecordData>();

            if (array.ValueKind != JsonValueKind.Array)
                throw new RulesetFormatException(where + "." + property + ": ожидался массив строк.");

            int length = array.GetArrayLength();
            if (length == 0)
                return Array.Empty<DnsResourceRecordData>();

            if (length > MaxAddressesPerFamily)
                throw new RulesetFormatException(where + "." + property + ": больше " + MaxAddressesPerFamily + " адресов.");

            DnsResourceRecordData[] result = new DnsResourceRecordData[length];
            int i = 0;

            foreach (JsonElement item in array.EnumerateArray())
            {
                if ((item.ValueKind != JsonValueKind.String) || !IPAddress.TryParse(item.GetString(), out IPAddress? address) || (address.AddressFamily != family))
                    throw new RulesetFormatException(where + "." + property + "[" + i + "]: не является адресом " + (family == AddressFamily.InterNetwork ? "IPv4" : "IPv6") + ".");

                result[i++] = family == AddressFamily.InterNetwork ? new DnsARecordData(address) : new DnsAAAARecordData(address);
            }

            return result;
        }

        #endregion

        #region properties

        public string Name { get; }

        public TargetMode Mode { get; }

        public uint Ttl { get; }

        public AddressRotation Rotation { get; }

        public EmptyFamilyPolicy EmptyFamilyPolicy { get; }

        public int AddressCountV4
        { get { return _ipv4.Length; } }

        public int AddressCountV6
        { get { return _ipv6.Length; } }

        #endregion
    }
}
