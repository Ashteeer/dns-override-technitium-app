using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride.Ruleset
{
    sealed class BypassPolicy
    {
        const int MaxRegexPatterns = 256;

        public static readonly BypassPolicy Empty = new BypassPolicy();

        readonly HashSet<string> _exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> _suffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> _protected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly List<DomainPattern> _allowPatterns = new List<DomainPattern>();
        readonly List<DomainPattern> _rules = new List<DomainPattern>();
        readonly List<AddressRange> _ipv4 = new List<AddressRange>();
        readonly List<AddressRange> _ipv6 = new List<AddressRange>();

        public bool HasNetworks => (_ipv4.Count != 0) || (_ipv6.Count != 0);
        public bool HasNames => (_exact.Count != 0) || (_suffixes.Count != 0) || (_allowPatterns.Count != 0);
        public int Count => _exact.Count + _suffixes.Count + _ipv4.Count + _ipv6.Count + _allowPatterns.Count + _rules.Count;

        public static BypassPolicy Parse(JsonElement json, int targetCount)
        {
            if (json.ValueKind != JsonValueKind.Object)
                throw new RulesetFormatException("policy: ожидался объект.");

            var policy = new BypassPolicy();
            foreach (JsonElement entry in ReadArray(json, "allowDomains"))
            {
                string domain = ReadString(entry, "allowDomains");
                if (domain.StartsWith('@'))
                    policy._exact.Add(ValidateDomain(domain[1..]));
                else
                    policy._suffixes.Add(ValidateDomain(domain));
            }
            foreach (JsonElement entry in ReadArray(json, "protectedZones"))
                policy._protected.Add(ValidateDomain(ReadString(entry, "protectedZones")));

            foreach (JsonElement entry in ReadArray(json, "allowNetworks"))
            {
                string value = ReadString(entry, "allowNetworks");
                if (value.Contains('%') || !IPNetwork.TryParse(value, out IPNetwork network))
                    throw new RulesetFormatException("policy.allowNetworks: некорректная подсеть " + value + ".");
                bool ipv4 = network.BaseAddress.AddressFamily == AddressFamily.InterNetwork;
                int hostBits = (ipv4 ? 32 : 128) - network.PrefixLength;
                UInt128 start = AddressValue(network.BaseAddress);
                UInt128 mask = hostBits == 128 ? UInt128.MaxValue : ((UInt128.One << hostBits) - 1);
                (ipv4 ? policy._ipv4 : policy._ipv6).Add(new AddressRange(start, start | mask));
            }
            Merge(policy._ipv4);
            Merge(policy._ipv6);

            int regexCount = 0;
            foreach (JsonElement entry in ReadArray(json, "patterns"))
            {
                const string where = "policy.patterns";
                if (entry.ValueKind != JsonValueKind.Object)
                    throw new RulesetFormatException(where + ": ожидался объект.");
                string action = JsonUtil.RequireString(entry, "action", where);
                int index = JsonUtil.RequireInt32(entry, "targetIndex", where);
                if (action is not ("allowlist" or "passthru" or "override") || index < 0 ||
                    index >= targetCount || (action != "override" && index != 0))
                    throw new RulesetFormatException(where + ": некорректное действие или targetIndex.");

                string kind = JsonUtil.RequireString(entry, "kind", where);
                string value = JsonUtil.RequireString(entry, "value", where);
                if (value.Length is < 1 or > 1024 || value.AsSpan().IndexOfAnyExceptInRange(' ', '~') >= 0)
                    throw new RulesetFormatException(where + ": шаблон должен содержать 1…1024 печатных ASCII-символов.");
                Regex? regex = null;
                switch (kind)
                {
                    case "substring":
                        break;
                    case "regexp":
                        if (++regexCount > MaxRegexPatterns)
                            throw new RulesetFormatException(where + ": максимум 256 регулярных выражений.");
                        try
                        {
                            regex = new Regex(value, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
                        }
                        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
                        {
                            throw new RulesetFormatException(where + ": " + ex.Message);
                        }
                        break;
                    default:
                        throw new RulesetFormatException(where + ": неизвестный тип " + kind + ".");
                }

                bool allow = action == "allowlist";
                (allow ? policy._allowPatterns : policy._rules).Add(
                    new DomainPattern(value, regex, action == "override" ? index : -1));
            }
            return policy;
        }

        public bool AllowsName(string name)
        {
            ReadOnlySpan<char> domain = name.AsSpan().TrimEnd('.');
            return (_exact.Count != 0 && _exact.GetAlternateLookup<ReadOnlySpan<char>>().Contains(domain)) ||
                ContainsSuffix(_suffixes, domain) ||
                TryMatch(_allowPatterns, domain, out _);
        }

        public bool TryMatchRule(string name, out int targetIndex)
        {
            ReadOnlySpan<char> domain = name.AsSpan().TrimEnd('.');
            targetIndex = -1;
            return domain.Contains('.') && !ContainsSuffix(_protected, domain) &&
                TryMatch(_rules, domain, out targetIndex);
        }

        static bool TryMatch(List<DomainPattern> patterns, ReadOnlySpan<char> domain, out int targetIndex)
        {
            targetIndex = -1;
            if (patterns.Count == 0 || domain.IsEmpty)
                return false;
            // DNS-имена приведены к нижнему регистру, как при поиске в GeoSite.
            Span<char> lower = stackalloc char[RulesetParser.MaxRDomainLength];
            int length = domain.ToLowerInvariant(lower);
            if (length < 0)
                return false;
            foreach (DomainPattern pattern in patterns)
            {
                if (!pattern.Matches(lower[..length]))
                    continue;
                targetIndex = pattern.TargetIndex;
                return true;
            }
            return false;
        }

        public bool AllowsAnswer(DnsDatagram response)
        {
            foreach (DnsResourceRecord record in response.Answer)
            {
                switch (record.RDATA)
                {
                    case DnsARecordData a when ContainsAddress(a.Address):
                    case DnsAAAARecordData aaaa when ContainsAddress(aaaa.Address):
                        return true;
                    case DnsSVCBRecordData svcb:
                        foreach (DnsSvcParamValue parameter in svcb.SvcParams.Values)
                        {
                            IReadOnlyList<IPAddress>? hints = parameter switch
                            {
                                DnsSvcIPv4HintParamValue ipv4 => ipv4.Addresses,
                                DnsSvcIPv6HintParamValue ipv6 => ipv6.Addresses,
                                _ => null
                            };
                            if (hints is null)
                                continue;
                            foreach (IPAddress address in hints)
                            {
                                if (ContainsAddress(address))
                                    return true;
                            }
                        }
                        break;
                }
            }
            return false;
        }

        bool ContainsAddress(IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
                return Contains(_ipv4, AddressValue(address));
            return Contains(_ipv6, AddressValue(address)) ||
                (address.IsIPv4MappedToIPv6 && Contains(_ipv4, AddressValue(address.MapToIPv4())));
        }

        static bool ContainsSuffix(HashSet<string> domains, ReadOnlySpan<char> name)
        {
            if (domains.Count == 0)
                return false;
            var lookup = domains.GetAlternateLookup<ReadOnlySpan<char>>();
            while (!name.IsEmpty)
            {
                if (lookup.Contains(name))
                    return true;
                int dot = name.IndexOf('.');
                if (dot < 0)
                    break;
                name = name[(dot + 1)..];
            }
            return false;
        }

        static UInt128 AddressValue(IPAddress address)
        {
            Span<byte> bytes = stackalloc byte[16];
            address.TryWriteBytes(bytes, out int length);
            return length == 4 ? BinaryPrimitives.ReadUInt32BigEndian(bytes) :
                BinaryPrimitives.ReadUInt128BigEndian(bytes);
        }

        static void Merge(List<AddressRange> ranges)
        {
            ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
            int count = 0;
            for (int i = 0; i < ranges.Count; i++)
            {
                AddressRange range = ranges[i];
                if (count > 0 && range.Start <= ranges[count - 1].End)
                    ranges[count - 1] = new AddressRange(ranges[count - 1].Start,
                        UInt128.Max(ranges[count - 1].End, range.End));
                else
                    ranges[count++] = range;
            }
            ranges.RemoveRange(count, ranges.Count - count);
        }

        static bool Contains(List<AddressRange> ranges, UInt128 address)
        {
            int lo = 0, hi = ranges.Count - 1;
            while (lo <= hi)
            {
                int mid = lo + (hi - lo) / 2;
                AddressRange range = ranges[mid];
                if (address < range.Start)
                    hi = mid - 1;
                else if (address > range.End)
                    lo = mid + 1;
                else
                    return true;
            }
            return false;
        }

        static IEnumerable<JsonElement> ReadArray(JsonElement parent, string name)
        {
            if (!parent.TryGetProperty(name, out JsonElement array))
                yield break;
            if (array.ValueKind != JsonValueKind.Array)
                throw new RulesetFormatException("policy." + name + ": ожидался массив.");
            foreach (JsonElement item in array.EnumerateArray())
                yield return item;
        }

        static string ReadString(JsonElement item, string name)
        {
            if (item.ValueKind != JsonValueKind.String)
                throw new RulesetFormatException("policy." + name + ": ожидалась строка.");
            return item.GetString()!;
        }

        static string ValidateDomain(string domain)
        {
            RulesetParser.ValidateRDomain(System.Text.Encoding.UTF8.GetBytes(domain), 1);
            return domain;
        }

        readonly record struct AddressRange(UInt128 Start, UInt128 End);

        readonly record struct DomainPattern(string Value, Regex? Regex, int TargetIndex)
        {
            public bool Matches(ReadOnlySpan<char> domain)
                => Regex?.IsMatch(domain) ?? domain.Contains(Value, StringComparison.Ordinal);
        }
    }
}
