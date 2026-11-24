/*
Сборка тестовых ruleset.dat по контракту docs/ruleset-format.md.
Позволяет намеренно сломать count, sha256 и сигнатуру — для проверок отклонения.
*/

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DnsOverride.Tests;

sealed class RulesetBuilder
{
    public string Magic = "!DNSOVR1";
    public int Version = 1;
    public long Revision = 1;
    public string GeneratedAt = "2026-08-09T12:00:00Z";
    public string Generator = "tests/1.0";

    public string Engine = """{"enabled":true,"defaultAction":"passthru","defaultTarget":null,"logMatches":false,"logSampleRate":0.0}""";

    public string Targets = """[{"name":"default","mode":"address","ipv4":["10.8.0.1"],"ipv6":[],"ttl":60,"rotation":"none","emptyFamilyPolicy":"nodata"},{"name":"proxy","mode":"address","ipv4":["10.8.0.2"],"ipv6":["fd00::2"],"ttl":120,"rotation":"none","emptyFamilyPolicy":"nodata"},{"name":"blackhole","mode":"nxdomain","ttl":300}]""";

    public string QtypePolicy = """{"A":"target","AAAA":"target","HTTPS":"nodata","SVCB":"nodata","ANY":"nodata","*":"passthru"}""";
    public string? Policy { get; set; }

    public List<string> Rules = new List<string>();

    public int? CountOverride;
    public string? Sha256Override;

    public byte[] ToBytes()
    {
        string bodyText = Rules.Count == 0 ? string.Empty : string.Join('\n', Rules) + "\n";
        byte[] body = Encoding.UTF8.GetBytes(bodyText);

        string sha256 = Sha256Override ?? Convert.ToHexStringLower(SHA256.HashData(body));
        int count = CountOverride ?? Rules.Count;

        string header = $$"""
{"version":{{Version}},"revision":{{Revision}},"generatedAt":"{{GeneratedAt}}","generator":"{{Generator}}","count":{{count}},"sha256":"{{sha256}}","engine":{{Engine}},"targets":{{Targets}},"qtypePolicy":{{QtypePolicy}}}
""";

        header = header.Trim();
        if (Policy is not null)
        {
            using JsonDocument policy = JsonDocument.Parse(Policy);
            header = header[..^1] + ",\"policy\":" + JsonSerializer.Serialize(policy.RootElement) + "}";
        }
        byte[] head = Encoding.UTF8.GetBytes(Magic + " " + header + "\n");
        byte[] result = new byte[head.Length + body.Length];

        Buffer.BlockCopy(head, 0, result, 0, head.Length);
        Buffer.BlockCopy(body, 0, result, head.Length, body.Length);

        return result;
    }

    public string WriteTo(string path)
    {
        // Так же, как пишет бот: .tmp → rename(). Замена inode — то, из-за чего
        // watcher вешается на каталог, а не на файл.
        string temporary = path + ".tmp";

        File.WriteAllBytes(temporary, ToBytes());
        File.Move(temporary, path, true);

        return path;
    }

    /// <summary>Правила из docs/rule-matching.md §2.1 — эталонный пример.</summary>
    public static RulesetBuilder Sample()
    {
        return new RulesetBuilder()
        {
            Rules =
            {
                "WP0 com.google",
                "WO0 com.google.test",
                "AO1 org.example"
            }
        };
    }
}
