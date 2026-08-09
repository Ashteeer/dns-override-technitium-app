/*
Поднимает App в временном каталоге: dnsApp.config + ruleset.dat + runtime-state.json.
*/

using System.Net;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride.Tests;

sealed class AppHost : IDisposable
{
    public readonly string Directory;
    public readonly string RulesetPath;
    public readonly string RuntimeStatePath;
    public readonly TestDnsServer Server;
    public readonly App App = new App();

    AppHost(string directory)
    {
        Directory = directory;
        RulesetPath = Path.Combine(directory, "ruleset.dat");
        RuntimeStatePath = Path.Combine(directory, "runtime-state.json");
        Server = new TestDnsServer(directory);
    }

    public static async Task<AppHost> StartAsync(RulesetBuilder? builder, bool enabled = true, int pollIntervalSec = 3600)
    {
        string directory = Path.Combine(Path.GetTempPath(), "dns-override-tests", Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(directory);

        AppHost host = new AppHost(directory);

        builder?.WriteTo(host.RulesetPath);

        string config = JsonSerializer.Serialize(new
        {
            rulesetPath = host.RulesetPath,
            runtimeStatePath = host.RuntimeStatePath,
            enabled,
            appPreference = 20,
            watch = new { debounceMs = 100, pollIntervalSec }
        });

        await host.App.InitializeAsync(host.Server, config);

        return host;
    }

    public Task<DnsDatagram?> QueryAsync(string name, DnsResourceRecordType type, bool recursionAllowed = true)
    {
        DnsDatagram request = new DnsDatagram(1234, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
            [new DnsQuestionRecord(name, type, DnsClass.IN)]);

        return App.ProcessRequestAsync(request, new IPEndPoint(IPAddress.Loopback, 5353), DnsTransportProtocol.Udp, recursionAllowed);
    }

    public JsonElement ReadRuntimeState()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(RuntimeStatePath));

        return document.RootElement.Clone();
    }

    public void Dispose()
    {
        App.Dispose();

        try
        {
            System.IO.Directory.Delete(Directory, true);
        }
        catch (IOException)
        { }
    }
}
