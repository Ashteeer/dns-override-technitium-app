using System.Net;
using DnsOverride.Ruleset;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsOverride.Tests;

public class BypassPolicyTests
{
    static readonly IPEndPoint Endpoint = new IPEndPoint(IPAddress.Loopback, 5353);

    [Fact]
    public async Task DomainAllowlistBeatsMoreSpecificAndDefaultOverrides()
    {
        var builder = new RulesetBuilder()
        {
            Version = 2,
            Policy = """{"allowDomains":["example.com","@exact.test"]}""",
            Engine = """{"enabled":true,"defaultAction":"override","defaultTarget":"default"}""",
            Rules = { "AO1 com.example.child" }
        };
        using AppHost host = await AppHost.StartAsync(builder);

        Assert.Null(await host.QueryAsync("child.example.com", DnsResourceRecordType.A));
        Assert.Null(await host.QueryAsync("EXACT.test", DnsResourceRecordType.HTTPS));
        Assert.NotNull(await host.QueryAsync("child.exact.test", DnsResourceRecordType.A));
        Assert.NotNull(await host.QueryAsync("notexample.com", DnsResourceRecordType.A));
        Assert.Null(await host.QueryAsync("notexample.com", DnsResourceRecordType.A, false));

        var request = new DnsDatagram(1234, false, DnsOpcode.StandardQuery, false, false, true, false, false, false,
            DnsResponseCode.NoError, [new DnsQuestionRecord("child.example.com", DnsResourceRecordType.A, DnsClass.IN)]);
        var alias = new DnsResourceRecord(request.Question[0].Name, DnsResourceRecordType.CNAME, DnsClass.IN, 300,
            new DnsCNAMERecordData("target.test"));
        DnsDatagram original = Answer(request, alias);
        DnsDatagram synthetic = Answer(request, Address("target.test", "10.8.0.1"));
        host.Server.OriginalQuery = (query, endpoint) =>
        {
            Assert.Same(request, query);
            Assert.Equal(Endpoint, endpoint);
            return Task.FromResult(original);
        };
        Assert.Same(original, await host.App.PostProcessAsync(request, Endpoint, DnsTransportProtocol.Udp, synthetic));
    }

    [Theory]
    [InlineData("192.0.2.99", true)]
    [InlineData("192.0.3.1", false)]
    [InlineData("2001:db8::42", true)]
    [InlineData("2001:db9::42", false)]
    public async Task GeoIpTestsOriginalAddressAndPreservesWholeAnswer(string address, bool allowed)
    {
        var builder = new RulesetBuilder()
        {
            Version = 2,
            Policy = """{"allowNetworks":["192.0.2.0/24","2001:db8::/32"]}""",
            Rules = { "WO1 com.example" }
        };
        using AppHost host = await AppHost.StartAsync(builder);
        DnsResourceRecord record = Address("upstream.test", address);
        DnsDatagram? original = null;
        host.Server.OriginalQuery = (request, endpoint) =>
        {
            Assert.Equal(Endpoint, endpoint);
            original = Answer(request,
                new DnsResourceRecord("example.com", DnsResourceRecordType.CNAME, DnsClass.IN, 300,
                    new DnsCNAMERecordData("upstream.test")), record);
            return Task.FromResult(original);
        };

        DnsDatagram? response = await host.QueryAsync("example.com", record.Type);
        Assert.NotNull(original);
        if (allowed)
            Assert.Same(original, response);
        else
            Assert.Single(response!.Answer);
    }

    [Fact]
    public async Task GeoSitePatternAllowlistWinsAndProtectedZonesSkipPatterns()
    {
        var builder = new RulesetBuilder()
        {
            Version = 2,
            Policy = """
                {"protectedZones":["local"],"patterns":[
                  {"kind":"substring","value":"example","action":"override","targetIndex":1},
                  {"kind":"regexp","value":"^safe[0-9]+\\.","action":"allowlist","targetIndex":0}
                ]}
                """
        };
        using AppHost host = await AppHost.StartAsync(builder);
        Assert.NotNull(await host.QueryAsync("A.EXAMPLE.NET", DnsResourceRecordType.A));
        Assert.Null(await host.QueryAsync("safe1.example.net", DnsResourceRecordType.A));
        Assert.Null(await host.QueryAsync("example.local", DnsResourceRecordType.A));
        Assert.Null(await host.QueryAsync("safeXYZ.example.net", DnsResourceRecordType.MX));
    }

    [Fact]
    public void VersionTwoWithoutPolicyIsRejected()
    {
        var builder = new RulesetBuilder() { Version = 2 };
        Assert.Throws<RulesetFormatException>(() => RulesetParser.Parse(builder.ToBytes(), null));
    }

    static DnsResourceRecord Address(string owner, string address)
    {
        IPAddress ip = IPAddress.Parse(address);
        return address.Contains(':')
            ? new DnsResourceRecord(owner, DnsResourceRecordType.AAAA, DnsClass.IN, 300, new DnsAAAARecordData(ip))
            : new DnsResourceRecord(owner, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(ip));
    }

    static DnsDatagram Answer(DnsDatagram request, params DnsResourceRecord[] records)
        => new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, true, false,
            DnsResponseCode.NoError, request.Question, records);
}
