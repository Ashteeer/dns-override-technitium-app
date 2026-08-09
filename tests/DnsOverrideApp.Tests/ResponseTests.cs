/*
Формирование ответа: docs/rule-matching.md §5.
Проверяется то, что видит клиент: RCODE, ANSWER, AUTHORITY и флаги.
*/

using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsOverride.Tests;

public class ResponseTests
{
    static RulesetBuilder Overriding(string engine = """{"enabled":true,"defaultAction":"passthru"}""")
    {
        return new RulesetBuilder()
        {
            Engine = engine,
            Rules = { "WO2 com.blocked", "WO0 com.example", "WP0 com.google" }      // тело отсортировано побайтово
        };
    }

    [Fact]
    public async Task OverriddenDomainGetsConfiguredAddress()
    {
        using AppHost host = await AppHost.StartAsync(Overriding());

        DnsDatagram? response = await host.QueryAsync("www.example.com", DnsResourceRecordType.A);

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.NoError, response.RCODE);
        Assert.Single(response.Answer);
        Assert.Equal("www.example.com", response.Answer[0].Name);
        Assert.Equal(60u, response.Answer[0].TTL);
        Assert.Equal(IPAddress.Parse("10.8.0.1"), ((DnsARecordData)response.Answer[0].RDATA).Address);

        Assert.True(response.AuthoritativeAnswer);
        Assert.False(response.AuthenticData);           // подменённые данные не валидированы
        Assert.True(response.RecursionAvailable);
    }

    [Fact]
    public async Task PassthruRuleReturnsNull()
    {
        using AppHost host = await AppHost.StartAsync(Overriding());

        Assert.Null(await host.QueryAsync("www.google.com", DnsResourceRecordType.A));
    }

    [Fact]
    public async Task UnmatchedDomainReturnsNull()
    {
        using AppHost host = await AppHost.StartAsync(Overriding());

        Assert.Null(await host.QueryAsync("www.microsoft.com", DnsResourceRecordType.A));
    }

    [Fact]
    public async Task MissingAddressFamilyGivesNoDataWithSoa()
    {
        // target[0] описан без IPv6, emptyFamilyPolicy=nodata: реальный AAAA утечь не должен.
        using AppHost host = await AppHost.StartAsync(Overriding());

        DnsDatagram? response = await host.QueryAsync("www.example.com", DnsResourceRecordType.AAAA);

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.NoError, response.RCODE);
        Assert.Empty(response.Answer);
        Assert.Single(response.Authority);
        Assert.Equal(DnsResourceRecordType.SOA, response.Authority[0].Type);
        Assert.Equal("example.com", response.Authority[0].Name);
    }

    [Fact]
    public async Task EmptyFamilyPolicyPassthruReturnsNull()
    {
        RulesetBuilder builder = Overriding();
        builder.Targets = """[{"name":"default","mode":"address","ipv4":["10.8.0.1"],"emptyFamilyPolicy":"passthru"},{"name":"x","mode":"nodata"},{"name":"blackhole","mode":"nxdomain","ttl":300}]""";

        using AppHost host = await AppHost.StartAsync(builder);

        Assert.Null(await host.QueryAsync("www.example.com", DnsResourceRecordType.AAAA));
    }

    [Fact]
    public async Task EmptyFamilyPolicyAnswerGivesEmptyNoErrorWithoutSoa()
    {
        RulesetBuilder builder = Overriding();
        builder.Targets = """[{"name":"default","mode":"address","ipv4":["10.8.0.1"],"emptyFamilyPolicy":"answer"},{"name":"x","mode":"nodata"},{"name":"blackhole","mode":"nxdomain","ttl":300}]""";

        using AppHost host = await AppHost.StartAsync(builder);

        DnsDatagram? response = await host.QueryAsync("www.example.com", DnsResourceRecordType.AAAA);

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.NoError, response.RCODE);
        Assert.Empty(response.Answer);
        Assert.Empty(response.Authority);
    }

    [Theory]
    [InlineData(DnsResourceRecordType.HTTPS)]
    [InlineData(DnsResourceRecordType.SVCB)]
    [InlineData(DnsResourceRecordType.ANY)]
    public async Task HttpsSvcbAndAnyGiveNoData(DnsResourceRecordType type)
    {
        // ipv4hint/ipv6hint в HTTPS/SVCB уводят браузер мимо подмены — их гасим.
        using AppHost host = await AppHost.StartAsync(Overriding());

        DnsDatagram? response = await host.QueryAsync("www.example.com", type);

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.NoError, response.RCODE);
        Assert.Empty(response.Answer);
        Assert.Single(response.Authority);
    }

    [Fact]
    public async Task TypesUnderStarPolicyArePassthru()
    {
        using AppHost host = await AppHost.StartAsync(Overriding());

        Assert.Null(await host.QueryAsync("www.example.com", DnsResourceRecordType.MX));
        Assert.Null(await host.QueryAsync("www.example.com", DnsResourceRecordType.TXT));
    }

    [Fact]
    public async Task NxDomainTargetGivesNxDomainWithParentZoneSoa()
    {
        using AppHost host = await AppHost.StartAsync(Overriding());

        DnsDatagram? response = await host.QueryAsync("ads.blocked.com", DnsResourceRecordType.A);

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.NxDomain, response.RCODE);
        Assert.Empty(response.Answer);
        Assert.Single(response.Authority);
        Assert.Equal("com", response.Authority[0].Name);
        Assert.Equal(300u, response.Authority[0].TTL);
    }

    [Fact]
    public async Task RefusedTargetGivesRefused()
    {
        RulesetBuilder builder = Overriding();
        builder.Targets = """[{"name":"default","mode":"refused","ttl":30},{"name":"x","mode":"nodata"},{"name":"blackhole","mode":"nxdomain","ttl":300}]""";

        using AppHost host = await AppHost.StartAsync(builder);

        DnsDatagram? response = await host.QueryAsync("www.example.com", DnsResourceRecordType.A);

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.Refused, response.RCODE);
        Assert.Empty(response.Authority);
    }

    [Fact]
    public async Task IPv6TargetAnswersAaaa()
    {
        RulesetBuilder builder = Overriding();
        builder.Rules.Clear();
        builder.Rules.Add("WO1 com.example");

        using AppHost host = await AppHost.StartAsync(builder);

        DnsDatagram? response = await host.QueryAsync("example.com", DnsResourceRecordType.AAAA);

        Assert.NotNull(response);
        Assert.Single(response.Answer);
        Assert.Equal(120u, response.Answer[0].TTL);
        Assert.Equal(IPAddress.Parse("fd00::2"), ((DnsAAAARecordData)response.Answer[0].RDATA).Address);
    }

    [Fact]
    public async Task EngineDisabledInRulesetTurnsEverythingIntoPassthru()
    {
        using AppHost host = await AppHost.StartAsync(Overriding("""{"enabled":false,"defaultAction":"passthru"}"""));

        Assert.Null(await host.QueryAsync("www.example.com", DnsResourceRecordType.A));
    }

    [Fact]
    public async Task AppDisabledInConfigTurnsEverythingIntoPassthru()
    {
        using AppHost host = await AppHost.StartAsync(Overriding(), enabled: false);

        Assert.Null(await host.QueryAsync("www.example.com", DnsResourceRecordType.A));

        Assert.False(host.ReadRuntimeState().GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task DefaultActionOverrideCatchesEverythingElse()
    {
        using AppHost host = await AppHost.StartAsync(Overriding("""{"enabled":true,"defaultAction":"override","defaultTarget":"proxy"}"""));

        DnsDatagram? response = await host.QueryAsync("whatever.test", DnsResourceRecordType.A);

        Assert.NotNull(response);
        Assert.Single(response.Answer);
        Assert.Equal(IPAddress.Parse("10.8.0.2"), ((DnsARecordData)response.Answer[0].RDATA).Address);
    }

    [Fact]
    public async Task RoundRobinRotatesAddresses()
    {
        RulesetBuilder builder = Overriding();
        builder.Targets = """[{"name":"default","mode":"address","ipv4":["10.0.0.1","10.0.0.2","10.0.0.3"],"rotation":"round-robin"},{"name":"x","mode":"nodata"},{"name":"blackhole","mode":"nxdomain","ttl":300}]""";

        using AppHost host = await AppHost.StartAsync(builder);

        List<string> firstAddresses = new List<string>();

        for (int i = 0; i < 3; i++)
        {
            DnsDatagram? response = await host.QueryAsync("example.com", DnsResourceRecordType.A);

            Assert.NotNull(response);
            Assert.Equal(3, response.Answer.Count);
            firstAddresses.Add(((DnsARecordData)response.Answer[0].RDATA).Address.ToString());
        }

        Assert.Equal(3, firstAddresses.Distinct().Count());
    }

    [Fact]
    public async Task RuntimeStateReportsAppliedRevision()
    {
        RulesetBuilder builder = Overriding();
        builder.Revision = 4242;

        using AppHost host = await AppHost.StartAsync(builder);

        System.Text.Json.JsonElement state = host.ReadRuntimeState();

        Assert.Equal(4242L, state.GetProperty("appliedRevision").GetInt64());
        Assert.Equal(3, state.GetProperty("rulesLoaded").GetInt32());
        Assert.Equal(3, state.GetProperty("targetsLoaded").GetInt32());
        Assert.True(state.GetProperty("enabled").GetBoolean());
        Assert.Empty(state.GetProperty("errors").EnumerateArray());
        Assert.Equal("init", state.GetProperty("lastLoadTrigger").GetString());
    }

    [Fact]
    public async Task StatsAreCounted()
    {
        using AppHost host = await AppHost.StartAsync(Overriding());

        await host.QueryAsync("www.example.com", DnsResourceRecordType.A);       // override
        await host.QueryAsync("www.google.com", DnsResourceRecordType.A);        // passthru
        await host.QueryAsync("www.example.com", DnsResourceRecordType.HTTPS);   // nodata
        await host.QueryAsync("ads.blocked.com", DnsResourceRecordType.A);       // nxdomain

        host.App.WriteRuntimeState();

        System.Text.Json.JsonElement stats = host.ReadRuntimeState().GetProperty("stats");

        Assert.Equal(4L, stats.GetProperty("queriesTotal").GetInt64());
        Assert.Equal(1L, stats.GetProperty("overridden").GetInt64());
        Assert.Equal(1L, stats.GetProperty("passthru").GetInt64());
        Assert.Equal(1L, stats.GetProperty("nodata").GetInt64());
        Assert.Equal(1L, stats.GetProperty("nxdomain").GetInt64());
    }
}
