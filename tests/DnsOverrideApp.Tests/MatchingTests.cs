/*
Поиск правила по QNAME: docs/rule-matching.md §2.
Таблица §2.1 перенесена в тесты один в один — это контракт поведения.
*/

using DnsOverride.Ruleset;

namespace DnsOverride.Tests;

public class MatchingTests
{
    static RulesetSnapshot Load(RulesetBuilder builder)
    {
        return RulesetParser.Parse(builder.ToBytes(), null);
    }

    [Theory]
    // запрос                  найдено  действие     apex
    [InlineData("google.com", true, "passthru", false)]
    [InlineData("www.google.com", true, "passthru", false)]
    [InlineData("test.google.com", true, "override", false)]
    [InlineData("a.b.test.google.com", true, "override", false)]
    [InlineData("example.org", true, "override", true)]
    [InlineData("www.example.org", false, "", false)]
    [InlineData("evilgoogle.com", false, "", false)]
    [InlineData("google.com.ru", false, "", false)]
    public void RuleMatchingTable(string qname, bool found, string action, bool isApex)
    {
        RulesetSnapshot snapshot = Load(RulesetBuilder.Sample());

        RuleMatch match = snapshot.Match(qname);

        Assert.Equal(found, match.Found);

        if (!found)
            return;

        Assert.Equal(action, match.Action == RuleAction.Override ? "override" : "passthru");
        Assert.Equal(isApex, match.IsApex);
    }

    [Fact]
    public void LongestSuffixWins()
    {
        RulesetSnapshot snapshot = Load(RulesetBuilder.Sample());

        RuleMatch match = snapshot.Match("test.google.com");

        Assert.True(match.Found);
        Assert.Equal("test.google.com", snapshot.GetRuleDomain(match.LineIndex));
    }

    [Fact]
    public void ApexBeatsWildcardOnExactMatch()
    {
        // Случай из docs/rule-matching.md §4.4: список дал wildcard, пользователь — apex.
        RulesetSnapshot snapshot = Load(new RulesetBuilder()
        {
            Rules = { "AP0 com.google", "WO0 com.google" }
        });

        RuleMatch exact = snapshot.Match("google.com");
        Assert.True(exact.Found);
        Assert.True(exact.IsApex);
        Assert.Equal(RuleAction.Passthru, exact.Action);

        RuleMatch subdomain = snapshot.Match("www.google.com");
        Assert.True(subdomain.Found);
        Assert.False(subdomain.IsApex);
        Assert.Equal(RuleAction.Override, subdomain.Action);
    }

    [Fact]
    public void ApexDoesNotCoverSubdomainsAndSearchContinues()
    {
        // На com.google.test лежит только apex — для поддомена он не подходит,
        // цикл обязан дойти до более короткого суффикса com.google.
        RulesetSnapshot snapshot = Load(new RulesetBuilder()
        {
            Rules = { "WO1 com.google", "AP0 com.google.test" }
        });

        RuleMatch match = snapshot.Match("a.test.google.com");

        Assert.True(match.Found);
        Assert.Equal("google.com", snapshot.GetRuleDomain(match.LineIndex));
        Assert.Equal(RuleAction.Override, match.Action);
        Assert.Equal(1, match.TargetIndex);
    }

    [Theory]
    [InlineData("TEST.Google.COM")]
    [InlineData("test.google.com.")]
    [InlineData("TeSt.GoOgLe.CoM.")]
    public void QnameIsCaseInsensitiveAndTrailingDotIsIgnored(string qname)
    {
        RulesetSnapshot snapshot = Load(RulesetBuilder.Sample());

        RuleMatch match = snapshot.Match(qname);

        Assert.True(match.Found);
        Assert.Equal("test.google.com", snapshot.GetRuleDomain(match.LineIndex));
    }

    [Fact]
    public void UnderscoreLabelsFallBackToParentRule()
    {
        // _dmarc не может встретиться в правиле (бот такие домены нормализует),
        // но запрос обязан попасть под wildcard родителя.
        RulesetSnapshot snapshot = Load(new RulesetBuilder()
        {
            Rules = { "WO0 com.example" }
        });

        Assert.True(snapshot.Match("_dmarc.example.com").Found);
    }

    [Fact]
    public void RootAndEmptyNameNeverMatch()
    {
        RulesetSnapshot snapshot = Load(RulesetBuilder.Sample());

        Assert.False(snapshot.Match(string.Empty).Found);
        Assert.False(snapshot.Match(".").Found);
    }

    [Fact]
    public void EmptyRulesetLoadsAndMatchesNothing()
    {
        RulesetSnapshot snapshot = Load(new RulesetBuilder());

        Assert.Equal(0, snapshot.Count);
        Assert.False(snapshot.Match("google.com").Found);
        Assert.Equal(RuleAction.Passthru, snapshot.Header.Engine.DefaultAction);
    }

    [Fact]
    public void TargetIndexIsReadFromRule()
    {
        RulesetSnapshot snapshot = Load(new RulesetBuilder()
        {
            Rules = { "WO2 com.blocked", "WO10 net.example" },
            Targets = BuildTargets(11)
        });

        Assert.Equal(2, snapshot.Match("blocked.com").TargetIndex);
        Assert.Equal(10, snapshot.Match("example.net").TargetIndex);
    }

    [Fact]
    public void BinarySearchFindsEveryRuleInLargeRuleset()
    {
        List<string> rules = new List<string>();

        for (int i = 0; i < 5000; i++)
            rules.Add("WO0 com.d" + i.ToString("00000"));

        rules.Sort(StringComparer.Ordinal);

        RulesetSnapshot snapshot = Load(new RulesetBuilder() { Rules = rules });

        for (int i = 0; i < 5000; i++)
            Assert.True(snapshot.Match("d" + i.ToString("00000") + ".com").Found, "не найден d" + i);

        Assert.False(snapshot.Match("d99999.com").Found);
    }

    static string BuildTargets(int count)
    {
        List<string> targets = new List<string>();

        for (int i = 0; i < count; i++)
            targets.Add($$"""{"name":"t{{i}}","mode":"address","ipv4":["10.0.0.{{i + 1}}"]}""");

        return "[" + string.Join(',', targets) + "]";
    }
}
