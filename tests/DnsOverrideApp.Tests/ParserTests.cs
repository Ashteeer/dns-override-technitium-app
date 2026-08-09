/*
Отклонение битых ruleset (docs/ruleset-loading.md §4) и разбор заголовка.
Принцип: приложение не чинит файл — любая ошибка отвергает загрузку целиком.
*/

using System.Text;
using DnsOverride.Ruleset;

namespace DnsOverride.Tests;

public class ParserTests
{
    static RulesetFormatException Rejected(RulesetBuilder builder)
    {
        return Assert.Throws<RulesetFormatException>(() => RulesetParser.Parse(builder.ToBytes(), null));
    }

    [Fact]
    public void ValidFileLoads()
    {
        RulesetSnapshot snapshot = RulesetParser.Parse(RulesetBuilder.Sample().ToBytes(), null);

        Assert.Equal(3, snapshot.Count);
        Assert.Equal(1L, snapshot.Header.Revision);
        Assert.Equal(3, snapshot.Header.Targets.Length);
        Assert.Equal("default", snapshot.Header.Targets[0].Name);
    }

    [Fact]
    public void WrongSha256IsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Sha256Override = new string('0', 64);

        Assert.Contains("sha256", Rejected(builder).Message);
    }

    [Fact]
    public void WrongCountIsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.CountOverride = 99;

        Assert.Contains("count", Rejected(builder).Message);
    }

    [Fact]
    public void ForeignSignatureIsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Magic = "!DNSOVR2";

        Assert.Contains("сигнатура", Rejected(builder).Message);
    }

    [Fact]
    public void FutureHeaderVersionIsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Version = 2;

        Assert.Contains("version", Rejected(builder).Message);
    }

    [Fact]
    public void TargetIndexOutOfRangeIsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Rules.Add("WO7 com.zzz");

        Assert.Contains("вне диапазона", Rejected(builder).Message);
    }

    [Fact]
    public void UnsortedBodyIsRejected()
    {
        RulesetBuilder builder = new RulesetBuilder()
        {
            Rules = { "WO0 org.example", "WO0 com.google" }
        };

        Assert.Contains("сортировки", Rejected(builder).Message);
    }

    [Fact]
    public void DuplicateRuleIsRejected()
    {
        RulesetBuilder builder = new RulesetBuilder()
        {
            Rules = { "WO0 com.google", "WO0 com.google" }
        };

        Assert.Contains("дубль", Rejected(builder).Message);
    }

    [Fact]
    public void WildcardBeforeApexIsRejected()
    {
        RulesetBuilder builder = new RulesetBuilder()
        {
            Rules = { "WO0 com.google", "AO0 com.google" }
        };

        Assert.Contains("должна идти перед", Rejected(builder).Message);
    }

    [Theory]
    [InlineData("XO0 com.google")]
    [InlineData("WX0 com.google")]
    [InlineData("WOx com.google")]
    [InlineData("WO00 com.google")]
    [InlineData("WO0 COM.GOOGLE")]
    [InlineData("WO0 com..google")]
    [InlineData("WO0 com.google.")]
    [InlineData("WO0 com.-google")]
    [InlineData("WO0 com.google-")]
    [InlineData("WO0")]
    public void MalformedRuleLineIsRejected(string rule)
    {
        RulesetBuilder builder = new RulesetBuilder() { Rules = { rule } };

        Rejected(builder);
    }

    [Fact]
    public void PassthruRuleWithNonZeroTargetIndexIsRejected()
    {
        RulesetBuilder builder = new RulesetBuilder() { Rules = { "WP1 com.google" } };

        Assert.Contains("action=P", Rejected(builder).Message);
    }

    [Fact]
    public void BodyWithoutTrailingNewlineIsRejected()
    {
        byte[] valid = RulesetBuilder.Sample().ToBytes();
        byte[] truncated = valid[..^1];

        // Обрезанный последний байт ломает и sha256 — файл отвергается в любом случае.
        Assert.Throws<RulesetFormatException>(() => RulesetParser.Parse(truncated, null));
    }

    [Fact]
    public void AddressTargetWithoutAddressesIsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Targets = """[{"name":"broken","mode":"address","ipv4":[],"ipv6":[]}]""";
        builder.Rules.Clear();

        Assert.Contains("без адресов", Rejected(builder).Message);
    }

    [Fact]
    public void QtypePolicyWithoutStarIsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.QtypePolicy = """{"A":"target"}""";

        Assert.Contains("'*'", Rejected(builder).Message);
    }

    [Fact]
    public void DefaultActionOverrideRequiresKnownTarget()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Engine = """{"enabled":true,"defaultAction":"override","defaultTarget":"missing"}""";

        Assert.Contains("defaultTarget", Rejected(builder).Message);
    }

    [Fact]
    public void DefaultTargetIsResolvedToIndex()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Engine = """{"enabled":true,"defaultAction":"override","defaultTarget":"proxy"}""";

        RulesetSnapshot snapshot = RulesetParser.Parse(builder.ToBytes(), null);

        Assert.Equal(1, snapshot.Header.DefaultTargetIndex);
    }

    [Fact]
    public void UnknownHeaderFieldsAreIgnored()
    {
        // §6 ruleset-format.md: бот новее приложения должен уметь добавлять поля.
        byte[] bytes = RulesetBuilder.Sample().ToBytes();
        string text = Encoding.UTF8.GetString(bytes);
        text = text.Replace("\"version\":1", "\"version\":1,\"somethingNew\":{\"a\":1}");

        RulesetSnapshot snapshot = RulesetParser.Parse(Encoding.UTF8.GetBytes(text), null);

        Assert.Equal(3, snapshot.Count);
    }

    [Fact]
    public void LegacyCacheFlushFieldsAreIgnored()
    {
        // flushCacheOnReload / flushScope убраны из формата: сброс кэша делает
        // оператор кнопкой в боте. Старые файлы обязаны грузиться как обычно.
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.Engine = """{"enabled":true,"defaultAction":"passthru","flushCacheOnReload":true,"flushScope":"changed-domains"}""";

        RulesetSnapshot snapshot = RulesetParser.Parse(builder.ToBytes(), null);

        Assert.Equal(3, snapshot.Count);
        Assert.True(snapshot.Header.Engine.Enabled);
    }

    [Fact]
    public void UnknownQtypeNameIsIgnoredWithWarning()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.QtypePolicy = """{"A":"target","NOSUCHTYPE":"nodata","*":"passthru"}""";

        RulesetSnapshot snapshot = RulesetParser.Parse(builder.ToBytes(), null);

        Assert.Single(snapshot.Header.Warnings);
        Assert.Contains("NOSUCHTYPE", snapshot.Header.Warnings[0]);
    }

    [Fact]
    public void UnknownQtypeActionIsRejected()
    {
        RulesetBuilder builder = RulesetBuilder.Sample();
        builder.QtypePolicy = """{"A":"explode","*":"passthru"}""";

        Rejected(builder);
    }

    [Fact]
    public void RepositoryExampleFileLoads()
    {
        // config-examples/ruleset.dat — общий с ботом пример: приложение обязано его грузить.
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../config-examples/ruleset.dat"));

        Assert.True(File.Exists(path), "не найден пример " + path);

        RulesetSnapshot snapshot = RulesetParser.Parse(File.ReadAllBytes(path), null);

        Assert.Equal(10, snapshot.Count);
        Assert.Equal(128L, snapshot.Header.Revision);

        // Ожидаемые значения сняты с эталонной реализации поиска:
        // python3 tools/check-ruleset.py config-examples/ruleset.dat --query ...
        AssertLookup(snapshot, "test.google.com", RuleAction.Override, "default", "test.google.com");
        AssertLookup(snapshot, "www.google.com", RuleAction.Passthru, null, "google.com");
        AssertLookup(snapshot, "example.org", RuleAction.Override, "proxy-nl", "example.org");
        AssertLookup(snapshot, "static.example.co.uk", RuleAction.Override, "default", "static.example.co.uk");
        AssertLookup(snapshot, "ads.example.net", RuleAction.Override, "blackhole", "ads.example.net");

        Assert.False(snapshot.Match("www.example.org").Found);
        Assert.False(snapshot.Match("notinlist.com").Found);
    }

    static void AssertLookup(RulesetSnapshot snapshot, string qname, RuleAction action, string? targetName, string ruleDomain)
    {
        RuleMatch match = snapshot.Match(qname);

        Assert.True(match.Found, qname + ": правило не найдено");
        Assert.Equal(action, match.Action);
        Assert.Equal(ruleDomain, snapshot.GetRuleDomain(match.LineIndex));

        if (targetName is not null)
            Assert.Equal(targetName, snapshot.Header.Targets[match.TargetIndex].Name);
    }
}
