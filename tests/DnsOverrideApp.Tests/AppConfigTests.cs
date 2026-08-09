/*
dnsApp.config: docs/ruleset-loading.md §1.
Битый конфиг обязан кидать исключение — сервер записывает файл только после
успешного InitializeAsync, поэтому так он не сохранится из админки.
*/

namespace DnsOverride.Tests;

public class AppConfigTests
{
    [Fact]
    public void DefaultJsonParsesIntoDefaults()
    {
        AppConfig config = AppConfig.Parse(AppConfig.DefaultJson);

        Assert.Equal("/etc/dns-override/ruleset.dat", config.RulesetPath);
        Assert.Equal("/etc/dns-override/runtime-state.json", config.RuntimeStatePath);
        Assert.True(config.Enabled);
        Assert.Equal(20, config.AppPreference);
        Assert.Equal(500, config.DebounceMs);
        Assert.Equal(60, config.PollIntervalSec);
    }

    [Fact]
    public void MissingFieldsFallBackToDefaults()
    {
        AppConfig config = AppConfig.Parse("{}");

        Assert.Equal(AppConfig.DefaultRulesetPath, config.RulesetPath);
        Assert.True(config.Enabled);
        Assert.Equal(AppConfig.DefaultDebounceMs, config.DebounceMs);
    }

    [Fact]
    public void CommentsAreAllowed()
    {
        AppConfig config = AppConfig.Parse("""
        {
          // путь к правилам
          "rulesetPath": "/tmp/ruleset.dat"
        }
        """);

        Assert.Equal("/tmp/ruleset.dat", config.RulesetPath);
    }

    [Theory]
    [InlineData(0, 50)]
    [InlineData(999999, 60000)]
    public void DebounceIsClamped(int input, int expected)
    {
        AppConfig config = AppConfig.Parse("{\"watch\":{\"debounceMs\":" + input + "}}");

        Assert.Equal(expected, config.DebounceMs);
    }

    [Theory]
    [InlineData(1, 5)]
    [InlineData(999999, 3600)]
    public void PollIntervalIsClamped(int input, int expected)
    {
        AppConfig config = AppConfig.Parse("{\"watch\":{\"pollIntervalSec\":" + input + "}}");

        Assert.Equal(expected, config.PollIntervalSec);
    }

    [Fact]
    public void EmptyRuntimeStatePathDisablesTheChannel()
    {
        // Пустая строка — не битый конфиг, а «не пиши runtime-state.json».
        // Приложение обязано после этого работать: файл нужен только боту.
        AppConfig config = AppConfig.Parse("""{"runtimeStatePath":""}""");

        Assert.Equal("", config.RuntimeStatePath);
        Assert.False(new RuntimeStateChannel(config.RuntimeStatePath, "", new TestLogSink()).Enabled);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("""{"rulesetPath":""}""")]
    [InlineData("""{"rulesetPath":123}""")]
    [InlineData("""{"enabled":"yes"}""")]
    [InlineData("""{"appPreference":300}""")]
    public void InvalidConfigThrows(string json)
    {
        Assert.ThrowsAny<Exception>(() => AppConfig.Parse(json));
    }
}
