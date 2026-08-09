/*
Горячая перезагрузка: docs/ruleset-loading.md §2–§4.
Watcher на каталоге + дебаунс + страховочный опрос; ошибка загрузки не должна
подменять уже работающий снапшот.
*/

using System.Diagnostics;
using System.Text.Json;
using DnsOverride.Ruleset;

namespace DnsOverride.Tests;

public class LoaderTests : IDisposable
{
    readonly string _directory;
    readonly string _rulesetPath;
    readonly string _statePath;
    readonly TestLogSink _log = new TestLogSink();
    readonly List<RulesetLoader> _loaders = new List<RulesetLoader>();

    public LoaderTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), "dns-override-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);

        _rulesetPath = Path.Combine(_directory, "ruleset.dat");
        _statePath = Path.Combine(_directory, "runtime-state.json");
    }

    public void Dispose()
    {
        foreach (RulesetLoader loader in _loaders)
            loader.Dispose();

        try
        {
            Directory.Delete(_directory, true);
        }
        catch (IOException)
        { }
    }

    RulesetLoader CreateLoader(int debounceMs = 300, int pollIntervalSec = 3600)
    {
        string configJson = $$"""
        {
          "rulesetPath": {{JsonSerializer.Serialize(_rulesetPath)}},
          "runtimeStatePath": {{JsonSerializer.Serialize(_statePath)}},
          "enabled": true,
          "watch": { "debounceMs": {{debounceMs}}, "pollIntervalSec": {{pollIntervalSec}} }
        }
        """;

        AppConfig config = AppConfig.Parse(configJson);
        RuntimeStateData state = new RuntimeStateData() { StartedAtUtc = DateTime.UtcNow };
        RulesetLoader loader = new RulesetLoader(config, _log, new Stats(DateTime.UtcNow), state);

        _loaders.Add(loader);

        return loader;
    }

    static async Task<bool> WaitUntilAsync(Func<bool> condition, int timeoutMs = 5000)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

        while (stopwatch.ElapsedMilliseconds < timeoutMs)
        {
            if (condition())
                return true;

            await Task.Delay(25);
        }

        return condition();
    }

    [Fact]
    public async Task MissingFileAtStartupLeavesEverythingInPassthru()
    {
        RulesetLoader loader = CreateLoader();

        await loader.StartAsync();

        Assert.Null(loader.Snapshot);

        JsonElement errors = ReadState().GetProperty("errors");
        Assert.Single(errors.EnumerateArray());
        Assert.Contains("не найден", errors[0].GetString()!);
    }

    [Fact]
    public async Task WatcherReloadsAfterRename()
    {
        new RulesetBuilder() { Revision = 1, Rules = { "WO0 com.example" } }.WriteTo(_rulesetPath);

        RulesetLoader loader = CreateLoader(debounceMs: 100);
        await loader.StartAsync();

        Assert.Equal(1L, loader.Snapshot!.Header.Revision);

        new RulesetBuilder() { Revision = 2, Rules = { "WO0 com.example", "WO0 org.example" } }.WriteTo(_rulesetPath);

        Assert.True(await WaitUntilAsync(() => loader.Snapshot!.Header.Revision == 2), "перезагрузка по событию watcher'а не произошла");
        Assert.Equal(2, loader.Snapshot!.Count);
    }

    [Fact]
    public async Task BurstOfEventsCausesExactlyOneReload()
    {
        new RulesetBuilder() { Revision = 1, Rules = { "WO0 com.example" } }.WriteTo(_rulesetPath);

        RulesetLoader loader = CreateLoader(debounceMs: 500);
        await loader.StartAsync();

        int loadsAfterStart = _log.CountContaining("ruleset загружен");

        for (int i = 2; i <= 11; i++)
            new RulesetBuilder() { Revision = i, Rules = { "WO0 com.example" } }.WriteTo(_rulesetPath);

        Assert.True(await WaitUntilAsync(() => loader.Snapshot!.Header.Revision == 11), "финальная ревизия не применилась");

        await Task.Delay(700);                      // дать возможность лишним перезагрузкам проявиться

        Assert.Equal(loadsAfterStart + 1, _log.CountContaining("ruleset загружен"));
    }

    [Fact]
    public async Task PollReloadsWhenWatcherIsNotAvailable()
    {
        // Каталога нет на момент старта — watcher не создаётся, остаётся только опрос.
        string missingDirectory = Path.Combine(_directory, "later");
        string rulesetPath = Path.Combine(missingDirectory, "ruleset.dat");

        AppConfig config = AppConfig.Parse($$"""
        {
          "rulesetPath": {{JsonSerializer.Serialize(rulesetPath)}},
          "runtimeStatePath": {{JsonSerializer.Serialize(_statePath)}},
          "watch": { "debounceMs": 100, "pollIntervalSec": 5 }
        }
        """);

        RulesetLoader loader = new RulesetLoader(config, _log, new Stats(DateTime.UtcNow), new RuntimeStateData() { StartedAtUtc = DateTime.UtcNow });
        _loaders.Add(loader);

        await loader.StartAsync();

        Assert.Null(loader.Snapshot);
        Assert.True(_log.CountContaining("страховочный опрос") > 0);

        Directory.CreateDirectory(missingDirectory);
        new RulesetBuilder() { Revision = 7, Rules = { "WO0 com.example" } }.WriteTo(rulesetPath);

        Assert.True(await WaitUntilAsync(() => loader.Snapshot is not null, 15000), "страховочный опрос не подхватил появившийся файл");
        Assert.Equal(7L, loader.Snapshot!.Header.Revision);
    }

    [Fact]
    public async Task BrokenFileKeepsPreviousSnapshot()
    {
        new RulesetBuilder() { Revision = 1, Rules = { "WO0 com.example" } }.WriteTo(_rulesetPath);

        RulesetLoader loader = CreateLoader(debounceMs: 100);
        await loader.StartAsync();

        RulesetBuilder broken = new RulesetBuilder() { Revision = 2, Rules = { "WO0 com.example" } };
        broken.Sha256Override = new string('a', 64);
        broken.WriteTo(_rulesetPath);

        Assert.True(await WaitUntilAsync(() => ReadState().GetProperty("errors").GetArrayLength() > 0), "ошибка не попала в runtime-state");

        Assert.Equal(1L, loader.Snapshot!.Header.Revision);
        Assert.Equal(1L, ReadState().GetProperty("appliedRevision").GetInt64());
    }

    [Fact]
    public async Task MissingFileAfterSuccessfulLoadKeepsSnapshot()
    {
        new RulesetBuilder() { Revision = 3, Rules = { "WO0 com.example" } }.WriteTo(_rulesetPath);

        RulesetLoader loader = CreateLoader();
        await loader.StartAsync();

        File.Delete(_rulesetPath);
        await loader.LoadAsync("test");

        Assert.NotNull(loader.Snapshot);
        Assert.Equal(3L, loader.Snapshot!.Header.Revision);
        Assert.Empty(ReadState().GetProperty("errors").EnumerateArray());
    }

    [Fact]
    public async Task ConcurrentRenamesNeverYieldHalfLoadedSnapshot()
    {
        new RulesetBuilder() { Revision = 1, Rules = { "WO0 com.example" } }.WriteTo(_rulesetPath);

        RulesetLoader loader = CreateLoader(debounceMs: 20);
        await loader.StartAsync();

        using CancellationTokenSource cancellation = new CancellationTokenSource();

        Task readers = Task.Run(() =>
        {
            while (!cancellation.IsCancellationRequested)
            {
                RulesetSnapshot? snapshot = loader.Snapshot;

                if (snapshot is null)
                    continue;

                // Снапшот обязан быть целым: количество строк совпадает с заголовком,
                // а известное правило находится поиском.
                Assert.Equal(snapshot.Header.Count, snapshot.Count);
                Assert.True(snapshot.Match("www.example.com").Found);
            }
        });

        for (int revision = 2; revision <= 40; revision++)
        {
            new RulesetBuilder()
            {
                Revision = revision,
                Rules = { "WO0 com.example", "WO0 com.example." + revision }
            }.WriteTo(_rulesetPath);

            await Task.Delay(5);
        }

        await Task.Delay(300);
        cancellation.Cancel();
        await readers;

        Assert.DoesNotContain(_log.Messages, m => m.Contains("ошибка загрузки", StringComparison.Ordinal));
    }

    JsonElement ReadState()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(_statePath));

        return document.RootElement.Clone();
    }
}
