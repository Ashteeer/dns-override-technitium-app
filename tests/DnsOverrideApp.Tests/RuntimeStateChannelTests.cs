/*
Обратный канал приложение → бот. Требование: недоступный runtime-state.json
не должен ни ронять приложение, ни засорять журнал сервера повтором одной и
той же ошибки раз в минуту.

Недоступность основного пути имитируется файлом на месте каталога: и Linux,
и Windows отвечают на такое исключением при создании каталога.
*/

using System.Text.Json;

namespace DnsOverride.Tests;

public class RuntimeStateChannelTests : IDisposable
{
    readonly string _directory;
    readonly TestLogSink _log = new TestLogSink();

    public RuntimeStateChannelTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), "dns-override-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, true);
        }
        catch (IOException)
        { }
    }

    static (RuntimeStateData, Stats) Sample()
    {
        DateTime now = DateTime.UtcNow;

        return (new RuntimeStateData() { StartedAtUtc = now, AppliedRevision = 4 }, new Stats(now));
    }

    [Fact]
    public void WritesToThePrimaryPath()
    {
        string path = Path.Combine(_directory, "state", "runtime-state.json");
        RuntimeStateChannel channel = new RuntimeStateChannel(path, "", _log);
        (RuntimeStateData data, Stats stats) = Sample();

        channel.Write(data, stats);

        Assert.True(File.Exists(path));
        Assert.Equal(path, channel.EffectivePath);
        Assert.Empty(_log.Messages);

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal(4L, document.RootElement.GetProperty("appliedRevision").GetInt64());
    }

    [Fact]
    public void EmptyPathWritesNothingAndSaysNothing()
    {
        RuntimeStateChannel channel = new RuntimeStateChannel("", Path.Combine(_directory, "fallback.json"), _log);
        (RuntimeStateData data, Stats stats) = Sample();

        channel.Write(data, stats);

        Assert.False(channel.Enabled);
        Assert.Empty(Directory.GetFiles(_directory));
        Assert.Empty(_log.Messages);
    }

    [Fact]
    public void UnwritablePrimaryFallsBackAndComplainsOnce()
    {
        string blocker = Path.Combine(_directory, "blocked");
        File.WriteAllText(blocker, "не каталог");

        string primary = Path.Combine(blocker, "runtime-state.json");
        string fallback = Path.Combine(_directory, "app", "runtime-state.json");

        RuntimeStateChannel channel = new RuntimeStateChannel(primary, fallback, _log);
        (RuntimeStateData data, Stats stats) = Sample();

        for (int i = 0; i < 5; i++)
            channel.Write(data, stats);

        Assert.True(File.Exists(fallback));
        Assert.Equal(fallback, channel.EffectivePath);

        // Пять попыток — одна жалоба на сбой и одно сообщение о переходе на запасной путь.
        Assert.Equal(1, _log.CountContaining("не удалось записать"));
        Assert.Equal(1, _log.CountContaining("временно пишется"));
    }

    [Fact]
    public void ReturnsToThePrimaryPathOnItsOwn()
    {
        string blocker = Path.Combine(_directory, "blocked");
        File.WriteAllText(blocker, "не каталог");

        string primary = Path.Combine(blocker, "runtime-state.json");
        string fallback = Path.Combine(_directory, "app", "runtime-state.json");

        RuntimeStateChannel channel = new RuntimeStateChannel(primary, fallback, _log);
        (RuntimeStateData data, Stats stats) = Sample();

        channel.Write(data, stats);
        Assert.Equal(fallback, channel.EffectivePath);

        // Оператор выдал доступ: перезапуск DNS-сервера для возврата не нужен.
        File.Delete(blocker);
        channel.Write(data, stats);

        Assert.Equal(primary, channel.EffectivePath);
        Assert.True(File.Exists(primary));
        Assert.Equal(1, _log.CountContaining("восстановлен"));
    }

    [Fact]
    public void WithoutFallbackItKeepsRetryingSilently()
    {
        string blocker = Path.Combine(_directory, "blocked");
        File.WriteAllText(blocker, "не каталог");

        string primary = Path.Combine(blocker, "runtime-state.json");
        RuntimeStateChannel channel = new RuntimeStateChannel(primary, "", _log);
        (RuntimeStateData data, Stats stats) = Sample();

        for (int i = 0; i < 3; i++)
            channel.Write(data, stats);

        Assert.Equal(1, _log.CountContaining("не удалось записать"));

        File.Delete(blocker);
        channel.Write(data, stats);

        Assert.True(File.Exists(primary));
        Assert.Equal(1, _log.CountContaining("заработала"));
    }
}
