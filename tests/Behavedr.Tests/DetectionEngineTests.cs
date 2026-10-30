using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;

namespace Behavedr.Tests;

public class DetectionEngineTests
{
    [Fact]
    public void RegisterMonitor_AddsToList()
    {
        var engine = new DetectionEngine();
        var monitor = new FakeMonitor("Test", true, [new Signal("test", 10, 0.5)]);

        engine.RegisterMonitor(monitor);

        Assert.Single(engine.RegisteredMonitors);
        Assert.Equal("Test", engine.RegisteredMonitors[0].PlatformName);
    }

    [Fact]
    public void RegisterMonitor_NullMonitor_Throws()
    {
        var engine = new DetectionEngine();
        Assert.Throws<ArgumentNullException>(() => engine.RegisterMonitor(null!));
    }

    [Fact]
    public async Task ProcessEventAsync_CollectsSignalsFromMonitors()
    {
        var engine = new DetectionEngine();
        engine.RegisterMonitor(new FakeMonitor("A", true, [new Signal("sig_a", 20, 0.9)]));
        engine.RegisterMonitor(new FakeMonitor("B", true, [new Signal("sig_b", 30, 0.7)]));

        var evt = DetectionEvent.Create("1", "proc", "behavior", "test");
        var result = await engine.ProcessEventAsync(evt);

        Assert.Equal(2, result.Signals.Count);
        Assert.True(result.Score > 0);
    }

    [Fact]
    public async Task ProcessEventAsync_SkipsUnsupportedMonitors()
    {
        var engine = new DetectionEngine();
        engine.RegisterMonitor(new FakeMonitor("Supported", true, [new Signal("sig", 50, 1.0)]));
        engine.RegisterMonitor(new FakeMonitor("Unsupported", false, [new Signal("hidden", 99, 1.0)]));

        var evt = DetectionEvent.Create("1", "proc", "behavior", "test");
        var result = await engine.ProcessEventAsync(evt);

        Assert.Single(result.Signals);
        Assert.Equal("sig", result.Signals[0].Type);
    }

    [Fact]
    public async Task ProcessEventAsync_ContinuesOnMonitorFailure()
    {
        var engine = new DetectionEngine();
        engine.RegisterMonitor(new FakeMonitor("Failing", true, [], shouldThrow: true));
        engine.RegisterMonitor(new FakeMonitor("Working", true, [new Signal("ok", 10, 0.5)]));

        var evt = DetectionEvent.Create("1", "proc", "behavior", "test");
        var result = await engine.ProcessEventAsync(evt);

        // Should still get signals from the working monitor
        Assert.Single(result.Signals);
        Assert.Equal("ok", result.Signals[0].Type);
    }

    [Fact]
    public async Task ProcessEventAsync_NullEvent_Throws()
    {
        var engine = new DetectionEngine();
        await Assert.ThrowsAsync<ArgumentNullException>(() => engine.ProcessEventAsync(null!));
    }

    [Fact]
    public async Task ProcessEventAsync_PresidentKill_TriggeredCorrectly()
    {
        var config = new ScoringConfig
        {
            PresidentKillThreshold = 10.0,
            HighScoreAlertThreshold = 5.0,
        };
        var scoring = new ScoringEngine(config);
        var engine = new DetectionEngine(scoring);
        engine.RegisterMonitor(new FakeMonitor("High", true, [new Signal("critical", 100, 1.0)]));

        var evt = new DetectionEvent("1", "malware.exe", "injection", DateTime.UtcNow, true, "test");
        var result = await engine.ProcessEventAsync(evt);

        Assert.NotEmpty(result.Signals);
        Assert.True(result.Score > 10.0, $"score was {result.Score:F1}");
        Assert.True(result.PresidentKill);
    }

    [Fact]
    public async Task ProcessEvent_Sync_Works()
    {
        var engine = new DetectionEngine();
        engine.RegisterMonitor(new FakeMonitor("Sync", true, [new Signal("s", 10, 0.5)]));

        var evt = DetectionEvent.Create("1", "proc", "behavior", "test");
        var result = await engine.ProcessEventAsync(evt);

        Assert.Single(result.Signals);
    }

    private class FakeMonitor : IPlatformMonitor
    {
        private readonly IEnumerable<Signal> _signals;
        private readonly bool _shouldThrow;

        public FakeMonitor(string name, bool isSupported, IEnumerable<Signal> signals, bool shouldThrow = false)
        {
            PlatformName = name;
            IsSupported = isSupported;
            _signals = signals;
            _shouldThrow = shouldThrow;
        }

        public string PlatformName { get; }
        public bool IsSupported { get; }

        public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
        {
            if (_shouldThrow)
                throw new InvalidOperationException("Simulated monitor failure");
            return Task.FromResult(_signals);
        }
    }
}
