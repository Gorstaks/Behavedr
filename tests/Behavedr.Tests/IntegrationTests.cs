using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Behavedr.Core.Telemetry;

namespace Behavedr.Tests;

/// <summary>
/// Integration tests that exercise the full detection pipeline.
/// </summary>
public class IntegrationTests
{
    [Fact]
    public async Task FullPipeline_MonitorToDetectionToResponse()
    {
        // Arrange: create complete pipeline
        var scoringConfig = new ScoringConfig
        {
            PresidentKillThreshold = 80.0,
            UserTargetedMultiplier = 2.0,
            HighScoreAlertThreshold = 40.0,
        };
        var scoring = new ScoringEngine(scoringConfig);
        var engine = new DetectionEngine(scoring);

        var responsePolicy = new ResponsePolicy
        {
            Mode = ResponseMode.Active,
            ResponseThreshold = 60.0,
            AlertThreshold = 30.0,
        };
        var responseEngine = new ResponseEngine(responsePolicy);
        var fakeAction = new TrackingAction();
        responseEngine.RegisterAction(fakeAction);

        // Register a test monitor that returns high-confidence signals
        engine.RegisterMonitor(new HighThreatMonitor());

        // Act: process a user-targeted event
        var evt = new DetectionEvent(
            "999", "evil.exe", "credential_theft",
            DateTime.UtcNow, true, "integration_test");

        var result = await engine.ProcessEventAsync(evt);
        var responses = await responseEngine.RespondAsync(result);

        // Assert: full pipeline executed
        Assert.True(result.Score > 0);
        Assert.True(result.Signals.Count > 0);
        Assert.True(result.PresidentKill); // High score + user targeted
        Assert.NotEmpty(responses);
        Assert.True(fakeAction.ExecuteCount > 0);
    }

    [Fact]
    public async Task FullPipeline_LowScore_NoResponse()
    {
        var scoring = new ScoringEngine();
        var engine = new DetectionEngine(scoring);

        var responsePolicy = new ResponsePolicy
        {
            Mode = ResponseMode.Active,
            ResponseThreshold = 75.0,
        };
        var responseEngine = new ResponseEngine(responsePolicy);
        responseEngine.RegisterAction(new TrackingAction());

        engine.RegisterMonitor(new LowThreatMonitor());

        var evt = DetectionEvent.Create("1", "notepad.exe", "file_open", "test");
        var result = await engine.ProcessEventAsync(evt);
        var responses = await responseEngine.RespondAsync(result);

        // Low threat shouldn't trigger responses
        Assert.True(result.Score < 75.0);
        Assert.Empty(responses);
    }

    [Fact]
    public async Task FullPipeline_AlertOnlyMode_NoActions()
    {
        var scoring = new ScoringEngine();
        var engine = new DetectionEngine(scoring);

        var responsePolicy = new ResponsePolicy
        {
            Mode = ResponseMode.AlertOnly,
            ResponseThreshold = 10.0,
        };
        var responseEngine = new ResponseEngine(responsePolicy);
        var tracker = new TrackingAction();
        responseEngine.RegisterAction(tracker);

        engine.RegisterMonitor(new HighThreatMonitor());

        var evt = new DetectionEvent(
            "1", "malware.exe", "injection",
            DateTime.UtcNow, true, "test");

        var result = await engine.ProcessEventAsync(evt);
        var responses = await responseEngine.RespondAsync(result);

        Assert.Equal(0, tracker.ExecuteCount);
    }

    [Fact]
    public void MetricsIntegration_RecordsCorrectly()
    {
        var metrics = new BehavedrMetrics();

        // Ensure metrics don't throw
        metrics.RecordCycleCompleted();
        metrics.RecordSignalsCollected(5);
        metrics.RecordDetectionTriggered();
        metrics.RecordPresidentKill();
        metrics.RecordResponseExecuted(true);
        metrics.RecordResponseExecuted(false);
        metrics.RecordScore(75.5);
        metrics.RecordCycleDuration(123.4);
        metrics.RecordMonitorRegistered();
        metrics.RecordReportBuffered();
        metrics.RecordReportSent();
    }

    [Fact]
    public async Task MultipleMonitors_AllContribute()
    {
        var engine = new DetectionEngine();
        engine.RegisterMonitor(new HighThreatMonitor());
        engine.RegisterMonitor(new LowThreatMonitor());

        var evt = DetectionEvent.Create("1", "test", "scan", "test");
        var result = await engine.ProcessEventAsync(evt);

        // Both monitors should contribute signals
        Assert.True(result.Signals.Count >= 2);
    }

    [Fact]
    public async Task PlatformMonitors_CurrentPlatform_Works()
    {
        // Run the actual platform monitors for the current OS (bounded - never hang CI).
        var engine = AgentBootstrap.CreateEngine();
        Assert.True(engine.RegisteredMonitors.Count >= 1);

        var evt = DetectionEvent.Create(
            Environment.ProcessId.ToString(),
            "behavedr-test", "integration", "test");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var result = await engine.ProcessEventAsync(evt, cts.Token).WaitAsync(cts.Token);

        // Should get at least some signals from the real monitor
        Assert.NotNull(result);
        Assert.True(result.Score >= 0);
    }

    // --- Test monitors ---

    private class HighThreatMonitor : IPlatformMonitor
    {
        public string PlatformName => "TestHigh";
        public bool IsSupported => true;

        public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
        {
            IEnumerable<Signal> signals =
            [
                new Signal("credential_theft", 80, 0.9),
                new Signal("process_injection", 70, 0.85),
            ];
            return Task.FromResult(signals);
        }
    }

    private class LowThreatMonitor : IPlatformMonitor
    {
        public string PlatformName => "TestLow";
        public bool IsSupported => true;

        public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
        {
            IEnumerable<Signal> signals =
            [
                new Signal("normal_file_access", 5, 0.3),
            ];
            return Task.FromResult(signals);
        }
    }

    private class TrackingAction : IResponseAction
    {
        public string Name => "Tracker";
        public bool IsSupported => true;
        public int ExecuteCount { get; private set; }

        public Task<ResponseOutcome> ExecuteAsync(
            DetectionResult result, CancellationToken ct = default)
        {
            ExecuteCount++;
            return Task.FromResult(
                ResponseOutcome.Ok(Name, "Tracked"));
        }
    }
}
