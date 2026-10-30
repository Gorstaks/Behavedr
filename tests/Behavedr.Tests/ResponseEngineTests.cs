using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Response;

namespace Behavedr.Tests;

public class ResponseEngineTests
{
    [Fact]
    public async Task AlertOnlyMode_DoesNotExecuteActions()
    {
        var policy = new ResponsePolicy { Mode = ResponseMode.AlertOnly };
        var engine = new ResponseEngine(policy);
        engine.RegisterAction(new FakeAction("kill", true));

        var result = CreateHighScoreResult(99.0, presidentKill: true);
        var outcomes = await engine.RespondAsync(result);

        // Should log but not execute
        Assert.All(outcomes, o => Assert.Contains("Skipped", o.Message));
    }

    [Fact]
    public async Task ActiveMode_ExecutesOnHighScore()
    {
        var policy = new ResponsePolicy
        {
            Mode = ResponseMode.Active,
            ResponseThreshold = 70.0,
        };
        var engine = new ResponseEngine(policy);
        var action = new FakeAction("quarantine", true);
        engine.RegisterAction(action);

        var result = CreateHighScoreResult(80.0, presidentKill: false);
        var outcomes = await engine.RespondAsync(result);

        Assert.Single(outcomes);
        Assert.True(outcomes[0].Success);
        Assert.True(action.WasExecuted);
    }

    [Fact]
    public async Task ActiveMode_SkipsProcessKillBelowPresidentThreshold()
    {
        var policy = new ResponsePolicy
        {
            Mode = ResponseMode.Active,
            ResponseThreshold = 70.0,
        };
        var engine = new ResponseEngine(policy);
        engine.RegisterAction(new ProcessKillAction());

        var result = CreateHighScoreResult(80.0, presidentKill: false);
        var outcomes = await engine.RespondAsync(result);

        // ProcessKillAction should be skipped (not president-kill level)
        Assert.Single(outcomes);
        Assert.Contains("below president-kill", outcomes[0].Message);
    }

    [Fact]
    public async Task BelowAlertThreshold_NoActions()
    {
        var policy = new ResponsePolicy { Mode = ResponseMode.Active };
        var engine = new ResponseEngine(policy);
        engine.RegisterAction(new FakeAction("test", true));

        var result = CreateHighScoreResult(10.0, presidentKill: false);
        var outcomes = await engine.RespondAsync(result);

        Assert.Empty(outcomes);
    }

    [Fact]
    public async Task UnsupportedAction_IsSkipped()
    {
        var policy = new ResponsePolicy
        {
            Mode = ResponseMode.Active,
            ResponseThreshold = 70.0,
        };
        var engine = new ResponseEngine(policy);
        engine.RegisterAction(new FakeAction("unsupported", false));

        var result = CreateHighScoreResult(99.0, presidentKill: true);
        var outcomes = await engine.RespondAsync(result);

        Assert.Empty(outcomes); // Unsupported actions are silently skipped
    }

    [Fact]
    public void RegisterAction_NullThrows()
    {
        var engine = new ResponseEngine();
        Assert.Throws<ArgumentNullException>(() => engine.RegisterAction(null!));
    }

    [Fact]
    public void DefaultPolicy_IsAlertOnly()
    {
        var engine = new ResponseEngine();
        Assert.Equal(ResponseMode.AlertOnly, engine.Policy.Mode);
    }

    private static DetectionResult CreateHighScoreResult(
        double score, bool presidentKill)
    {
        var evt = new DetectionEvent(
            "1234", "malware.exe", "injection",
            DateTime.UtcNow, true, "test");

        return new DetectionResult(evt, score, presidentKill,
            [new Signal("test_signal", 90, 0.95)]);
    }

    private class FakeAction : IResponseAction
    {
        public FakeAction(string name, bool isSupported)
        {
            Name = name;
            IsSupported = isSupported;
        }

        public string Name { get; }
        public bool IsSupported { get; }
        public bool WasExecuted { get; private set; }

        public Task<ResponseOutcome> ExecuteAsync(
            DetectionResult result, CancellationToken ct = default)
        {
            WasExecuted = true;
            return Task.FromResult(
                ResponseOutcome.Ok(Name, $"Fake action executed"));
        }
    }
}
