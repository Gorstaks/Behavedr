using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Response;

namespace Behavedr.Tests;

/// <summary>
/// Golden / regression checks so high-privilege response paths do not fire on
/// obviously legitimate system processes (false-positive guard suite).
/// </summary>
public class FalsePositiveGuardTests
{
    [Theory]
    [InlineData("csrss")]
    [InlineData("lsass")]
    [InlineData("services")]
    [InlineData("systemd")]
    [InlineData("launchd")]
    [InlineData("behavedr")]
    public async Task ProcessKill_RefusesCriticalSystemPids(string name)
    {
        // PID 1 (Linux/macOS init) / low Windows PIDs must never be killable by name spoof alone.
        // Spoofed "lsass" under Temp is intentionally NOT protected (see ResponseSafetyTests).
        var kill = new ProcessKillAction();
        var result = new DetectionResult(
            DetectionEvent.Create("1", name, "test", "fp-suite", false),
            99, true,
            new List<Signal> { new("synthetic", 99, 1.0) });

        var outcome = await kill.ExecuteAsync(result);
        Assert.Contains("Safety", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessKill_DoesNotImmunizeSpoofedProtectedName_WithBogusPid()
    {
        // High non-existent PID + protected name: no kill immunity from name alone
        var kill = new ProcessKillAction();
        var result = new DetectionResult(
            DetectionEvent.Create("999991", "lsass", "test", "fp-suite", false),
            99, true,
            new List<Signal> { new("synthetic", 99, 1.0) });

        var outcome = await kill.ExecuteAsync(result);
        // Already exited / cannot kill - must NOT claim protected-process immunity
        Assert.DoesNotContain("protected system process", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessKill_RefusesSelf()
    {
        var kill = new ProcessKillAction();
        var result = new DetectionResult(
            DetectionEvent.Create(Environment.ProcessId.ToString(), "testhost", "test", "fp-suite", false),
            99, true,
            new List<Signal>());

        var outcome = await kill.ExecuteAsync(result);
        Assert.Contains("own process", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AlertOnly_NeverKills()
    {
        var engine = new ResponseEngine(new ResponsePolicy
        {
            Mode = ResponseMode.AlertOnly,
            ResponseThreshold = 10,
        });
        engine.RegisterAction(new ProcessKillAction());

        var result = new DetectionResult(
            DetectionEvent.Create("99999", "not-a-real-process-xyz", "t", "fp", true),
            99, true,
            new List<Signal> { new("x", 99, 1) });

        var outcomes = await engine.RespondAsync(result);
        Assert.All(outcomes, o =>
            Assert.Contains("Alert-only", o.Message, StringComparison.OrdinalIgnoreCase));
    }

}
