using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Response;

namespace Behavedr.Tests;

public class AttributionScoringTests
{
    [Fact]
    public void GroupByPid_IgnoresUnattributedSignals()
    {
        var grouped = SignalAttribution.GroupByPid(
        [
            new Signal("network_burst", 80, 0.9),
            new Signal("file_rename_storm", 90, 0.95),
        ]);
        Assert.Empty(grouped);
    }

    [Fact]
    public void GroupByPid_DoesNotUseCompositeRuleAsProcessName()
    {
        var grouped = SignalAttribution.GroupByPid(
        [
            new Signal("composite:injected_c2_beacon:pid:4242", 98, 0.98),
            new Signal("injection:powershell:pid:4242", 80, 0.9),
        ]);
        Assert.Single(grouped);
        Assert.Equal(4242, grouped[0].Pid);
        Assert.Equal("powershell", grouped[0].ProcessName);
        Assert.Equal(2, grouped[0].Signals.Count);
    }

    [Fact]
    public void ScoreAttributed_DoesNotInheritMachineWideScore()
    {
        var engine = new DetectionEngine();
        var noisy = new List<Signal>
        {
            new("canary_touch", 90, 1.0),
            new("exfil_burst", 80, 1.0),
            new("persistence_runkey", 70, 1.0),
        };
        var cycleEvt = DetectionEvent.Create("1", "behavedr-monitor", "periodic_scan", "test", false);
        var cycleScore = new ScoringEngine().CalculateScore(cycleEvt, noisy);
        Assert.True(cycleScore > 50);

        var pidSignals = new List<Signal> { new("unsigned_binary:pid:88888", 22, 0.5) };
        var targeted = engine.ScoreAttributed(
            DetectionEvent.Create("88888", "notepad", "behavioral_detection", "signal_attribution", false),
            pidSignals);

        Assert.True(targeted.Score < cycleScore);
        Assert.False(targeted.PresidentKill);
        Assert.True(targeted.Score < 40);
    }

    [Fact]
    public void ResponsePolicy_RejectsUnlimitedKillBudget()
    {
        Assert.False(new ResponsePolicy { MaxKillsPerMinute = 0 }.IsValid());
        Assert.True(ResponsePolicy.Default.IsValid());
    }

    [Fact]
    public void Isolation_RefusesNonIsoAndSystemPaths()
    {
        Assert.False(IsolationResponseEngine.IsSafeIsoPath("/etc/passwd"));
        Assert.False(IsolationResponseEngine.IsSafeIsoPath("/etc/shadow.iso"));
        Assert.False(IsolationResponseEngine.IsSafeIsoPath(@"C:\Windows\System32\foo.iso"));
        Assert.True(IsolationResponseEngine.IsSafeIsoPath(Path.Combine(Path.GetTempPath(), "payload.iso")));
    }
}
