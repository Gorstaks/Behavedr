using Behavedr.Core;
using Behavedr.Core.Response;

namespace Behavedr.Tests;

public class ResponseSafetyTests
{
    [Fact]
    public void RefuseKill_OwnProcess()
    {
        Assert.True(ResponseSafety.ShouldRefuseKill(Environment.ProcessId, "anything", out var reason));
        Assert.Contains("own", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RefuseKill_SystemPid()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.True(ResponseSafety.ShouldRefuseKill(4, "System", out _));
        }
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            Assert.True(ResponseSafety.ShouldRefuseKill(1, "init", out _));
        }
    }

    [Fact]
    public void SpoofedExplorerName_InTemp_IsNotSystemImage()
    {
        var fake = Path.Combine(Path.GetTempPath(), "explorer.exe");
        Assert.False(ResponseSafety.IsOsSystemImagePath(fake));
        // Name alone with non-system path must not grant protection when we only have name+pid
        // (path verification fails open for kill of spoofed names outside system dirs)
        Assert.False(ResponseSafety.IsOwnAgentImage(fake));
    }

    [Fact]
    public void TempBehavedrNamedMalware_IsNotOwnAgentImage()
    {
        var fake = Path.Combine(Path.GetTempPath(), "Behavedr_evil.exe");
        Assert.False(ResponseSafety.IsOwnAgentImage(fake));
    }

    [Fact]
    public void RefuseQuarantine_SystemPath()
    {
        if (OperatingSystem.IsWindows())
        {
            var sys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "ntdll.dll");
            Assert.True(ResponseSafety.ShouldRefuseQuarantine(sys, out _));
        }
        else
        {
            Assert.True(ResponseSafety.ShouldRefuseQuarantine("/bin/sh", out _));
        }
    }

    [Fact]
    public void ThreatHeuristics_NameOnly_IsLowWeight()
    {
        var s = ThreatHeuristics.Evaluate("mimikatz", null);
        Assert.NotNull(s);
        Assert.True(s!.Value.Weight < 50);
        Assert.Equal("known_tool_name_only", s.Value.Tag);
    }

    [Fact]
    public void ThreatHeuristics_StagingExe_IsHighWeight()
    {
        var s = ThreatHeuristics.Evaluate("totally_legit", "/tmp/payload.exe");
        Assert.NotNull(s);
        Assert.True(s!.Value.Weight >= 70);
        Assert.Contains("staging", s.Value.Tag, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ThreatHeuristics_RenameDoesNotEraseStagingRisk()
    {
        // Attacker renames tool but still drops in /tmp
        var s = ThreatHeuristics.Evaluate("chrome_update", "/var/tmp/chrome_update");
        Assert.NotNull(s);
        Assert.True(s!.Value.Weight >= 70);
    }

    [Fact]
    public void Policy_RejectsKillStormBudget()
    {
        var p = new ResponsePolicy { MaxKillsPerMinute = 500 };
        Assert.False(p.IsValid());
    }

    [Fact]
    public void Policy_RejectsActiveModeLowResponseThreshold()
    {
        var p = new ResponsePolicy
        {
            Mode = ResponseMode.Active,
            AlertThreshold = 5,
            ResponseThreshold = 10,
        };
        Assert.False(p.IsValid());
    }

    [Fact]
    public async Task ProcessKill_OwnPid_Skipped()
    {
        var action = new ProcessKillAction();
        var evt = new Behavedr.Core.Models.DetectionEvent(
            Environment.ProcessId.ToString(),
            "self",
            "test",
            DateTime.UtcNow,
            false,
            "test");
        var result = new DetectionResult(
            evt, 99, true,
            [new Behavedr.Core.Models.Signal("x", 90, 0.9)]);
        var outcome = await action.ExecuteAsync(result);
        Assert.Contains("Safety", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }
}
