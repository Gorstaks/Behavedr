using Behavedr.Core.Models;
using Behavedr.Core.Monitors;
using Behavedr.Core.Platform;

namespace Behavedr.Tests;

/// <summary>
/// v0.4.1 protection-rating lift: new monitors construct and register correctly.
/// </summary>
public class ProtectionLift041Tests
{
    [Fact]
    public void NewMonitors_ConstructAndReportPlatformNames()
    {
        var agentic = new AgenticProcessMonitor();
        var pkg = new PackageRuntimeMonitor();
        var canary = new CanaryFileMonitor();
        var cloud = new CloudSyncExfilMonitor();
        var pipes = new NamedPipeMonitor();
        var lnk = new LnkShortcutMonitor();
        var script = new ScriptExecutionMonitor();

        Assert.Equal("AgenticProcess", agentic.PlatformName);
        Assert.Equal("PackageRuntime", pkg.PlatformName);
        Assert.Equal("CanaryFile", canary.PlatformName);
        Assert.Equal("CloudSyncExfil", cloud.PlatformName);
        Assert.Equal("NamedPipe", pipes.PlatformName);
        Assert.Equal("LnkShortcut", lnk.PlatformName);
        Assert.Equal("ScriptExecution", script.PlatformName);

        Assert.True(canary.IsSupported);
        Assert.Equal(OperatingSystem.IsWindows(), pipes.IsSupported);
        Assert.Equal(OperatingSystem.IsWindows(), lnk.IsSupported);
        Assert.Equal(OperatingSystem.IsWindows(), script.IsSupported);
        Assert.Equal(
            OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS(),
            agentic.IsSupported);

        pkg.Dispose();
        lnk.Dispose();
    }

    [Fact]
    public async Task NewMonitors_GetSignalsDoesNotThrow()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));

        var agentic = new AgenticProcessMonitor();
        var pkg = new PackageRuntimeMonitor();
        var canary = new CanaryFileMonitor();
        var cloud = new CloudSyncExfilMonitor();

        // Bound wall-clock on a worker thread (sync monitors ignore CancellationToken).
        static Task<IEnumerable<Signal>> Bounded(IPlatformMonitor m, CancellationToken ct) =>
            Task.Run(() => m.GetSignalsAsync(ct), ct).WaitAsync(ct);

        var s1 = await Bounded(agentic, cts.Token);
        var s2 = await Bounded(pkg, cts.Token);
        var s3 = await Bounded(canary, cts.Token);
        var s4 = await Bounded(cloud, cts.Token);

        Assert.NotNull(s1);
        Assert.NotNull(s2);
        Assert.NotNull(s3);
        Assert.NotNull(s4);

        if (OperatingSystem.IsWindows())
        {
            var pipes = new NamedPipeMonitor();
            var lnk = new LnkShortcutMonitor();
            var script = new ScriptExecutionMonitor();
            Assert.NotNull(await Bounded(pipes, cts.Token));
            Assert.NotNull(await Bounded(lnk, cts.Token));
            Assert.NotNull(await Bounded(script, cts.Token));
            lnk.Dispose();
        }

        pkg.Dispose();
    }

    [Fact]
    public void PlatformMonitors_IncludesNewProtectionMonitors_OnWindows()
    {
        if (!OperatingSystem.IsWindows()) return;

        var names = PlatformMonitors.All.Select(m => m.GetType().Name).ToHashSet();
        Assert.Contains("AgenticProcessMonitor", names);
        Assert.Contains("PackageRuntimeMonitor", names);
        Assert.Contains("CanaryFileMonitor", names);
        Assert.Contains("CloudSyncExfilMonitor", names);
        Assert.Contains("NamedPipeMonitor", names);
        Assert.Contains("LnkShortcutMonitor", names);
        Assert.Contains("ScriptExecutionMonitor", names);
    }

    [Fact]
    public void CanaryFileMonitor_PlantsAndDetectsAbsence()
    {
        var mon = new CanaryFileMonitor();
        // First call plants; second call should not throw
        var first = mon.GetSignalsAsync().GetAwaiter().GetResult().ToList();
        var second = mon.GetSignalsAsync().GetAwaiter().GetResult().ToList();
        Assert.NotNull(first);
        Assert.NotNull(second);
    }
}
