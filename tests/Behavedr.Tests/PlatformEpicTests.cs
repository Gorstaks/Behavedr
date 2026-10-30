using Behavedr.Core.Monitors;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;

namespace Behavedr.Tests;

/// <summary>
/// Smoke tests for v0.2.7 platform epics (WFP, eBPF, EndpointSecurity).
/// Full attach paths require OS privileges / entitlements; we validate wiring and fail-soft.
/// </summary>
public class PlatformEpicTests
{
    [Fact]
    public void PlatformMonitors_IncludesEpicMonitors_OnSupportedOs()
    {
        var names = PlatformMonitors.All.Select(m => m.PlatformName).ToHashSet(StringComparer.Ordinal);

        // Epic monitors are registered only on their host OS (same as other platform monitors).
        if (OperatingSystem.IsLinux())
            Assert.Contains("LinuxEbpfExec", names);

        if (OperatingSystem.IsMacOS())
            Assert.Contains("MacOSEndpointSecurity", names);

        // Types construct on any OS (IsSupported gates runtime use).
        _ = new LinuxEbpfExecMonitor();
        _ = new MacOSEndpointSecurityMonitor();
    }

    [Fact]
    public void LinuxEbpf_IsSupportedOnlyOnLinux()
    {
        var m = new LinuxEbpfExecMonitor();
        Assert.Equal(OperatingSystem.IsLinux(), m.IsSupported);
        if (!OperatingSystem.IsLinux())
            Assert.False(m.IsActive);
    }

    [Fact]
    public void MacOSEndpointSecurity_IsSupportedOnlyOnMac()
    {
        var m = new MacOSEndpointSecurityMonitor();
        Assert.Equal(OperatingSystem.IsMacOS(), m.IsSupported);
        if (!OperatingSystem.IsMacOS())
            Assert.False(m.IsActive);
    }

    [Fact]
    public void WindowsNetworkIsolation_ExposesWfpPath()
    {
        var action = new WindowsNetworkIsolation();
        Assert.Equal(OperatingSystem.IsWindows(), action.IsSupported);
        Assert.Equal("WindowsNetworkIsolation", action.Name);
        action.Dispose();
    }

    [Fact]
    public void WindowsWfpEngine_ConstructsWithoutThrow()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var eng = new WindowsWfpEngine();
        // TryOpen may fail without elevation - must not throw
        _ = eng.TryOpen();
    }

    [Fact]
    public async Task EpicMonitors_GetSignals_DoesNotThrow()
    {
        if (OperatingSystem.IsLinux())
        {
            var ebpf = new LinuxEbpfExecMonitor();
            var sigs = await ebpf.GetSignalsAsync();
            Assert.NotNull(sigs);
            ebpf.Dispose();
        }

        if (OperatingSystem.IsMacOS())
        {
            var es = new MacOSEndpointSecurityMonitor();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var sigs = await Task.Run(() => es.GetSignalsAsync(cts.Token), cts.Token)
                .WaitAsync(cts.Token);
            Assert.NotNull(sigs);
            es.Dispose();
        }
    }

    [Fact]
    public void NativeEpicArtifacts_PresentInTree()
    {
        var root = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(root, "native", "linux", "ebpf", "behavedr_suite.bpf.c")));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "es_bridge", "behavedr_es_bridge.c")));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "SystemExtension", "main.m")));
        Assert.True(File.Exists(Path.Combine(root, "packaging", "unix", "macos-endpointsecurity.md")));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Behavedr.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
    }
}
