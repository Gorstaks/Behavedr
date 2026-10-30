using Behavedr.Core.Platform;

namespace Behavedr.Tests;

public class PlatformMonitorsTests
{
    [Fact]
    public void All_ContainsAtLeastBasePlatformMonitors()
    {
        // Base monitors: Windows, Linux, macOS, Android + cross-platform monitors.
        // On Windows, additional behavioral/anti-tamper monitors are added dynamically.
        Assert.True(PlatformMonitors.All.Count >= 6,
            $"Expected at least 6 monitors (4 platform + 2 cross-platform), got {PlatformMonitors.All.Count}");
    }

    [Fact]
    public void All_ContainsExpectedPlatforms()
    {
        var names = PlatformMonitors.All.Select(m => m.PlatformName).ToList();
        Assert.Contains("Windows", names);
        Assert.Contains("Linux", names);
        Assert.Contains("macOS", names);
        Assert.Contains("Android", names);
        Assert.DoesNotContain("iOS", names);
    }

    [Fact]
    public void Supported_ReturnsOnlyMatchingPlatform()
    {
        var supported = PlatformMonitors.Supported().ToList();

        // On the test host, exactly one desktop monitor should be supported
        Assert.True(supported.Count >= 1, "At least one monitor should be supported on the test host");

        // All returned monitors should report IsSupported = true
        Assert.All(supported, m => Assert.True(m.IsSupported));
    }

    [Fact]
    public void CurrentPlatformSummary_ReturnsNonEmpty()
    {
        var summary = PlatformMonitors.CurrentPlatformSummary();
        Assert.False(string.IsNullOrWhiteSpace(summary));
        Assert.NotEqual("Unknown", summary);
    }

    [Fact]
    public void LinuxAndMacOSGradeLiftMonitors_ConstructAndGateIsSupported()
    {
        // Types must construct on every CI host; IsSupported is platform-gated.
        var kernel = new Behavedr.Core.Monitors.LinuxKernelModuleMonitor();
        var auth = new Behavedr.Core.Monitors.LinuxAuthMonitor();
        var files = new Behavedr.Core.Monitors.MacOSFileEventMonitor();
        var codesign = new Behavedr.Core.Monitors.MacOSCodeSignMonitor();
        var isolation = new Behavedr.Core.Response.MacOSNetworkIsolation();

        Assert.Equal(OperatingSystem.IsLinux(), kernel.IsSupported);
        Assert.Equal(OperatingSystem.IsLinux(), auth.IsSupported);
        Assert.Equal(OperatingSystem.IsMacOS(), files.IsSupported);
        Assert.Equal(OperatingSystem.IsMacOS(), codesign.IsSupported);
        Assert.Equal(OperatingSystem.IsMacOS(), isolation.IsSupported);

        if (OperatingSystem.IsLinux())
        {
            Assert.Contains(PlatformMonitors.All, m => m.GetType().Name == "LinuxKernelModuleMonitor");
            Assert.Contains(PlatformMonitors.All, m => m.GetType().Name == "LinuxAuthMonitor");
        }

        if (OperatingSystem.IsMacOS())
        {
            Assert.Contains(PlatformMonitors.All, m => m.GetType().Name == "MacOSFileEventMonitor");
            Assert.Contains(PlatformMonitors.All, m => m.GetType().Name == "MacOSCodeSignMonitor");
        }
    }
}
