using Behavedr.Core.Platform;
using Behavedr.Core.Security;

namespace Behavedr.Tests;

public class PlatformFeaturesTests
{
    [Fact]
    public void FromEnvironment_MergesFlags()
    {
        var prev = Environment.GetEnvironmentVariable("BEHAVEDR_LANDLOCK");
        try
        {
            Environment.SetEnvironmentVariable("BEHAVEDR_LANDLOCK", "1");
            var f = PlatformFeatures.FromEnvironment(new PlatformFeatures { PreferWfp = false });
            Assert.True(f.EnableLandlock);
            Assert.False(f.PreferWfp);
        }
        finally
        {
            Environment.SetEnvironmentVariable("BEHAVEDR_LANDLOCK", prev);
        }
    }

    [Fact]
    public void LinuxLandlock_SoftFailsOnNonLinux()
    {
        if (OperatingSystem.IsLinux())
            return;
        Assert.False(LinuxLandlock.TryApplyDefaultProfile());
    }

    [Fact]
    public void PlatformFeatures_Default_IsSafe()
    {
        var d = PlatformFeatures.Default;
        Assert.False(d.EnableLandlock);
        Assert.False(d.EnableFanotifyPerm);
        Assert.False(d.EnableEndpointSecurityAuth);
        Assert.False(d.RequirePlayIntegrity);
        Assert.True(d.PreferWfp);
    }
}
