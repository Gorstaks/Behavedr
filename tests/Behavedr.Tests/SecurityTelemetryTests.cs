using Behavedr.Core.Security;
using Behavedr.Core.Telemetry;

namespace Behavedr.Tests;

public class SecurityTelemetryTests
{
    [Fact]
    public void SignatureFailure_InvokesHook()
    {
        var hits = 0;
        SecurityTelemetry.OnSignatureFailure = () => hits++;
        try
        {
            // Missing files -> failure path
            var ok = UpdateSignatureVerifier.VerifySignature(
                Path.Combine(Path.GetTempPath(), "no-such-update.zip"),
                Path.Combine(Path.GetTempPath(), "no-such-update.zip.sig"));
            Assert.False(ok);
            // VerifySignature returns before hook on missing file - ensure hook on bad sig
            hits = 0;
            var tmp = Path.Combine(Path.GetTempPath(), "behavedr-sig-" + Guid.NewGuid().ToString("N") + ".bin");
            var sig = tmp + ".sig";
            File.WriteAllBytes(tmp, new byte[2048]);
            File.WriteAllBytes(sig, new byte[256]); // invalid PSS
            try
            {
                ok = UpdateSignatureVerifier.VerifySignature(tmp, sig);
                Assert.False(ok);
                Assert.True(hits >= 1);
            }
            finally
            {
                try { File.Delete(tmp); } catch { }
                try { File.Delete(sig); } catch { }
            }
        }
        finally
        {
            SecurityTelemetry.OnSignatureFailure = null;
        }
    }

    [Fact]
    public void IsolationAndSoftFail_HooksFire()
    {
        var iso = 0;
        var soft = 0;
        SecurityTelemetry.OnIsolationAction = () => iso++;
        SecurityTelemetry.OnPlatformSoftFail = _ => soft++;
        try
        {
            SecurityTelemetry.ReportIsolationAction();
            SecurityTelemetry.ReportPlatformSoftFail("test");
            Assert.Equal(1, iso);
            Assert.Equal(1, soft);
        }
        finally
        {
            SecurityTelemetry.OnIsolationAction = null;
            SecurityTelemetry.OnPlatformSoftFail = null;
        }
    }
}
