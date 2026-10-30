using Behavedr.Core.Response;
using Behavedr.Core.Security;

namespace Behavedr.Tests;

public class SecurityTests
{
    [Fact]
    public void SecureEnvelope_RoundTrip_Succeeds()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("behavedr-selftest-payload");
        var sealedData = SecureEnvelope.Seal(plain, "unit-test");
        var opened = SecureEnvelope.Unseal(sealedData, "unit-test");

        Assert.NotNull(opened);
        Assert.Equal(plain, opened);
    }

    [Fact]
    public void SecureEnvelope_TamperedCiphertext_ReturnsNull()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("integrity-check");
        var sealedData = SecureEnvelope.Seal(plain, "unit-test-tamper");
        var bytes = Convert.FromBase64String(sealedData);
        bytes[^1] ^= 0xFF; // flip last ciphertext bit
        var tampered = Convert.ToBase64String(bytes);

        var opened = SecureEnvelope.Unseal(tampered, "unit-test-tamper");
        Assert.Null(opened);
    }

    [Fact]
    public void SecureEnvelope_WrongPurpose_ReturnsNull()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("purpose-binding");
        var sealedData = SecureEnvelope.Seal(plain, "purpose-a");
        Assert.Null(SecureEnvelope.Unseal(sealedData, "purpose-b"));
    }

    [Fact]
    public void UpdateSignatureVerifier_ProductionKeyConfigured()
    {
        Assert.True(UpdateSignatureVerifier.IsProductionKeyConfigured());
        Assert.NotNull(UpdateSignatureVerifier.GetPublicKeyPem());
    }

    [Fact]
    public void SecurityValidation_RejectsPathTraversal()
    {
        var baseDir = Path.GetTempPath();
        Assert.False(SecurityValidation.IsPathWithinDirectory(
            Path.Combine(baseDir, "..", "etc", "passwd"), baseDir));
    }

    [Fact]
    public void SecurityValidation_AcceptsChildPath()
    {
        var baseDir = Path.GetFullPath(Path.GetTempPath());
        var child = Path.Combine(baseDir, "quarantine", "sample.bin");
        Assert.True(SecurityValidation.IsPathWithinDirectory(child, baseDir));
    }

    [Fact]
    public async Task ResponseEngine_KillBudget_Exhausts()
    {
        var policy = new ResponsePolicy
        {
            Mode = ResponseMode.Active,
            ResponseThreshold = 50,
            MaxKillsPerMinute = 2,
        };
        var engine = new ResponseEngine(policy);
        // ProcessKillAction is kill-class; with presidentKill it will try to execute
        // Use FakeAction that is not kill-class for budget test of generic actions:
        // budget only applies to ProcessKillAction / AndroidResponseEngine.
        // So test MaxKillsPerMinute via ProcessKillAction with presidentKill.
        engine.RegisterAction(new ProcessKillAction());

        var r1 = new Core.DetectionResult(
            Core.Models.DetectionEvent.Create("99991", "nonexistent-a", "t", "test", false),
            99, true, new List<Core.Models.Signal>());
        var r2 = new Core.DetectionResult(
            Core.Models.DetectionEvent.Create("99992", "nonexistent-b", "t", "test", false),
            99, true, new List<Core.Models.Signal>());
        var r3 = new Core.DetectionResult(
            Core.Models.DetectionEvent.Create("99993", "nonexistent-c", "t", "test", false),
            99, true, new List<Core.Models.Signal>());

        await engine.RespondAsync(r1);
        await engine.RespondAsync(r2);
        var third = await engine.RespondAsync(r3);

        Assert.Contains(third, o => o.Message.Contains("budget", StringComparison.OrdinalIgnoreCase)
            || o.Message.Contains("Skipped", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ResponsePolicy_RejectsNegativeKillBudget()
    {
        var policy = new ResponsePolicy { MaxKillsPerMinute = -1 };
        Assert.False(policy.IsValid());
    }
}
