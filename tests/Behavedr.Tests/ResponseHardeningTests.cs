using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Response;
using Behavedr.Core.Security;

namespace Behavedr.Tests;

public class ResponseHardeningTests
{
    [Fact]
    public void IsolationResponse_ParsesDockerIdFromSignal()
    {
        var engine = new IsolationResponseEngine();
        var result = new DetectionResult(
            DetectionEvent.Create("1", "dockerd", "iso", "test", false),
            90, true,
            new List<Signal> { new("docker:a1b2c3d4e5f67890", 80, 0.9) });

        // On machines without docker this still returns Ok (attempt) or may no-op stop -
        // ExecuteAsync should not skip for "ID not available" when ID is parseable.
        var outcome = engine.ExecuteAsync(result).GetAwaiter().GetResult();
        Assert.DoesNotContain("container ID not available", outcome.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("not parseable", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsolationResponse_ParsesIsoPathFromSignal()
    {
        var engine = new IsolationResponseEngine();
        var result = new DetectionResult(
            DetectionEvent.Create("99999", "evil", "iso", "test", false),
            90, true,
            new List<Signal> { new("iso_mount:C:\\temp\\payload.iso", 80, 0.9) });

        var outcome = engine.ExecuteAsync(result).GetAwaiter().GetResult();
        Assert.Contains("ISO", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WindowsNetworkIsolation_IsSupportedOnlyOnWindows()
    {
        var action = new WindowsNetworkIsolation();
        Assert.Equal(OperatingSystem.IsWindows(), action.IsSupported);
    }

    [Fact]
    public async Task WindowsNetworkIsolation_SkipsWithoutIpsOnNonElevated()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var action = new WindowsNetworkIsolation();
        var result = new DetectionResult(
            DetectionEvent.Create("1", "test", "net", "test", false),
            90, true,
            new List<Signal> { new("no_ip_here", 50, 0.5) });

        var outcome = await action.ExecuteAsync(result);
        // Either skipped (no IP/image) or failed netsh - must not throw
        Assert.False(string.IsNullOrEmpty(outcome.Message));
    }

    [Fact]
    public void ResponseAuditWriter_WritesJsonl()
    {
        var dir = Path.Combine(Path.GetTempPath(), "behavedr-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var writer = new ResponseAuditWriter(dir);
            var result = new DetectionResult(
                DetectionEvent.Create("42", "malware", "t", "test", true),
                99, true,
                new List<Signal> { new("evil:pid:42", 90, 1.0) });
            writer.Append(result, new[] { ResponseOutcome.Ok("ProcessKill", "killed") }, "Active");

            var path = Path.Combine(dir, ResponseAuditWriter.RelativePath);
            Assert.True(File.Exists(path));
            var text = File.ReadAllText(path);
            Assert.Contains("ProcessKill", text, StringComparison.Ordinal);
            Assert.Contains("malware", text, StringComparison.Ordinal);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void PolicyKey_IsDistinctFromUpdateKey()
    {
        Assert.False(PolicySignatureVerifier.IsUsingSharedUpdateKey());
    }
}
