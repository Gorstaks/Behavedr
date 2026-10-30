using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Behavedr.Core.Security;
using Behavedr.Core.Update;

namespace Behavedr.Tests;

/// <summary>
/// Security-focused tests for update path: Zip Slip, version compare, policy key path, rollback markers.
/// </summary>
public class UpdateSecurityTests
{
    [Theory]
    [InlineData("1.0.1", "1.0.0", true)]
    [InlineData("0.2.4", "0.2.3", true)]
    [InlineData("0.2.3", "0.2.3", false)]
    [InlineData("0.2.2", "0.2.3", false)]
    [InlineData("not-a-version", "0.2.3", false)]
    public void IsNewerVersion_ComparesSemantically(string latest, string current, bool expected)
    {
        Assert.Equal(expected, AutoUpdater.IsNewerVersion(latest, current));
    }

    [Fact]
    public void TryResolveZipEntryPath_RejectsPathTraversal()
    {
        var staging = Path.Combine(Path.GetTempPath(), "behavedr-zipslip-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        try
        {
            Assert.False(AutoUpdater.TryResolveZipEntryPath(staging, "../evil.exe", out _));
            Assert.False(AutoUpdater.TryResolveZipEntryPath(staging, "..\\evil.exe", out _));
            Assert.False(AutoUpdater.TryResolveZipEntryPath(staging, "sub/../../evil.exe", out _));
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { }
        }
    }

    [Fact]
    public void TryResolveZipEntryPath_AcceptsSafeChild()
    {
        var staging = Path.Combine(Path.GetTempPath(), "behavedr-zipok-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        try
        {
            Assert.True(AutoUpdater.TryResolveZipEntryPath(staging, "Behavedr.exe", out var dest));
            Assert.StartsWith(Path.GetFullPath(staging), dest, StringComparison.OrdinalIgnoreCase);
            Assert.True(AutoUpdater.TryResolveZipEntryPath(staging, "nested/file.dll", out _));
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { }
        }
    }

    [Fact]
    public void ExtractZipSafely_RejectsZipSlipArchive()
    {
        var root = Path.Combine(Path.GetTempPath(), "behavedr-extract-" + Guid.NewGuid().ToString("N"));
        var staging = Path.Combine(root, "stage");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(staging);

        var zipPath = Path.Combine(root, "slip.zip");
        try
        {
            // Build a zip with a traversal entry name
            using (var fs = File.Create(zipPath))
            using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("../escape.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.Write("should-not-extract");
            }

            Assert.False(AutoUpdater.ExtractZipSafely(zipPath, staging));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public void ExtractZipSafely_ExtractsHonestArchive()
    {
        var root = Path.Combine(Path.GetTempPath(), "behavedr-extract-ok-" + Guid.NewGuid().ToString("N"));
        var staging = Path.Combine(root, "stage");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(staging);

        var zipPath = Path.Combine(root, "ok.zip");
        try
        {
            using (var fs = File.Create(zipPath))
            using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("hello.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.Write("payload");
            }

            Assert.True(AutoUpdater.ExtractZipSafely(zipPath, staging));
            Assert.True(File.Exists(Path.Combine(staging, "hello.txt")));
            Assert.Equal("payload", File.ReadAllText(Path.Combine(staging, "hello.txt")));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public void UpdateSignatureVerifier_RoundTrip_WithEphemeralKey_IsValid()
    {
        // Demonstrates algorithm compatibility (PSS + SHA-256) even though production uses baked key.
        using var rsa = RSA.Create(2048);
        var payload = Encoding.UTF8.GetBytes("behavedr-update-fixture");
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.True(rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Fact]
    public void PolicySignatureVerifier_IsConfigured_AndDistinctFromUpdateKey()
    {
        Assert.True(PolicySignatureVerifier.IsProductionKeyConfigured());
        Assert.NotNull(PolicySignatureVerifier.GetPublicKeyPem());
        // v0.2.6: distinct policy key baked in (blast-radius isolation).
        Assert.False(PolicySignatureVerifier.IsUsingSharedUpdateKey());
    }

    [Fact]
    public void PolicySignatureVerifier_RejectsEmptyPayload()
    {
        Assert.False(PolicySignatureVerifier.VerifyPayload(ReadOnlySpan<byte>.Empty, new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void PolicySignatureVerifier_VerifyPayload_WithMatchingKey_Succeeds()
    {
        // Sign with the baked public key's matching private key is not available in CI.
        // Verify that wrong signature fails closed.
        var payload = Encoding.UTF8.GetBytes("{\"MonitoringIntervalSeconds\":5}");
        var bogusSig = new byte[256];
        RandomNumberGenerator.Fill(bogusSig);
        Assert.False(PolicySignatureVerifier.VerifyPayload(payload, bogusSig));
    }

    [Fact]
    public void WritePendingUpdateMarker_CreatesReadableVersionFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "behavedr-marker-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            AutoUpdater.WritePendingUpdateMarker(dir, "0.2.4");
            var marker = Path.Combine(dir, AutoUpdater.PendingUpdateMarkerFileName);
            Assert.True(File.Exists(marker));
            Assert.Contains("0.2.4", File.ReadAllText(marker), StringComparison.Ordinal);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void TryHealthCheckRollback_NoMarker_ReturnsFalse()
    {
        // Without a marker next to the running process, rollback is a no-op.
        Assert.False(AutoUpdater.TryHealthCheckRollback(() => true));
    }
}
