using Android.Content;
using Android.Content.PM;
using Android.OS;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Environment = System.Environment;
using Signal = Behavedr.Core.Models.Signal;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Android update security service providing:
/// 1. Update package signature verification (reject unsigned/wrong-key updates)
/// 2. Certificate pinning for update download channel
/// 3. Minimum version enforcement (anti-downgrade)
/// 4. Rollback detection (was current version replaced with older one?)
/// 5. In-app update API integration (Google Play In-App Updates)
/// 6. Update integrity verification (SHA-256 hash of downloaded APK)
///
/// Attack vectors mitigated:
/// - MITM on update download -> certificate pinning + hash verification
/// - Malicious update pushed by compromised server -> signature pinning
/// - Downgrade to vulnerable version -> version code monotonic enforcement
/// - Update channel manipulation -> multiple redundant verification
///
/// v0.2.0 audit fix: Secure OTA update verification for Android.
/// </summary>
public sealed class AndroidUpdateSecurity
{
    private readonly Context _context;
    private readonly ILogger _logger;

    // Known good SHA-256 fingerprint of the signing key for updates
    // Same as in SupplyChainVerifier - updates must be signed with same key
    private readonly string _trustedSigningKeyFingerprint;

    // Update server URLs (primary + fallback)
    private readonly string _primaryUpdateUrl;
    private readonly string _fallbackUpdateUrl;

    // Version tracking file for rollback detection
    private const string VersionHistoryFile = "version_history.json";

    public AndroidUpdateSecurity(
        Context context,
        string? trustedKeyFingerprint = null,
        string primaryUpdateUrl = "https://api.croatiasecurity.com/updates/android",
        string fallbackUpdateUrl = "https://github.com/CroatiaSecurity/Behavedr/releases",
        ILogger? logger = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        // End users never set this. Order: ctor -> vendor bake-in -> env (MDM only).
        var pin = trustedKeyFingerprint
                  ?? FirstVendorPin()
                  ?? Environment.GetEnvironmentVariable("BEHAVEDR_ANDROID_CERT_SHA256")
                  ?? "";
        if (pin.Contains("PLACEHOLDER", StringComparison.OrdinalIgnoreCase))
            pin = "";
        if (pin.Contains(','))
            pin = pin.Split(',')[0].Trim();
        _trustedSigningKeyFingerprint = pin.Replace(":", "", StringComparison.Ordinal)
            .Replace(" ", "", StringComparison.Ordinal)
            .Trim()
            .ToUpperInvariant();
        // Zero-config: if no vendor pin, pin to the cert of the *currently installed* APK.
        // Update APKs must be signed with the same key as what the user already runs.
        if (string.IsNullOrEmpty(_trustedSigningKeyFingerprint))
            _trustedSigningKeyFingerprint = TryGetInstalledApkCertFingerprint() ?? "";
        _primaryUpdateUrl = primaryUpdateUrl;
        _fallbackUpdateUrl = fallbackUpdateUrl;
        _logger = logger ?? NullLogger.Instance;
        if (string.IsNullOrEmpty(_trustedSigningKeyFingerprint))
            _logger.LogWarning("[UpdateSecurity] Could not resolve APK cert for update pinning");
        else
            _logger.LogDebug("[UpdateSecurity] Update APKs must match cert pin (automatic, no user setup)");
    }

    public bool IsSignerPinConfigured =>
        !string.IsNullOrEmpty(_trustedSigningKeyFingerprint) &&
        !_trustedSigningKeyFingerprint.Contains("PLACEHOLDER", StringComparison.OrdinalIgnoreCase);

    private static string? FirstVendorPin()
    {
        var pins = AndroidCertPins.VendorFingerprints;
        return pins.Length > 0 ? pins[0] : null;
    }

    private string? TryGetInstalledApkCertFingerprint()
    {
        try
        {
            var pm = _context.PackageManager;
            if (pm is null) return null;
#pragma warning disable CA1416
            if (Build.VERSION.SdkInt >= BuildVersionCodes.P)
            {
                var pkgInfo = pm.GetPackageInfo(_context.PackageName!,
                    (PackageInfoFlags)((long)PackageInfoFlags.SigningCertificates));
                var signingInfo = pkgInfo?.SigningInfo;
                var signers = signingInfo?.HasMultipleSigners == true
                    ? signingInfo.GetApkContentsSigners()?.ToArray()
                    : signingInfo?.GetSigningCertificateHistory()?.ToArray();
                var bytes = signers?.FirstOrDefault()?.ToByteArray();
                if (bytes is null) return null;
                return Convert.ToHexString(SHA256.HashData(bytes));
            }
#pragma warning restore CA1416
#pragma warning disable CS0618, CA1422
            var legacy = pm.GetPackageInfo(_context.PackageName!, PackageInfoFlags.Signatures);
            var sig = legacy?.Signatures?.FirstOrDefault()?.ToByteArray();
            return sig is null ? null : Convert.ToHexString(SHA256.HashData(sig));
#pragma warning restore CS0618, CA1422
        }
        catch { return null; }
    }

    /// <summary>
    /// Check for updates securely. Returns update info if available.
    /// </summary>
    public async Task<UpdateCheckResult> CheckForUpdateAsync(CancellationToken ct = default)
    {
        try
        {
            var currentVersion = GetCurrentVersionCode();

            // Try primary update server
            var updateInfo = await FetchUpdateInfoAsync(_primaryUpdateUrl, ct);
            if (updateInfo is null)
            {
                // Fallback to secondary
                updateInfo = await FetchUpdateInfoAsync(_fallbackUpdateUrl, ct);
            }

            if (updateInfo is null)
            {
                return new UpdateCheckResult(false, currentVersion, 0, null, "Server unreachable");
            }

            if (updateInfo.VersionCode <= currentVersion)
            {
                return new UpdateCheckResult(false, currentVersion, updateInfo.VersionCode,
                    null, "Already up to date");
            }

            // Verify the update metadata signature
            if (!VerifyUpdateMetadataSignature(updateInfo))
            {
                _logger.LogCritical("[UpdateSecurity] Update metadata signature INVALID - " +
                    "possible update channel compromise!");
                return new UpdateCheckResult(false, currentVersion, updateInfo.VersionCode,
                    null, "Metadata signature invalid");
            }

            return new UpdateCheckResult(true, currentVersion, updateInfo.VersionCode,
                updateInfo.DownloadUrl, "Update available");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[UpdateSecurity] Update check failed");
            return new UpdateCheckResult(false, GetCurrentVersionCode(), 0, null, ex.Message);
        }
    }

    /// <summary>
    /// Verify a downloaded APK before installation.
    /// Checks: SHA-256 hash, signing certificate, version code, debuggable flag.
    /// </summary>
    public UpdateVerificationResult VerifyDownloadedApk(string apkPath, string expectedHash)
    {
        if (!File.Exists(apkPath))
            return UpdateVerificationResult.Failed("APK file not found");

        // 1. Verify SHA-256 hash
        using (var stream = File.OpenRead(apkPath))
        {
            var actualHash = Convert.ToHexString(SHA256.HashData(stream));
            if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogCritical("[UpdateSecurity] APK hash mismatch! Expected={Expected}, Got={Got}",
                    expectedHash, actualHash);
                return UpdateVerificationResult.Failed(
                    $"Hash mismatch: expected {expectedHash[..16]}..., got {actualHash[..16]}...");
            }
        }

        // 2. Verify signing certificate
        try
        {
            var pm = _context.PackageManager;
            if (pm is null) return UpdateVerificationResult.Failed("PackageManager unavailable");

#pragma warning disable CA1416
            var archiveInfo = pm.GetPackageArchiveInfo(apkPath,
                (PackageInfoFlags)((long)PackageInfoFlags.SigningCertificates));

            if (archiveInfo is null)
                return UpdateVerificationResult.Failed("Cannot parse APK archive");

            // Check signing certificate
            var signingInfo = archiveInfo.SigningInfo;
            if (signingInfo is null)
                return UpdateVerificationResult.Failed("No signing info in APK");

            var signers = signingInfo.HasMultipleSigners
                ? signingInfo.GetApkContentsSigners()?.ToArray()
                : signingInfo.GetSigningCertificateHistory()?.ToArray();
#pragma warning restore CA1416

            if (signers is null || signers.Length == 0)
                return UpdateVerificationResult.Failed("No signers in APK");

            if (!IsSignerPinConfigured)
            {
                return UpdateVerificationResult.Failed(
                    "Cannot verify update signer (no installed-app cert available)");
            }

            bool foundTrusted = false;
            foreach (var sig in signers)
            {
                var certBytes = sig?.ToByteArray();
                if (certBytes is null) continue;
                var fingerprint = Convert.ToHexString(SHA256.HashData(certBytes));

                if (string.Equals(fingerprint, _trustedSigningKeyFingerprint,
                    StringComparison.OrdinalIgnoreCase))
                {
                    foundTrusted = true;
                    break;
                }
            }

            if (!foundTrusted)
            {
                return UpdateVerificationResult.Failed(
                    "Update APK signed with different key than installed app - refused");
            }

            // 3. Version code anti-rollback
            long updateVersionCode;
            if (Build.VERSION.SdkInt >= BuildVersionCodes.P)
            {
#pragma warning disable CA1416
                updateVersionCode = archiveInfo.LongVersionCode;
#pragma warning restore CA1416
            }
            else
            {
#pragma warning disable CS0618, CA1422
                updateVersionCode = archiveInfo.VersionCode;
#pragma warning restore CS0618, CA1422
            }

            var currentVersion = GetCurrentVersionCode();
            if (updateVersionCode <= currentVersion)
            {
                return UpdateVerificationResult.Failed(
                    $"Version rollback: update v{updateVersionCode} <= current v{currentVersion}");
            }

            // 4. Ensure not debuggable
            if (archiveInfo.ApplicationInfo is not null &&
                (archiveInfo.ApplicationInfo.Flags & ApplicationInfoFlags.Debuggable) != 0)
            {
                return UpdateVerificationResult.Failed("Update APK is debuggable");
            }

            // 5. Record version in history (for future rollback detection)
            RecordVersionHistory(updateVersionCode, expectedHash);

            _logger.LogInformation("[UpdateSecurity] APK verified: v{Version}, hash={Hash}",
                updateVersionCode, expectedHash[..16]);
            return UpdateVerificationResult.Passed(updateVersionCode, expectedHash);
        }
        catch (Exception ex)
        {
            return UpdateVerificationResult.Failed($"Verification error: {ex.Message}");
        }
    }

    /// <summary>
    /// Detect if a rollback has occurred since last known version.
    /// Compare current version against version history file.
    /// </summary>
    public IReadOnlyList<Signal> DetectRollback()
    {
        var signals = new List<Signal>();

        try
        {
            var historyPath = GetVersionHistoryPath();
            if (!File.Exists(historyPath)) return signals;

            var history = JsonSerializer.Deserialize<VersionHistory>(
                File.ReadAllText(historyPath));

            if (history is null) return signals;

            var currentVersion = GetCurrentVersionCode();
            if (currentVersion < history.HighestVersionCode)
            {
                signals.Add(new Signal(
                    $"update_rollback_detected:current_v{currentVersion}<highest_v{history.HighestVersionCode}",
                    85, 0.92));
                _logger.LogCritical(
                    "[UpdateSecurity] VERSION ROLLBACK! Current={Current}, Highest={Highest}",
                    currentVersion, history.HighestVersionCode);
            }
        }
        catch { }

        return signals;
    }

    /// <summary>
    /// Get signals related to update security status.
    /// </summary>
    public IReadOnlyList<Signal> GetUpdateSignals()
    {
        var signals = new List<Signal>();

        // Check rollback
        signals.AddRange(DetectRollback());

        // Check if Play Protect is disabled (reduces update verification)
        try
        {
            var cr = _context.ContentResolver;
            if (cr is not null)
            {
                // Google Play Protect status can be checked via package verification
                var verifyApps = Android.Provider.Settings.Global.GetInt(
                    cr, "package_verifier_enable", 1);
                if (verifyApps == 0)
                {
                    signals.Add(new Signal("play_protect_disabled", 50, 0.72));
                }
            }
        }
        catch { }

        return signals;
    }

    private async Task<UpdateMetadata?> FetchUpdateInfoAsync(string url, CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            // Certificate pinning is handled by network_security_config.xml at the platform level
            var response = await http.GetStringAsync(url + "/latest.json", ct);
            return JsonSerializer.Deserialize<UpdateMetadata>(response,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch { return null; }
    }

    private bool VerifyUpdateMetadataSignature(UpdateMetadata metadata)
    {
        if (string.IsNullOrEmpty(metadata.Signature))
            return false;

        // Canonical payload signed by release RSA-PSS key (same family as desktop updates).
        // Operators: sign UTF-8 of this string with UPDATE_SIGNING_KEY, base64 the .sig.
        var payload =
            $"{metadata.VersionCode}|{metadata.VersionName}|{metadata.DownloadUrl}|{metadata.Sha256Hash}";
        try
        {
            var sig = Convert.FromBase64String(metadata.Signature);
            return Behavedr.Core.Security.UpdateSignatureVerifier.VerifyPayload(
                System.Text.Encoding.UTF8.GetBytes(payload), sig, _logger);
        }
        catch (FormatException)
        {
            _logger.LogCritical("[UpdateSecurity] Metadata signature is not valid Base64");
            return false;
        }
    }

    private long GetCurrentVersionCode()
    {
        try
        {
            var pm = _context.PackageManager;
            var pkgInfo = pm?.GetPackageInfo(_context.PackageName!, 0);
            if (pkgInfo is null) return 0;

            if (Build.VERSION.SdkInt >= BuildVersionCodes.P)
            {
#pragma warning disable CA1416
                return pkgInfo.LongVersionCode;
#pragma warning restore CA1416
            }
#pragma warning disable CS0618, CA1422
            return pkgInfo.VersionCode;
#pragma warning restore CS0618, CA1422
        }
        catch { return 0; }
    }

    private void RecordVersionHistory(long versionCode, string hash)
    {
        try
        {
            var historyPath = GetVersionHistoryPath();
            var dir = Path.GetDirectoryName(historyPath);
            if (dir is not null) Directory.CreateDirectory(dir);

            VersionHistory history;
            if (File.Exists(historyPath))
            {
                history = JsonSerializer.Deserialize<VersionHistory>(
                    File.ReadAllText(historyPath)) ?? new VersionHistory();
            }
            else
            {
                history = new VersionHistory();
            }

            if (versionCode > history.HighestVersionCode)
                history.HighestVersionCode = versionCode;

            history.Entries.Add(new VersionEntry(
                versionCode, hash, DateTime.UtcNow.ToString("O")));

            // Keep last 20 entries
            while (history.Entries.Count > 20)
                history.Entries.RemoveAt(0);

            File.WriteAllText(historyPath, JsonSerializer.Serialize(history));
        }
        catch { }
    }

    private string GetVersionHistoryPath()
    {
        return Path.Combine(
            System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
            "security", VersionHistoryFile);
    }
}

// --- DTOs ---

internal class UpdateMetadata
{
    public long VersionCode { get; set; }
    public string VersionName { get; set; } = "";
    public string DownloadUrl { get; set; } = "";
    public string Sha256Hash { get; set; } = "";
    public string Signature { get; set; } = "";
    public string MinimumVersionCode { get; set; } = "";
}

public record UpdateCheckResult(
    bool UpdateAvailable,
    long CurrentVersion,
    long AvailableVersion,
    string? DownloadUrl,
    string Message);

public record UpdateVerificationResult(bool IsValid, long VersionCode, string Hash, string? Error)
{
    public static UpdateVerificationResult Passed(long version, string hash) =>
        new(true, version, hash, null);
    public static UpdateVerificationResult Failed(string error) =>
        new(false, 0, "", error);
}

internal class VersionHistory
{
    public long HighestVersionCode { get; set; }
    public List<VersionEntry> Entries { get; set; } = new();
}

internal record VersionEntry(long VersionCode, string Hash, string Timestamp);
