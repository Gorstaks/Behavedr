namespace Behavedr.Core.Update;

using System.IO.Compression;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Auto-update mechanism using GitHub Releases API.
/// Downloads platform packages, verifies RSA-PSS signatures (and optional SHA-256
/// manifests), stages binaries with a rollback point, and supports health-check
/// driven rollback on the subsequent process start.
/// </summary>
public class AutoUpdater
{
    /// <summary>Marker written after a successful stage; cleared after healthy startup or rollback.</summary>
    public const string PendingUpdateMarkerFileName = ".update-pending";

    /// <summary>Directory holding previous binaries for rollback.</summary>
    public const string PreviousDirectoryName = ".previous";

    /// <summary>Staging directory used during extraction.</summary>
    public const string StagingDirectoryName = ".update-staging";

    private readonly HttpClient _http;
    private readonly ILogger<AutoUpdater> _logger;
    private readonly string _currentVersion;
    private readonly string _repoOwner;
    private readonly string _repoName;
    private readonly string _platform;

    public AutoUpdater(
        string repoOwner = "CroatiaSecurity",
        string repoName = "Behavedr",
        ILogger<AutoUpdater>? logger = null)
    {
        _repoOwner = repoOwner;
        _repoName = repoName;
        _logger = logger ?? NullLogger<AutoUpdater>.Instance;
        _currentVersion = Assembly.GetEntryAssembly()
            ?.GetName().Version?.ToString(3) ?? "0.0.0";
        _platform = GetPlatformRid();

        // RT-5 FIX: Pin TLS to 1.2+ and prefer 1.3 for update downloads.
        var handler = new HttpClientHandler
        {
            SslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12,
        };
        _http = new HttpClient(handler);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"Behavedr/{_currentVersion}");
    }

    /// <summary>Current agent version used for anti-downgrade comparisons.</summary>
    public string CurrentVersion => _currentVersion;

    /// <summary>
    /// Check GitHub Releases for a newer version.
    /// </summary>
    public async Task<UpdateInfo?> CheckForUpdateAsync(CancellationToken ct = default)
    {
        try
        {
            var url = $"https://api.github.com/repos/{_repoOwner}/{_repoName}/releases/latest";
            var response = await _http.GetAsync(url, ct);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogDebug("Update check returned {Status}", response.StatusCode);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var tagName = root.GetProperty("tag_name").GetString() ?? "";
            var latestVersion = tagName.TrimStart('v');

            if (!IsNewerVersion(latestVersion, _currentVersion))
            {
                _logger.LogDebug("Current version {Current} is up-to-date (latest: {Latest})",
                    _currentVersion, latestVersion);
                return null;
            }

            var assetUrl = FindPlatformAsset(root);
            if (assetUrl is null)
            {
                _logger.LogWarning("No update asset found for platform {Platform}", _platform);
                return null;
            }

            var checksumsUrl = FindAssetUrl(root, "SHA256SUMS");
            return new UpdateInfo(latestVersion, assetUrl, tagName, checksumsUrl);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Update check failed");
            return null;
        }
    }

    /// <summary>
    /// Download and apply an update. Verifies RSA-PSS signature (and SHA-256
    /// when a release SHA256SUMS is published) before extraction.
    /// </summary>
    public async Task<bool> ApplyUpdateAsync(UpdateInfo update, CancellationToken ct = default)
    {
        _logger.LogInformation("Downloading update v{Version} from {Url}",
            update.Version, update.DownloadUrl);

        try
        {
            if (!IsNewerVersion(update.Version, _currentVersion))
            {
                _logger.LogCritical(
                    "SECURITY: Rejecting update v{Version} - not newer than current {Current} (anti-downgrade)",
                    update.Version, _currentVersion);
                return false;
            }

            var tempPath = Path.Combine(Path.GetTempPath(), $"behavedr-update-{update.Version}.zip");
            var sigPath = tempPath + ".sig";

            await using (var fileStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            await using (var responseStream = await _http.GetStreamAsync(update.DownloadUrl, ct))
            {
                await responseStream.CopyToAsync(fileStream, ct);
            }

            _logger.LogInformation("Downloaded update to {Path}", tempPath);

            var sigUrl = update.DownloadUrl + ".sig";
            try
            {
                await using (var sigFileStream = new FileStream(sigPath, FileMode.Create, FileAccess.Write, FileShare.None))
                await using (var sigStream = await _http.GetStreamAsync(sigUrl, ct))
                {
                    await sigStream.CopyToAsync(sigFileStream, ct);
                }
            }
            catch (HttpRequestException)
            {
                _logger.LogCritical("SECURITY: No signature file available for update - rejecting");
                Telemetry.SecurityTelemetry.ReportSignatureFailure();
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            var fileInfo = new FileInfo(tempPath);
            if (fileInfo.Length < 1_000_000)
            {
                _logger.LogWarning("Downloaded file suspiciously small ({Size} bytes), aborting",
                    fileInfo.Length);
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            if (Security.UpdateSignatureVerifier.IsProductionKeyConfigured())
            {
                if (!Security.UpdateSignatureVerifier.VerifySignature(tempPath, sigPath, _logger))
                {
                    _logger.LogCritical("SECURITY: Update signature verification FAILED - aborting update");
                    CleanupTempFiles(tempPath, sigPath);
                    return false;
                }
            }
            else
            {
                _logger.LogWarning("Update signing key is not configured (development mode) - skipping signature verification");
            }

            var hash = ComputeHash(tempPath);
            _logger.LogInformation("Update SHA-256: {Hash}", hash[..16] + "...");

            // Optional second factor: published SHA256SUMS (signed separately on release).
            if (!string.IsNullOrEmpty(update.ChecksumsUrl))
            {
                if (!await VerifyAgainstChecksumManifestAsync(update.ChecksumsUrl, update.DownloadUrl, hash, ct))
                {
                    _logger.LogCritical("SECURITY: SHA-256 does not match published SHA256SUMS - aborting update");
                    CleanupTempFiles(tempPath, sigPath);
                    return false;
                }
            }

            var currentExe = Environment.ProcessPath;
            if (currentExe is null)
            {
                _logger.LogError("Cannot determine current executable path");
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            var targetDir = Path.GetFullPath(Path.GetDirectoryName(currentExe)!);
            var stagingDir = Path.Combine(targetDir, StagingDirectoryName);
            var previousDir = Path.Combine(targetDir, PreviousDirectoryName);

            if (Directory.Exists(stagingDir))
                Directory.Delete(stagingDir, recursive: true);
            Directory.CreateDirectory(stagingDir);

            if (!ExtractZipSafely(tempPath, stagingDir, _logger))
            {
                if (Directory.Exists(stagingDir))
                    Directory.Delete(stagingDir, recursive: true);
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            var stagedExe = Path.Combine(stagingDir, Path.GetFileName(currentExe));
            if (!File.Exists(stagedExe))
            {
                stagedExe = Directory.GetFiles(stagingDir, "Behavedr*").FirstOrDefault() ?? "";
            }

            if (!File.Exists(stagedExe))
            {
                _logger.LogError("Staged update does not contain expected binary");
                Directory.Delete(stagingDir, recursive: true);
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            if (Directory.Exists(previousDir))
                Directory.Delete(previousDir, recursive: true);
            Directory.CreateDirectory(previousDir);

            foreach (var file in Directory.GetFiles(targetDir))
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".dll" or ".exe" or ".json" or "" or ".so" or ".dylib")
                {
                    var backupDest = Path.Combine(previousDir, Path.GetFileName(file));
                    try { File.Copy(file, backupDest, overwrite: true); }
                    catch { /* locked files are skipped; partial backup still aids recovery */ }
                }
            }

            foreach (var file in Directory.GetFiles(stagingDir, "*", SearchOption.AllDirectories))
            {
                var relativePath = Path.GetRelativePath(stagingDir, file);
                var finalPath = Path.Combine(targetDir, relativePath);
                var finalDir = Path.GetDirectoryName(finalPath)!;
                Directory.CreateDirectory(finalDir);

                try
                {
                    File.Move(file, finalPath, overwrite: true);
                }
                catch (IOException)
                {
                    var bakPath = finalPath + ".bak";
                    try { File.Move(finalPath, bakPath, overwrite: true); } catch { }
                    File.Move(file, finalPath, overwrite: true);
                }
            }

            try { Directory.Delete(stagingDir, recursive: true); } catch { }

            // Health-check rollback contract: next healthy startup clears this marker.
            WritePendingUpdateMarker(targetDir, update.Version);

            _logger.LogInformation(
                "Update v{Version} staged successfully. Previous version backed up to {Previous}/. " +
                "Marker {Marker} written for health-check rollback. Restart the agent to complete the update.",
                update.Version, PreviousDirectoryName, PendingUpdateMarkerFileName);

            CleanupTempFiles(tempPath, sigPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply update");
            return false;
        }
    }

    /// <summary>
    /// If a pending-update marker exists and <paramref name="isHealthy"/> returns false,
    /// restore binaries from <see cref="PreviousDirectoryName"/> and clear the marker.
    /// If healthy, clear the marker and leave the new binaries in place.
    /// </summary>
    /// <returns>
    /// <c>true</c> if a rollback was performed; <c>false</c> if no marker, healthy clear, or rollback unavailable.
    /// </returns>
    public static bool TryHealthCheckRollback(Func<bool> isHealthy, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        var currentExe = Environment.ProcessPath;
        if (currentExe is null)
            return false;

        var targetDir = Path.GetFullPath(Path.GetDirectoryName(currentExe)!);
        var markerPath = Path.Combine(targetDir, PendingUpdateMarkerFileName);
        if (!File.Exists(markerPath))
            return false;

        string pendingVersion = "(unknown)";
        try { pendingVersion = File.ReadAllText(markerPath).Trim(); } catch { }

        bool healthy;
        try
        {
            healthy = isHealthy();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Health check threw after pending update v{Version} - treating as unhealthy", pendingVersion);
            healthy = false;
        }

        if (healthy)
        {
            try { File.Delete(markerPath); } catch { }
            logger.LogInformation(
                "Post-update health check PASSED for v{Version} - pending marker cleared",
                pendingVersion);
            return false;
        }

        var previousDir = Path.Combine(targetDir, PreviousDirectoryName);
        if (!Directory.Exists(previousDir))
        {
            logger.LogCritical(
                "SECURITY: Post-update health check FAILED for v{Version} but no {Previous} directory exists - cannot auto-rollback",
                pendingVersion, PreviousDirectoryName);
            return false;
        }

        logger.LogCritical(
            "SECURITY: Post-update health check FAILED for v{Version} - restoring binaries from {Previous}",
            pendingVersion, PreviousDirectoryName);

        try
        {
            foreach (var file in Directory.GetFiles(previousDir))
            {
                var dest = Path.Combine(targetDir, Path.GetFileName(file));
                try
                {
                    File.Copy(file, dest, overwrite: true);
                }
                catch (IOException)
                {
                    // Windows may lock the running image; leave .previous for manual recovery.
                    logger.LogWarning("Could not restore {File} (locked) - manual recovery from {Previous} may be required",
                        Path.GetFileName(file), PreviousDirectoryName);
                }
            }

            try { File.Delete(markerPath); } catch { }
            logger.LogWarning(
                "Rollback from failed update v{Version} completed. Restart the agent to run the restored binary.",
                pendingVersion);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Rollback after failed update v{Version} encountered errors", pendingVersion);
            return false;
        }
    }

    /// <summary>
    /// Extract a zip into <paramref name="stagingDir"/> with Zip Slip rejection.
    /// Returns false if any entry escapes the staging root or extraction fails.
    /// </summary>
    public static bool ExtractZipSafely(string zipPath, string stagingDir, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;
        stagingDir = Path.GetFullPath(stagingDir);

        try
        {
            using var archive = ZipFile.OpenRead(zipPath);
            foreach (var entry in archive.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name))
                    continue;

                if (!TryResolveZipEntryPath(stagingDir, entry.FullName, out var destPath))
                {
                    logger.LogCritical(
                        "SECURITY: Zip Slip detected - entry '{Entry}' resolves outside target directory. Aborting update.",
                        entry.FullName);
                    return false;
                }

                var destDir = Path.GetDirectoryName(destPath)!;
                Directory.CreateDirectory(destDir);
                entry.ExtractToFile(destPath, overwrite: true);
            }

            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Zip extraction failed");
            return false;
        }
    }

    /// <summary>
    /// Resolve a zip entry path under <paramref name="stagingDir"/>. Returns false on Zip Slip.
    /// </summary>
    public static bool TryResolveZipEntryPath(string stagingDir, string entryFullName, out string destPath)
    {
        destPath = string.Empty;
        stagingDir = Path.GetFullPath(stagingDir);

        // Normalize entry path separators before combine
        var normalizedEntry = entryFullName.Replace('/', Path.DirectorySeparatorChar)
            .Replace('\\', Path.DirectorySeparatorChar);

        try
        {
            destPath = Path.GetFullPath(Path.Combine(stagingDir, normalizedEntry));
        }
        catch
        {
            return false;
        }

        var root = stagingDir.EndsWith(Path.DirectorySeparatorChar)
            ? stagingDir
            : stagingDir + Path.DirectorySeparatorChar;

        // OrdinalIgnoreCase: Windows paths are case-insensitive; Unix remains safe (case-sensitive FS still OK).
        if (!destPath.StartsWith(root, StringComparison.OrdinalIgnoreCase) &&
            !destPath.Equals(stagingDir, StringComparison.OrdinalIgnoreCase))
        {
            destPath = string.Empty;
            return false;
        }

        return true;
    }

    /// <summary>Compare dotted version strings; true when latest is strictly greater than current.</summary>
    public static bool IsNewerVersion(string latest, string current)
    {
        if (Version.TryParse(latest, out var latestVer) &&
            Version.TryParse(current, out var currentVer))
        {
            return latestVer > currentVer;
        }
        return false;
    }

    public static void WritePendingUpdateMarker(string targetDir, string version)
    {
        var markerPath = Path.Combine(targetDir, PendingUpdateMarkerFileName);
        File.WriteAllText(markerPath, version + Environment.NewLine);
    }

    private async Task<bool> VerifyAgainstChecksumManifestAsync(
        string checksumsUrl,
        string downloadUrl,
        string actualHashHex,
        CancellationToken ct)
    {
        try
        {
            var text = await _http.GetStringAsync(checksumsUrl, ct);
            var assetName = Path.GetFileName(new Uri(downloadUrl).AbsolutePath);
            if (string.IsNullOrEmpty(assetName))
                return false;

            foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                // Formats: "hash  filename" or "hash *filename"
                var trimmed = line.Trim();
                if (trimmed.StartsWith('#'))
                    continue;

                var parts = trimmed.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2)
                    continue;

                var listedHash = parts[0];
                var listedName = parts[^1].TrimStart('*');
                if (!listedName.Equals(assetName, StringComparison.OrdinalIgnoreCase) &&
                    !listedName.EndsWith(assetName, StringComparison.OrdinalIgnoreCase))
                    continue;

                var match = string.Equals(listedHash, actualHashHex, StringComparison.OrdinalIgnoreCase);
                if (match)
                    _logger.LogInformation("SHA-256 matches published SHA256SUMS for {Asset}", assetName);
                else
                    _logger.LogCritical(
                        "SECURITY: SHA-256 mismatch for {Asset}: expected {Expected}, got {Actual}",
                        assetName, listedHash, actualHashHex);
                return match;
            }

            _logger.LogWarning("Asset {Asset} not listed in SHA256SUMS - treating as soft failure (signature still required)", assetName);
            return true; // signature remains the hard gate; missing line is not fatal
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not download or parse SHA256SUMS - continuing with signature-only verification");
            return true;
        }
    }

    private static void CleanupTempFiles(params string[] paths)
    {
        foreach (var path in paths)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
    }

    private string? FindPlatformAsset(JsonElement root)
    {
        if (!root.TryGetProperty("assets", out var assets))
            return null;

        foreach (var asset in assets.EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? "";
            if (name.Contains(_platform, StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                return asset.GetProperty("browser_download_url").GetString();
            }
        }

        return null;
    }

    private static string? FindAssetUrl(JsonElement root, string exactName)
    {
        if (!root.TryGetProperty("assets", out var assets))
            return null;

        foreach (var asset in assets.EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? "";
            if (name.Equals(exactName, StringComparison.OrdinalIgnoreCase))
                return asset.GetProperty("browser_download_url").GetString();
        }

        return null;
    }

    private static string ComputeHash(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash);
    }

    private static string GetPlatformRid()
    {
        if (OperatingSystem.IsWindows()) return "win-x64";
        if (OperatingSystem.IsLinux()) return "linux-x64";
        if (OperatingSystem.IsMacOS()) return "osx-arm64";
        return "unknown";
    }
}

/// <summary>
/// Information about an available update.
/// </summary>
/// <param name="Version">Semantic version string without leading 'v'.</param>
/// <param name="DownloadUrl">Browser download URL for the platform zip.</param>
/// <param name="TagName">Git tag (e.g. v0.2.4).</param>
/// <param name="ChecksumsUrl">Optional URL of release SHA256SUMS manifest.</param>
public record UpdateInfo(
    string Version,
    string DownloadUrl,
    string TagName,
    string? ChecksumsUrl = null);
