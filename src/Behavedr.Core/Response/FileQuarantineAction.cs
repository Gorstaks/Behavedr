namespace Behavedr.Core.Response;

using System.Security.Cryptography;
using System.Text.Json;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Response action that quarantines suspicious files.
/// Moves them to a restricted quarantine directory and logs metadata for potential restore.
/// </summary>
public class FileQuarantineAction : IResponseAction
{
    private readonly ILogger<FileQuarantineAction> _logger;
    private readonly string _quarantinePath;

    public FileQuarantineAction(string? quarantinePath = null, ILogger<FileQuarantineAction>? logger = null)
    {
        _quarantinePath = quarantinePath ?? Path.Combine(AppContext.BaseDirectory, "quarantine");
        _logger = logger ?? NullLogger<FileQuarantineAction>.Instance;
    }

    public string Name => "FileQuarantine";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        // Extract file paths from signals that reference files
        var filePaths = ExtractFilePaths(result);

        if (filePaths.Count == 0)
        {
            return ResponseOutcome.Skipped(Name, "No file paths in detection signals");
        }

        var quarantinedCount = 0;
        var errors = new List<string>();

        foreach (var filePath in filePaths)
        {
            if (ct.IsCancellationRequested) break;

            if (ResponseSafety.ShouldRefuseQuarantine(filePath, out var refuse))
            {
                _logger.LogWarning("Refusing quarantine {File}: {Reason}", filePath, refuse);
                errors.Add($"{filePath}: safety:{refuse}");
                continue;
            }

            try
            {
                var outcome = await QuarantineFileAsync(filePath, result, ct);
                if (outcome)
                    quarantinedCount++;
            }
            catch (Exception ex)
            {
                errors.Add($"{filePath}: {ex.Message}");
                _logger.LogError(ex, "Failed to quarantine {File}", filePath);
            }
        }

        if (quarantinedCount > 0)
        {
            return ResponseOutcome.Ok(Name,
                $"Quarantined {quarantinedCount} file(s)" +
                (errors.Count > 0 ? $", {errors.Count} failed" : ""));
        }

        if (errors.Count > 0)
        {
            return ResponseOutcome.Failed(Name, string.Join("; ", errors));
        }

        return ResponseOutcome.Skipped(Name, "No files found to quarantine");
    }

    private async Task<bool> QuarantineFileAsync(string filePath, DetectionResult result, CancellationToken ct)
    {
        if (!File.Exists(filePath))
        {
            _logger.LogDebug("File not found for quarantine: {File}", filePath);
            return false;
        }

        // Ensure quarantine directory exists
        Directory.CreateDirectory(_quarantinePath);

        // Generate unique quarantine name
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var hash = ComputeFileHash(filePath);
        var quarantineName = $"{timestamp}_{Path.GetFileName(filePath)}_{hash[..8]}.quarantined";
        var quarantineDest = Path.Combine(_quarantinePath, quarantineName);

        // Write metadata for potential restore
        var metadata = new QuarantineMetadata
        {
            OriginalPath = filePath,
            QuarantinedAt = DateTime.UtcNow,
            Sha256 = hash,
            DetectionScore = result.Score,
            DetectionSignals = result.Signals.Select(s => s.Type).ToList(),
            ProcessName = result.Event.ProcessName,
            ProcessId = result.Event.ProcessId,
        };

        var metadataPath = quarantineDest + ".meta.json";
        var metadataJson = JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(metadataPath, metadataJson, ct);

        // Move the file to quarantine
        File.Move(filePath, quarantineDest);

        _logger.LogWarning("QUARANTINED: {OriginalPath} -> {QuarantinePath} (SHA-256: {Hash})",
            filePath, quarantineDest, hash[..16] + "...");

        return true;
    }

    /// <summary>
    /// Extract file paths from detection signals.
    /// Signals containing "executable_in_tmp:", "suspicious_file:", etc. may reference file paths.
    /// SECURITY: Validates paths to prevent path traversal attacks.
    /// </summary>
    private static List<string> ExtractFilePaths(DetectionResult result)
    {
        var paths = new List<string>();

        foreach (var signal in result.Signals)
        {
            // Signals that reference file paths (from Linux monitor's /tmp detection)
            if (signal.Type.StartsWith("executable_in_tmp:", StringComparison.Ordinal))
            {
                var fileName = signal.Type["executable_in_tmp:".Length..];

                // SECURITY: Reject path traversal attempts
                if (!IsValidFileName(fileName))
                    continue;

                // Try common tmp directories
                foreach (var dir in new[] { "/tmp", "/var/tmp", "/dev/shm" })
                {
                    var fullPath = Path.Combine(dir, fileName);

                    // SECURITY: Verify resolved path is still under expected directory
                    var resolvedPath = Path.GetFullPath(fullPath);
                    if (!resolvedPath.StartsWith(dir, StringComparison.Ordinal))
                        continue; // Path traversal detected - skip

                    if (File.Exists(resolvedPath))
                    {
                        paths.Add(resolvedPath);
                        break;
                    }
                }
            }
        }

        return paths;
    }

    /// <summary>
    /// Validates that a filename doesn't contain path traversal or dangerous characters.
    /// </summary>
    private static bool IsValidFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return false;

        // Reject path separators and traversal
        if (fileName.Contains("..") ||
            fileName.Contains('/') ||
            fileName.Contains('\\') ||
            fileName.Contains('\0'))
            return false;

        // Reject if it contains any invalid path characters
        var invalidChars = Path.GetInvalidFileNameChars();
        if (fileName.Any(c => invalidChars.Contains(c)))
            return false;

        return true;
    }

    private static string ComputeFileHash(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hashBytes = SHA256.HashData(stream);
        return Convert.ToHexString(hashBytes);
    }

    private record QuarantineMetadata
    {
        public required string OriginalPath { get; init; }
        public required DateTime QuarantinedAt { get; init; }
        public required string Sha256 { get; init; }
        public required double DetectionScore { get; init; }
        public required List<string> DetectionSignals { get; init; }
        public required string ProcessName { get; init; }
        public required string ProcessId { get; init; }
    }
}
