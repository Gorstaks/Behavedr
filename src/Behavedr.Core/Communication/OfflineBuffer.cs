namespace Behavedr.Core.Communication;

using System.Text.Json;
using Behavedr.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Buffers detection reports locally when the server is unreachable.
/// Uses a simple file-based queue in the agent's data directory.
/// On reconnection, queued reports are replayed in order.
/// </summary>
public class OfflineBuffer
{
    private readonly string _bufferPath;
    private readonly ILogger<OfflineBuffer> _logger;
    private readonly int _maxBufferedReports;

    public OfflineBuffer(string? bufferPath = null, int maxBufferedReports = 1000, ILogger<OfflineBuffer>? logger = null)
    {
        _bufferPath = bufferPath ?? Path.Combine(AppContext.BaseDirectory, "buffer");
        _maxBufferedReports = maxBufferedReports;
        _logger = logger ?? NullLogger<OfflineBuffer>.Instance;

        Directory.CreateDirectory(_bufferPath);
    }

    /// <summary>Number of buffered reports waiting to be sent.</summary>
    public int PendingCount => Directory.Exists(_bufferPath)
        ? Directory.GetFiles(_bufferPath, "*.enc").Length
        : 0;

    /// <summary>
    /// Enqueue a report for later delivery. Report is encrypted at rest using AES-256-GCM.
    /// </summary>
    public async Task EnqueueAsync(DetectionReport report, CancellationToken ct = default)
    {
        // Enforce max buffer size
        if (PendingCount >= _maxBufferedReports)
        {
            _logger.LogWarning("Offline buffer full ({Max} reports), dropping oldest", _maxBufferedReports);
            DropOldest();
        }

        var fileName = $"{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}_{Guid.NewGuid():N}.enc";
        var filePath = Path.Combine(_bufferPath, fileName);

        var json = JsonSerializer.Serialize(report, BufferJsonOptions);

        // Encrypt the report before writing to disk
        var envelope = SecureEnvelope.SealString(json, "offline-buffer");
        await File.WriteAllTextAsync(filePath, envelope, ct);

        _logger.LogDebug("Buffered report for {Process} (score={Score:F1})",
            report.Event.ProcessName, report.Score);
    }

    /// <summary>
    /// Replay all buffered reports through the client.
    /// Reports are decrypted, sent in chronological order, and removed on successful delivery.
    /// 
    /// V-5 DOCUMENTED: Reports retain their original sequence numbers from when they were created.
    /// On replay, the server will see gaps in the sequence (other reports may have been sent
    /// between creation and replay). The server's replay detection must account for offline
    /// buffer gaps - it should accept out-of-order sequence numbers within a boot nonce session
    /// and only reject duplicate nonces, not sequence gaps.
    /// </summary>
    public async Task<int> ReplayAsync(IBehavedrClient client, CancellationToken ct = default)
    {
        if (!Directory.Exists(_bufferPath)) return 0;

        var files = Directory.GetFiles(_bufferPath, "*.enc")
            .OrderBy(f => f) // Filename starts with timestamp, so alphabetical = chronological
            .ToList();

        if (files.Count == 0) return 0;

        _logger.LogInformation("Replaying {Count} buffered reports", files.Count);

        var sentCount = 0;
        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                var envelope = await File.ReadAllTextAsync(file, ct);

                // Decrypt and verify authenticity
                var json = SecureEnvelope.UnsealString(envelope, "offline-buffer");
                if (json is null)
                {
                    _logger.LogCritical("SECURITY: Buffered report {File} failed decryption - tampered or corrupted, moving to dead-letter",
                        Path.GetFileName(file));
                    MoveToDeadLetter(file);
                    continue;
                }

                var report = JsonSerializer.Deserialize<DetectionReport>(json, BufferJsonOptions);

                if (report is null)
                {
                    File.Delete(file);
                    continue;
                }

                await client.ReportDetectionAsync(report, ct);
                File.Delete(file);
                sentCount++;
            }
            catch (HttpRequestException)
            {
                // Server still unreachable - stop replay
                _logger.LogDebug("Replay stopped: server unreachable after {Sent} reports", sentCount);
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to replay buffered report {File}", Path.GetFileName(file));
                MoveToDeadLetter(file);
            }
        }

        if (sentCount > 0)
            _logger.LogInformation("Replayed {Count} buffered reports successfully", sentCount);

        return sentCount;
    }

    private void DropOldest()
    {
        try
        {
            var oldest = Directory.GetFiles(_bufferPath, "*.enc")
                .OrderBy(f => f)
                .FirstOrDefault();

            if (oldest is not null)
                File.Delete(oldest);
        }
        catch { }
    }

    private void MoveToDeadLetter(string filePath)
    {
        try
        {
            var deadLetterDir = Path.Combine(_bufferPath, "dead-letter");
            Directory.CreateDirectory(deadLetterDir);
            var dest = Path.Combine(deadLetterDir, Path.GetFileName(filePath));
            File.Move(filePath, dest, overwrite: true);
        }
        catch { }
    }

    /// <summary>
    /// RT-8 FIX: Clean up dead-letter files older than the retention period.
    /// Prevents unbounded disk usage from tampered/corrupted reports accumulating.
    /// Also enforces restrictive permissions on the dead-letter directory.
    /// </summary>
    public void CleanupDeadLetters(TimeSpan? maxAge = null)
    {
        var retention = maxAge ?? TimeSpan.FromDays(7);
        var deadLetterDir = Path.Combine(_bufferPath, "dead-letter");

        if (!Directory.Exists(deadLetterDir)) return;

        // Enforce restrictive permissions on dead-letter directory
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(deadLetterDir,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }
        catch { }

        try
        {
            var cutoff = DateTime.UtcNow - retention;
            foreach (var file in Directory.GetFiles(deadLetterDir))
            {
                try
                {
                    if (File.GetCreationTimeUtc(file) < cutoff)
                    {
                        File.Delete(file);
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static readonly JsonSerializerOptions BufferJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };
}
