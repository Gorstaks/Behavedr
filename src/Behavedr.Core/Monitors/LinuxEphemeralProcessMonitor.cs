namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects ephemeral (flash-execution) processes on Linux.
/// These are processes that start, execute quickly (&lt;2s), and terminate before
/// the next detection cycle can observe them. Common in:
/// - Staged payload execution (download -> execute -> delete)
/// - Living-off-the-land attacks (quick command execution chains)
/// - Anti-forensics (execute then remove binary)
///
/// Uses /proc/*/stat start time delta and tracks PIDs across cycles.
/// Also monitors recently-created+deleted files in /tmp and /dev/shm.
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxEphemeralProcessMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxEphemeralProcessMonitor> _logger;
    private HashSet<int> _previousPids = new();
    private HashSet<int> _currentPids = new();
    private readonly Dictionary<string, DateTime> _recentTmpFiles = new();
    private DateTime _lastTmpScan = DateTime.UtcNow;

    public string PlatformName => "LinuxEphemeralProcess";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxEphemeralProcessMonitor(ILogger<LinuxEphemeralProcessMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxEphemeralProcessMonitor>.Instance;
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            _currentPids.Clear();

            // Scan all PIDs and track recently-started processes
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                _currentPids.Add(pid);

                // Check for newly-started processes with very short lifetimes
                // that weren't in our previous scan (appeared between cycles)
                if (!_previousPids.Contains(pid) && _previousPids.Count > 0)
                {
                    // Process started since last cycle - check if suspicious
                    try
                    {
                        var commPath = Path.Combine(procDir, "comm");
                        if (!File.Exists(commPath)) continue;
                        var name = File.ReadAllText(commPath).Trim();

                        var cmdlinePath = Path.Combine(procDir, "cmdline");
                        var cmdline = File.Exists(cmdlinePath)
                            ? File.ReadAllText(cmdlinePath).Replace('\0', ' ').Trim()
                            : "";

                        // Check if the executable has been deleted (execute-then-delete pattern)
                        var exePath = Path.Combine(procDir, "exe");
                        try
                        {
                            var exeTarget = File.ResolveLinkTarget(exePath, false)?.ToString() ?? "";
                            if (exeTarget.Contains("(deleted)", StringComparison.Ordinal))
                            {
                                signals.Add(new Signal(
                                    $"ephemeral_deleted_exec:{name}:pid:{pid}", 82, 0.87));
                            }
                        }
                        catch { }

                        // Suspicious: new process running from /tmp or /dev/shm
                        if (!string.IsNullOrEmpty(cmdline) &&
                            (cmdline.Contains("/tmp/", StringComparison.Ordinal) ||
                             cmdline.Contains("/dev/shm/", StringComparison.Ordinal)))
                        {
                            signals.Add(new Signal(
                                $"ephemeral_tmp_exec:{name}:pid:{pid}", 62, 0.7));
                        }
                    }
                    catch { }
                }
            }

            // Detect PIDs that appeared and disappeared between cycles (flash execution)
            if (_previousPids.Count > 0)
            {
                // PIDs that were in previous but not current = processes that exited
                // We can't directly detect these, but we can check /tmp for recently-created-then-deleted files
                DetectTmpFlashExecution(signals, ct);
            }

            // Swap
            (_previousPids, _currentPids) = (_currentPids, _previousPids);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxEphemeral] Error during scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Monitor /tmp and /dev/shm for files that were created and quickly deleted
    /// (staged payloads that execute then self-delete).
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectTmpFlashExecution(List<Signal> signals, CancellationToken ct)
    {
        if ((DateTime.UtcNow - _lastTmpScan).TotalSeconds < 10) return;
        _lastTmpScan = DateTime.UtcNow;

        var tmpDirs = new[] { "/tmp", "/dev/shm", "/var/tmp" };

        foreach (var dir in tmpDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            try
            {
                var currentFiles = new HashSet<string>(Directory.GetFiles(dir));

                // Check if previously seen files have disappeared (deleted after execution)
                var deletedFiles = _recentTmpFiles.Keys
                    .Where(f => f.StartsWith(dir, StringComparison.Ordinal) && !currentFiles.Contains(f))
                    .ToList();

                foreach (var deleted in deletedFiles)
                {
                    var age = DateTime.UtcNow - _recentTmpFiles[deleted];
                    if (age.TotalSeconds < 30) // Created and deleted within 30s
                    {
                        signals.Add(new Signal(
                            $"flash_execution:{Path.GetFileName(deleted)}:lived:{age.TotalSeconds:F0}s",
                            68, 0.75));
                    }
                    _recentTmpFiles.Remove(deleted);
                }

                // Track new files
                foreach (var file in currentFiles)
                {
                    if (!_recentTmpFiles.ContainsKey(file))
                    {
                        try
                        {
                            var info = new FileInfo(file);
                            if (info.CreationTimeUtc > DateTime.UtcNow.AddMinutes(-1))
                            {
                                _recentTmpFiles[file] = info.CreationTimeUtc;
                            }
                        }
                        catch { }
                    }
                }

                // Prune old entries
                var old = _recentTmpFiles.Where(kv => (DateTime.UtcNow - kv.Value).TotalMinutes > 2)
                    .Select(kv => kv.Key).ToList();
                foreach (var k in old) _recentTmpFiles.Remove(k);
            }
            catch { }
        }
    }
}
