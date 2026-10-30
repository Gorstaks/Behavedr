namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects "ghost" processes on Linux/macOS - PIDs with active network connections
/// whose process info cannot be resolved or whose binary has been deleted from disk.
/// Catches: process hollowing, fileless malware, orphaned RAT sockets, deleted-binary backdoors.
///
/// On Linux: cross-references /proc/net/tcp with /proc/*/exe (deleted indicator).
/// On macOS: uses lsof to find connections from dead/zombie processes.
/// </summary>
public class UnixGhostProcessMonitor : IPlatformMonitor
{
    private readonly ILogger<UnixGhostProcessMonitor> _logger;
    private readonly HashSet<int> _alertedPids = new();

    public string PlatformName => "UnixGhostProcess";
    public bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public UnixGhostProcessMonitor(ILogger<UnixGhostProcessMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<UnixGhostProcessMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            if (OperatingSystem.IsLinux())
                DetectLinuxGhosts(signals, ct);
            else if (OperatingSystem.IsMacOS())
                DetectMacOSGhosts(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixGhostProcess] Error during ghost scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// On Linux: find processes with network connections whose /proc/PID/exe
    /// points to "(deleted)" - binary was removed from disk while running.
    /// This is a classic fileless malware pattern.
    /// </summary>
    private void DetectLinuxGhosts(List<Signal> signals, CancellationToken ct)
    {
        // Get PIDs with established connections from /proc/net/tcp
        var connectedPids = GetLinuxConnectedPids(ct);

        foreach (var pid in connectedPids)
        {
            if (ct.IsCancellationRequested) break;
            if (pid <= 4 || pid == Environment.ProcessId) continue;
            if (_alertedPids.Contains(pid)) continue;

            var exePath = $"/proc/{pid}/exe";
            try
            {
                // Check if the exe link resolves
                var target = File.ResolveLinkTarget(exePath, false)?.ToString() ?? "";

                // Binary deleted from disk while process runs (fileless malware)
                if (target.Contains("(deleted)", StringComparison.Ordinal))
                {
                    _alertedPids.Add(pid);
                    var procName = GetProcessName(pid) ?? "unknown";
                    signals.Add(new Signal(
                        $"ghost_process_deleted_binary:{procName}:pid:{pid}", 88, 0.92));
                    _logger.LogWarning(
                        "[GhostProcess] Deleted-binary process with network connection: {Name} PID {Pid}",
                        procName, pid);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Can't read exe link but process has connections - suspicious
                // Only alert if we also can't read comm (truly hidden process)
                var commPath = $"/proc/{pid}/comm";
                if (!File.Exists(commPath))
                {
                    _alertedPids.Add(pid);
                    signals.Add(new Signal(
                        $"ghost_process_unresolvable:pid:{pid}", 82, 0.85));
                }
            }
            catch { }
        }

        // Also check for memfd-based processes (fileless execution)
        DetectMemfdProcesses(signals, ct);

        // Prune alerted PIDs for dead processes
        _alertedPids.RemoveWhere(p => !Directory.Exists($"/proc/{p}"));
    }

    private void DetectMemfdProcesses(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (pid <= 4 || _alertedPids.Contains(pid)) continue;

                try
                {
                    var exeLink = File.ResolveLinkTarget(Path.Combine(procDir, "exe"), false)?.ToString() ?? "";
                    if (exeLink.Contains("memfd:", StringComparison.Ordinal))
                    {
                        _alertedPids.Add(pid);
                        var procName = GetProcessName(pid) ?? "unknown";
                        signals.Add(new Signal(
                            $"memfd_execution:{procName}:pid:{pid}", 90, 0.93));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// On macOS: use lsof to find processes with connections that can't be resolved.
    /// </summary>
    private void DetectMacOSGhosts(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/usr/sbin/lsof",
                Arguments = "-i -n -P",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            foreach (var line in output.Split('\n'))
            {
                if (ct.IsCancellationRequested) break;
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                if (!int.TryParse(parts[1], out var pid)) continue;
                if (pid <= 1 || _alertedPids.Contains(pid)) continue;

                // Check if process still exists
                try
                {
                    Process.GetProcessById(pid).Dispose();
                }
                catch (ArgumentException)
                {
                    // Process doesn't exist but has connections = ghost
                    _alertedPids.Add(pid);
                    signals.Add(new Signal(
                        $"ghost_process_dead_socket:pid:{pid}", 80, 0.85));
                }
            }
        }
        catch { }
    }

    private HashSet<int> GetLinuxConnectedPids(CancellationToken ct)
    {
        var pids = new HashSet<int>();
        // Build inode->PID map then cross-reference with /proc/net/tcp
        var inodeToPid = new Dictionary<long, int>();

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                var fdDir = Path.Combine(procDir, "fd");
                if (!Directory.Exists(fdDir)) continue;

                try
                {
                    foreach (var fdPath in Directory.GetFiles(fdDir))
                    {
                        try
                        {
                            var target = File.ResolveLinkTarget(fdPath, false)?.ToString() ?? "";
                            if (target.StartsWith("socket:[", StringComparison.Ordinal))
                            {
                                var inodeStr = target["socket:[".Length..^1];
                                if (long.TryParse(inodeStr, out var inode))
                                    inodeToPid.TryAdd(inode, pid);
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }

        // Read /proc/net/tcp for ESTABLISHED connections and resolve PIDs
        if (File.Exists("/proc/net/tcp"))
        {
            try
            {
                foreach (var line in File.ReadLines("/proc/net/tcp").Skip(1))
                {
                    var parts = line.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 10) continue;
                    // State 01 = ESTABLISHED
                    if (parts[3] != "01") continue;
                    if (long.TryParse(parts[9], out var inode) && inodeToPid.TryGetValue(inode, out var pid))
                        pids.Add(pid);
                }
            }
            catch { }
        }

        return pids;
    }

    private static string? GetProcessName(int pid)
    {
        try
        {
            var commPath = $"/proc/{pid}/comm";
            return File.Exists(commPath) ? File.ReadAllText(commPath).Trim() : null;
        }
        catch { return null; }
    }
}
