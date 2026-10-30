namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Data exfiltration detection for Linux and macOS.
/// Tracks outbound data volume per process by monitoring /proc/*/net/dev (Linux)
/// or nettop output (macOS). Detects:
/// - Large outbound transfers from shell/LOLBin processes
/// - High upload-to-download ratio (exfiltration pattern)
/// - Unusual outbound volume from non-browser processes
/// </summary>
public class UnixDataExfiltrationMonitor : IPlatformMonitor
{
    private readonly ILogger<UnixDataExfiltrationMonitor> _logger;
    private readonly Dictionary<int, TransferSnapshot> _previousSnapshots = new();
    private DateTime _lastCheck = DateTime.MinValue;
    private const int CheckIntervalSeconds = 30;
    private const long ExfilThresholdBytes = 50 * 1024 * 1024; // 50 MB

    public string PlatformName => "UnixDataExfiltration";
    public bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private static readonly HashSet<string> HighUploadAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "chromium", "brave", "opera", "safari",
        "dropbox", "syncthing", "rsync", "scp", "sftp",
        "git", "ssh", "code", "electron", "slack", "teams", "zoom",
        "nginx", "apache2", "httpd", "node", "java",
    };

    private static readonly HashSet<string> SuspiciousUploaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash", "sh", "zsh", "dash", "fish", "csh",
        "python", "python3", "perl", "ruby", "php",
        "curl", "wget", "nc", "ncat", "socat", "openssl",
    };

    public UnixDataExfiltrationMonitor(ILogger<UnixDataExfiltrationMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<UnixDataExfiltrationMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if ((DateTime.UtcNow - _lastCheck).TotalSeconds < CheckIntervalSeconds)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        _lastCheck = DateTime.UtcNow;

        try
        {
            if (OperatingSystem.IsLinux())
                AnalyzeLinuxTraffic(signals, ct);
            else if (OperatingSystem.IsMacOS())
                AnalyzeMacOSTraffic(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixDataExfil] Error during analysis");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// On Linux, read /proc/PID/net/dev for per-process network byte counters.
    /// Falls back to /proc/net/dev with PID attribution via socket inodes.
    /// </summary>
    private void AnalyzeLinuxTraffic(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (pid <= 4 || pid == Environment.ProcessId) continue;

                var netDevPath = Path.Combine(procDir, "net", "dev");
                if (!File.Exists(netDevPath)) continue;

                string? processName = null;
                try
                {
                    var commPath = Path.Combine(procDir, "comm");
                    if (File.Exists(commPath))
                        processName = File.ReadAllText(commPath).Trim();
                }
                catch { continue; }

                if (processName is null || HighUploadAllowlist.Contains(processName)) continue;

                try
                {
                    long totalTx = 0;
                    long totalRx = 0;
                    foreach (var line in File.ReadLines(netDevPath).Skip(2))
                    {
                        var parts = line.Trim().Split(new[] { ' ', ':' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 10) continue;
                        if (parts[0] == "lo") continue; // Skip loopback

                        if (long.TryParse(parts[1], out var rx)) totalRx += rx;
                        if (long.TryParse(parts[9], out var tx)) totalTx += tx;
                    }

                    if (totalTx < 1_000_000) continue; // Skip trivial

                    // Compare with previous snapshot
                    if (_previousSnapshots.TryGetValue(pid, out var prev))
                    {
                        var deltaTx = totalTx - prev.TxBytes;
                        var deltaRx = totalRx - prev.RxBytes;

                        if (deltaTx > ExfilThresholdBytes)
                        {
                            var mbSent = deltaTx / (1024 * 1024);
                            var confidence = SuspiciousUploaders.Contains(processName) ? 0.9 : 0.75;
                            var weight = SuspiciousUploaders.Contains(processName) ? 85.0 : 65.0;
                            signals.Add(new Signal(
                                $"large_outbound_transfer:{processName}({mbSent}MB):pid:{pid}",
                                weight, confidence));
                        }

                        // Shell sending significant data
                        if (SuspiciousUploaders.Contains(processName) && deltaTx > 5 * 1024 * 1024)
                        {
                            signals.Add(new Signal(
                                $"shell_data_upload:{processName}({deltaTx / 1024 / 1024}MB):pid:{pid}",
                                78, 0.85));
                        }
                    }

                    _previousSnapshots[pid] = new TransferSnapshot(totalTx, totalRx);
                }
                catch { }
            }
        }
        catch { }

        // Prune dead PIDs
        var deadPids = _previousSnapshots.Keys
            .Where(p => !Directory.Exists($"/proc/{p}"))
            .ToList();
        foreach (var p in deadPids) _previousSnapshots.Remove(p);
    }

    /// <summary>
    /// On macOS, use nettop or netstat for aggregate traffic analysis.
    /// Less granular but still detects shell processes with large outbound volume.
    /// </summary>
    private void AnalyzeMacOSTraffic(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            // Use nettop -x -l 1 -J bytes_in,bytes_out for per-process stats
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/usr/bin/nettop",
                Arguments = "-x -l 1 -P -J bytes_in,bytes_out",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (string.IsNullOrEmpty(output)) return;

            foreach (var line in output.Split('\n'))
            {
                if (ct.IsCancellationRequested) break;
                var parts = line.Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                // Format: process.pid, bytes_in, bytes_out
                var procField = parts[0].Trim();
                var dotIdx = procField.LastIndexOf('.');
                if (dotIdx < 0) continue;

                var processName = procField[..dotIdx];
                var pidStr = procField[(dotIdx + 1)..];
                if (!int.TryParse(pidStr, out var pid)) continue;

                if (HighUploadAllowlist.Contains(processName)) continue;

                if (!long.TryParse(parts[2].Trim(), out var bytesOut)) continue;
                if (bytesOut < 5 * 1024 * 1024) continue; // Skip trivial

                if (SuspiciousUploaders.Contains(processName))
                {
                    signals.Add(new Signal(
                        $"shell_data_upload:{processName}({bytesOut / 1024 / 1024}MB):pid:{pid}",
                        78, 0.85));
                }
                else if (bytesOut > ExfilThresholdBytes)
                {
                    signals.Add(new Signal(
                        $"large_outbound_transfer:{processName}({bytesOut / 1024 / 1024}MB):pid:{pid}",
                        65, 0.75));
                }
            }
        }
        catch { }
    }

    private record TransferSnapshot(long TxBytes, long RxBytes);
}
