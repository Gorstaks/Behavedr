namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Security.Cryptography;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Anti-tamper guard for Linux and macOS providing self-protection against:
/// 1. Binary integrity verification (detect on-disk replacement)
/// 2. Process suspension detection via monotonic clock timing gaps
/// 3. Service health monitoring (systemd on Linux, launchd on macOS)
/// 4. Config file tampering detection
/// 5. Log file deletion/truncation detection
/// 6. Debugger attachment detection (/proc/self/status TracerPid on Linux)
///
/// Equivalent to Windows AntiTamperGuard but using Unix-native mechanisms.
/// </summary>
public class UnixAntiTamperGuard : IPlatformMonitor
{
    private readonly ILogger<UnixAntiTamperGuard> _logger;
    private string? _binaryHash;
    private long _lastMonotonicMs;
    private DateTime _lastCheck = DateTime.UtcNow;
    private long _lastLogSize = -1;
    private const int SuspendThresholdMs = 4000;

    public string PlatformName => "UnixAntiTamper";
    public bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public UnixAntiTamperGuard(ILogger<UnixAntiTamperGuard>? logger = null)
    {
        _logger = logger ?? NullLogger<UnixAntiTamperGuard>.Instance;
        _lastMonotonicMs = Environment.TickCount64;

        // Establish binary integrity baseline
        var exePath = Environment.ProcessPath;
        if (exePath is not null && File.Exists(exePath))
        {
            try
            {
                using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                _binaryHash = Convert.ToHexString(SHA256.HashData(stream));
            }
            catch { }
        }
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        // 1. Suspension detection via monotonic clock
        DetectSuspension(signals);

        // 2. Periodic checks (every ~10s)
        if ((DateTime.UtcNow - _lastCheck).TotalSeconds >= 10)
        {
            CheckBinaryIntegrity(signals);
            DetectDebuggerAttachment(signals);
            CheckServiceHealth(signals);
            CheckLogIntegrity(signals);
            if (OperatingSystem.IsLinux())
                CheckLinuxProcTamper(signals);
            _lastCheck = DateTime.UtcNow;
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect /proc hide / mount tricks against the agent (bind-mount over /proc/self).
    /// </summary>
    private void CheckLinuxProcTamper(List<Signal> signals)
    {
        try
        {
            var status = "/proc/self/status";
            if (!File.Exists(status))
            {
                signals.Add(new Signal("proc_self_missing", 95, 0.95));
                return;
            }

            // /proc/self should resolve to our PID
            var link = "/proc/self";
            if (Directory.Exists(link))
            {
                var target = new DirectoryInfo(link).ResolveLinkTarget(true)?.FullName
                             ?? Path.GetFullPath(link);
                if (!target.Contains(Environment.ProcessId.ToString(), StringComparison.Ordinal))
                {
                    // Some kernels expose numeric path; soft check via cmdline
                    var cmdline = File.ReadAllText($"/proc/{Environment.ProcessId}/cmdline");
                    if (string.IsNullOrEmpty(cmdline))
                        signals.Add(new Signal("proc_pid_cmdline_empty", 70, 0.75));
                }
            }

            // TracerPid re-check is in DetectDebuggerAttachment; here check NSpid hide
            foreach (var line in File.ReadLines(status))
            {
                if (line.StartsWith("TracerPid:", StringComparison.Ordinal) &&
                    !line.Trim().EndsWith("0", StringComparison.Ordinal))
                {
                    signals.Add(new Signal("tracer_pid_attached", 92, 0.95));
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixAntiTamper] /proc check failed");
        }
    }

    /// <summary>
    /// Detect process suspension via monotonic clock (Environment.TickCount64).
    /// If elapsed time far exceeds expected 2-5s detection interval, process was suspended.
    /// Uses monotonic clock which cannot be manipulated by attackers changing wall clock.
    /// </summary>
    private void DetectSuspension(List<Signal> signals)
    {
        var currentMs = Environment.TickCount64;
        var elapsedMs = currentMs - _lastMonotonicMs;
        _lastMonotonicMs = currentMs;

        if (elapsedMs > SuspendThresholdMs)
        {
            signals.Add(new Signal(
                $"process_suspension_detected:{elapsedMs}ms_gap", 90, 0.92));
            _logger.LogCritical(
                "SECURITY: Process suspension detected - {Elapsed}ms gap (threshold: {Threshold}ms). " +
                "Possible SIGSTOP/kill -STOP attack.",
                elapsedMs, SuspendThresholdMs);
        }
    }

    /// <summary>
    /// Verify the on-disk binary hasn't been replaced while the agent is running.
    /// </summary>
    private void CheckBinaryIntegrity(List<Signal> signals)
    {
        if (_binaryHash is null) return;
        var exePath = Environment.ProcessPath;
        if (exePath is null || !File.Exists(exePath)) return;

        try
        {
            using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var currentHash = Convert.ToHexString(SHA256.HashData(stream));

            if (!string.Equals(currentHash, _binaryHash, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal("binary_integrity_violation", 95, 0.99));
                _logger.LogCritical(
                    "SECURITY: Binary integrity violation - executable has been modified on disk!");
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect debugger attachment on Linux via /proc/self/status TracerPid.
    /// On macOS, uses sysctl to check P_TRACED flag.
    /// </summary>
    private void DetectDebuggerAttachment(List<Signal> signals)
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var statusPath = "/proc/self/status";
                if (File.Exists(statusPath))
                {
                    foreach (var line in File.ReadLines(statusPath))
                    {
                        if (!line.StartsWith("TracerPid:", StringComparison.Ordinal)) continue;
                        var tracerStr = line["TracerPid:".Length..].Trim();
                        if (int.TryParse(tracerStr, out var tracerPid) && tracerPid != 0)
                        {
                            signals.Add(new Signal(
                                $"debugger_attached:tracer_pid:{tracerPid}", 88, 0.92));
                            _logger.LogCritical(
                                "SECURITY: Debugger attached to agent (TracerPid={Pid})", tracerPid);
                        }
                        break;
                    }
                }
            }
            catch { }
        }
        else if (OperatingSystem.IsMacOS())
        {
            // On macOS, check via sysctl kern.proc.pid
            try
            {
                using var proc = new Process();
                proc.StartInfo = new ProcessStartInfo
                {
                    FileName = "/usr/sbin/sysctl",
                    Arguments = $"kern.proc.pid.{Environment.ProcessId}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                };
                proc.Start();
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(2000);

                // P_TRACED flag (0x00000800) indicates debugging
                if (output.Contains("P_TRACED", StringComparison.Ordinal))
                {
                    signals.Add(new Signal("debugger_attached:P_TRACED", 88, 0.92));
                    _logger.LogCritical("SECURITY: Debugger attached to agent (P_TRACED)");
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Check that the agent's service is still registered and healthy.
    /// Linux: verify systemd unit status.
    /// macOS: verify launchd plist exists and is loaded.
    /// </summary>
    private void CheckServiceHealth(List<Signal> signals)
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                // Check systemd unit file exists
                var unitPaths = new[]
                {
                    "/etc/systemd/system/behavedr.service",
                    "/lib/systemd/system/behavedr.service",
                };
                bool unitExists = unitPaths.Any(File.Exists);

                if (!unitExists)
                {
                    // Service unit deleted - attempt detection
                    signals.Add(new Signal("service_unit_deleted:systemd", 82, 0.88));
                    _logger.LogCritical(
                        "SECURITY: Behavedr systemd unit file has been deleted");
                }
            }
            catch { }
        }
        else if (OperatingSystem.IsMacOS())
        {
            try
            {
                var plistPaths = new[]
                {
                    "/Library/LaunchDaemons/com.croatiasecurity.behavedr.plist",
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                        "Library/LaunchAgents/com.croatiasecurity.behavedr.plist"),
                };
                bool plistExists = plistPaths.Any(File.Exists);

                if (!plistExists)
                {
                    signals.Add(new Signal("service_plist_deleted:launchd", 82, 0.88));
                    _logger.LogCritical(
                        "SECURITY: Behavedr launchd plist has been deleted");
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Check that our own log directory hasn't been deleted or truncated.
    /// Attackers may attempt to destroy forensic evidence.
    /// </summary>
    private void CheckLogIntegrity(List<Signal> signals)
    {
        var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
        if (!Directory.Exists(logDir))
        {
            signals.Add(new Signal("log_directory_deleted", 75, 0.82));
            _logger.LogCritical("SECURITY: Log directory has been deleted");
            // Attempt to recreate
            try { Directory.CreateDirectory(logDir); } catch { }
            return;
        }

        // Check if main log file was truncated
        try
        {
            var logFiles = Directory.GetFiles(logDir, "behavedr-*.log");
            if (logFiles.Length > 0)
            {
                var latestLog = logFiles.OrderByDescending(File.GetLastWriteTimeUtc).First();
                var currentSize = new FileInfo(latestLog).Length;

                if (_lastLogSize >= 0 && currentSize < _lastLogSize * 0.3 && _lastLogSize > 4096)
                {
                    signals.Add(new Signal(
                        $"log_file_truncated:was:{_lastLogSize}:now:{currentSize}", 80, 0.85));
                    _logger.LogCritical(
                        "SECURITY: Log file truncated - possible anti-forensics");
                }
                _lastLogSize = currentSize;
            }
        }
        catch { }
    }
}
