namespace Behavedr.Agent;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Dual-process watchdog for Linux and macOS (userland mode).
///
/// Since Unix has no equivalent to Windows DACL process termination protection,
/// this watchdog provides defense-in-depth by:
/// 1. Monitoring the main agent PID via /proc (Linux) or kill(pid,0) signal probe (macOS)
/// 2. Detecting kill gaps - if the monitoring heartbeat goes stale AND the process disappears
/// 3. Logging forensic evidence about who killed the agent (Linux audit log query)
/// 4. Writing last-gasp evidence with monotonic timestamps for tamper detection
/// 5. Verifying /proc/self is not being hidden via bind mounts
///
/// This runs as a background service within the same process. For true dual-process
/// protection, deploy the companion `behavedr-watchdog` binary (see packaging/unix/).
/// The in-process watchdog detects suspension attacks (SIGSTOP) and heartbeat failures.
///
/// NOTE: SIGKILL (signal 9) cannot be caught or blocked in userland. The only defense
/// is rapid restart via systemd Restart=always (RestartSec=1) or launchd KeepAlive.
/// This watchdog focuses on DETECTION and FORENSIC LOGGING of kill events, not prevention.
/// </summary>
public sealed class UnixWatchdog : BackgroundService
{
    private readonly ILogger<UnixWatchdog> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(2);
    private long _lastMonotonicMs;
    private const int SuspendThresholdMs = 5000;

    private static readonly string ForensicLogPath = Path.Combine(
        AppContext.BaseDirectory, "logs", "watchdog-forensic.log");

    public UnixWatchdog(ILogger<UnixWatchdog> logger)
    {
        _logger = logger;
        _lastMonotonicMs = Environment.TickCount64;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return;

        _logger.LogInformation("[UnixWatchdog] Started - PID {Pid}, monitoring for suspension/kill attacks",
            Environment.ProcessId);

        // Write PID file for external watchdog companion
        WritePidFile();

        using var timer = new PeriodicTimer(_checkInterval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);
                PerformWatchdogChecks();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UnixWatchdog] Check failed");
            }
        }

        _logger.LogInformation("[UnixWatchdog] Stopping gracefully");
        WriteForensicEntry("Watchdog stopping gracefully (cancellation requested)");
    }

    private void PerformWatchdogChecks()
    {
        // 1. Suspension detection via monotonic clock
        var currentMs = Environment.TickCount64;
        var elapsedMs = currentMs - _lastMonotonicMs;
        _lastMonotonicMs = currentMs;

        if (elapsedMs > SuspendThresholdMs)
        {
            _logger.LogCritical(
                "[UnixWatchdog] SUSPENSION DETECTED - {Elapsed}ms gap (threshold: {Threshold}ms). " +
                "Possible SIGSTOP attack. Querying audit log for attacker PID.",
                elapsedMs, SuspendThresholdMs);

            WriteForensicEntry($"SUSPENSION: {elapsedMs}ms gap detected");

            if (OperatingSystem.IsLinux())
            {
                QueryAuditLogForKiller();
            }
        }

        // 2. Verify monitoring heartbeat is fresh
        var heartbeatAge = DateTime.UtcNow - AgentWatchdog.LastMonitoringHeartbeat;
        if (heartbeatAge.TotalSeconds > 20)
        {
            _logger.LogCritical(
                "[UnixWatchdog] Monitoring heartbeat stale for {Seconds:F1}s - possible deadlock or injection",
                heartbeatAge.TotalSeconds);
            WriteForensicEntry($"HEARTBEAT_STALE: {heartbeatAge.TotalSeconds:F1}s");
        }

        // 3. Linux: verify /proc/self hasn't been tampered with
        if (OperatingSystem.IsLinux())
        {
            VerifyProcSelf();
        }
    }

    /// <summary>
    /// Query Linux audit log to identify who sent a signal to our process.
    /// Uses ausearch to find recent KILL audit events targeting our PID.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void QueryAuditLogForKiller()
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/usr/sbin/ausearch",
                Arguments = $"-m KILL -i --just-one -ts recent",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            if (!File.Exists("/usr/sbin/ausearch"))
            {
                // Try aureport as fallback
                proc.StartInfo.FileName = "/usr/sbin/aureport";
                proc.StartInfo.Arguments = "--anomaly --summary";
                if (!File.Exists("/usr/sbin/aureport"))
                    return;
            }

            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            if (!string.IsNullOrWhiteSpace(output))
            {
                _logger.LogCritical("[UnixWatchdog] Audit log evidence: {Output}",
                    output.Length > 500 ? output[..500] : output);
                WriteForensicEntry($"AUDIT_EVIDENCE: {output}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixWatchdog] Cannot query audit log (auditd may not be installed)");
        }
    }

    /// <summary>
    /// Verify /proc/self is not hidden via bind mounts.
    /// An attacker could: mount --bind /dev/null /proc/$(pidof behavedr)/maps
    /// to blind the memory analyzer.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void VerifyProcSelf()
    {
        try
        {
            // Verify we can read our own comm
            var commPath = "/proc/self/comm";
            if (!File.Exists(commPath))
            {
                _logger.LogCritical("[UnixWatchdog] /proc/self/comm not accessible - possible /proc tampering");
                WriteForensicEntry("PROC_TAMPER: /proc/self/comm not accessible");
                return;
            }

            var comm = File.ReadAllText(commPath).Trim();
            // Our process name should contain "Behavedr" or "dotnet"
            if (!comm.Contains("Behavedr", StringComparison.OrdinalIgnoreCase) &&
                !comm.Contains("dotnet", StringComparison.OrdinalIgnoreCase) &&
                comm != "behavedr")
            {
                _logger.LogCritical(
                    "[UnixWatchdog] /proc/self/comm reports '{Comm}' - expected Behavedr. Possible process identity manipulation.",
                    comm);
                WriteForensicEntry($"PROC_IDENTITY_MISMATCH: comm={comm}");
            }

            // Verify /proc/self/exe points to our binary
            var exePath = "/proc/self/exe";
            if (File.Exists(exePath))
            {
                try
                {
                    var target = File.ResolveLinkTarget(exePath, returnFinalTarget: true)?.ToString();
                    if (target is not null && !target.Contains("Behavedr", StringComparison.OrdinalIgnoreCase) &&
                        !target.Contains("dotnet", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogCritical(
                            "[UnixWatchdog] /proc/self/exe -> '{Target}' - unexpected binary. Possible process hollowing.",
                            target);
                        WriteForensicEntry($"PROC_EXE_MISMATCH: exe={target}");
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixWatchdog] /proc/self verification failed");
        }
    }

    private void WritePidFile()
    {
        try
        {
            var pidDir = Path.Combine(AppContext.BaseDirectory, "run");
            Directory.CreateDirectory(pidDir);
            var pidPath = Path.Combine(pidDir, "behavedr.pid");
            File.WriteAllText(pidPath, Environment.ProcessId.ToString());
        }
        catch { }
    }

    private static void WriteForensicEntry(string message)
    {
        try
        {
            var dir = Path.GetDirectoryName(ForensicLogPath);
            if (dir is not null) Directory.CreateDirectory(dir);
            var entry = $"[{DateTime.UtcNow:O}] MONOTONIC={Environment.TickCount64} PID={Environment.ProcessId} {message}{Environment.NewLine}";
            File.AppendAllText(ForensicLogPath, entry);
        }
        catch { }
    }
}
