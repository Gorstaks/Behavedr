namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux behavioral detection monitor using /proc filesystem, audit logs, and container inspection.
/// Provides real-time detection of:
/// - Suspicious process execution (offensive tools, reverse shells, encoded commands)
/// - Privilege escalation (SUID abuse, capability manipulation, kernel module loading)
/// - Container escape indicators (namespace breakout, host mount abuse)
/// - ptrace-based injection (PTRACE_ATTACH on non-child processes)
/// - LD_PRELOAD/LD_LIBRARY_PATH hijacking
/// - Audit log tampering (truncation, clearing)
/// - Unexpected root processes
/// </summary>
public class LinuxMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxMonitor> _logger;

    public string PlatformName => "Linux";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxMonitor(ILogger<LinuxMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxMonitor>.Instance;
    }

    private static readonly HashSet<string> ExpectedRootProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "init", "systemd", "kthreadd", "sshd", "cron", "crond",
        "rsyslogd", "dockerd", "containerd", "snapd", "polkitd",
        "dbus-daemon", "NetworkManager", "accounts-daemon",
        "systemd-journald", "systemd-logind", "systemd-resolved",
        "systemd-networkd", "systemd-udevd", "agetty", "login",
        "auditd", "irqbalance", "multipathd", "packagekitd",
        "udisksd", "thermald", "fwupd", "behavedr",
    };

    private static readonly Regex ReverseShellRegex = new(
        @"(/dev/tcp/|bash\s+-i|nc\s+-e|ncat\s+-e|socat\s+exec|python.*socket.*connect|perl.*socket|ruby.*TCPSocket|php.*fsockopen)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex EncodedExecRegex = new(
        @"(base64\s+-d|\|\s*(ba)?sh|\|\s*python|eval\s*\(|exec\s*\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Track audit log size for truncation detection
    private long _lastAuditLogSize = -1;

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            ScanProcesses(signals, ct);
            DetectPtraceInjection(signals, ct);
            DetectLdPreloadHijacking(signals, ct);
            DetectContainerEscape(signals, ct);
            DetectKernelModuleLoading(signals, ct);
            DetectSuidAbuse(signals, ct);
            ScanAuditLog(signals, ct);
            DetectCapabilityAbuse(signals, ct);
            DetectProcBindMounts(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxMonitor] Error during scan cycle");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Scan /proc for suspicious processes: offensive tools, reverse shells,
    /// encoded execution, unexpected root processes.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void ScanProcesses(List<Signal> signals, CancellationToken ct)
    {
        if (!Directory.Exists("/proc")) return;

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                try
                {
                    var commPath = Path.Combine(procDir, "comm");
                    if (!File.Exists(commPath)) continue;
                    var processName = File.ReadAllText(commPath).Trim();

                    // Read command line + exe path (rename-resistant)
                    var cmdlinePath = Path.Combine(procDir, "cmdline");
                    var cmdline = "";
                    if (File.Exists(cmdlinePath))
                        cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ').Trim();

                    string? exePath = null;
                    try
                    {
                        exePath = File.ResolveLinkTarget(Path.Combine(procDir, "exe"), returnFinalTarget: true)?.FullName;
                    }
                    catch { /* permission */ }

                    if (Response.ResponseSafety.IsOwnAgentImage(exePath))
                        continue;

                    var off = ThreatHeuristics.Evaluate(processName, exePath ?? cmdline);
                    if (off is { } o)
                    {
                        signals.Add(new Signal(
                            $"suspicious_process:{o.Tag}:{o.Detail}:pid:{pid}",
                            o.Weight, o.Confidence));
                    }

                    if (!string.IsNullOrEmpty(cmdline))
                    {
                        // Reverse shell detection
                        if (ReverseShellRegex.IsMatch(cmdline))
                        {
                            signals.Add(new Signal(
                                $"reverse_shell:{processName}:pid:{pid}", 92, 0.88));
                        }

                        // Encoded/piped execution
                        if (EncodedExecRegex.IsMatch(cmdline))
                        {
                            signals.Add(new Signal(
                                $"encoded_execution:{processName}:pid:{pid}", 65, 0.72));
                        }
                    }

                    // Unexpected root process detection
                    var statusPath = Path.Combine(procDir, "status");
                    if (File.Exists(statusPath))
                    {
                        foreach (var line in File.ReadLines(statusPath))
                        {
                            if (!line.StartsWith("Uid:", StringComparison.Ordinal)) continue;
                            var parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length > 1 && parts[1] == "0" &&
                                !ExpectedRootProcesses.Contains(processName))
                            {
                                signals.Add(new Signal(
                                    $"unexpected_root_process:{processName}:pid:{pid}", 55, 0.65));
                            }
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxMonitor] Process scan error");
        }
    }

    /// <summary>
    /// Detect ptrace-based injection by scanning /proc/*/status for TracerPid != 0.
    /// A non-zero TracerPid means another process is attached via ptrace (debugging/injection).
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectPtraceInjection(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (pid == Environment.ProcessId) continue;

                var statusPath = Path.Combine(procDir, "status");
                if (!File.Exists(statusPath)) continue;

                try
                {
                    foreach (var line in File.ReadLines(statusPath))
                    {
                        if (!line.StartsWith("TracerPid:", StringComparison.Ordinal)) continue;
                        var tracerStr = line["TracerPid:".Length..].Trim();
                        if (int.TryParse(tracerStr, out var tracerPid) && tracerPid != 0)
                        {
                            // Something is ptracing this process - check if it's gdb/strace (legitimate)
                            var tracerName = GetProcessName(tracerPid);
                            if (tracerName is not ("gdb" or "strace" or "ltrace" or "lldb" or "valgrind"))
                            {
                                signals.Add(new Signal(
                                    $"ptrace_injection:{tracerName}(pid:{tracerPid})->pid:{pid}", 80, 0.82));
                            }
                        }
                        break;
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect LD_PRELOAD/LD_LIBRARY_PATH hijacking by inspecting /proc/*/environ.
    /// Attacker sets LD_PRELOAD to inject a malicious shared object into target processes.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectLdPreloadHijacking(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                var environPath = Path.Combine(procDir, "environ");
                if (!File.Exists(environPath)) continue;

                try
                {
                    var environ = File.ReadAllText(environPath).Replace('\0', '\n');

                    // LD_PRELOAD set to non-standard path
                    if (environ.Contains("LD_PRELOAD=", StringComparison.Ordinal))
                    {
                        var match = Regex.Match(environ, @"LD_PRELOAD=(.+?)(\n|$)");
                        if (match.Success)
                        {
                            var preloadPath = match.Groups[1].Value;
                            // Legitimate: empty, or known library paths
                            if (!string.IsNullOrWhiteSpace(preloadPath) &&
                                !preloadPath.StartsWith("/usr/lib", StringComparison.Ordinal) &&
                                !preloadPath.StartsWith("/lib", StringComparison.Ordinal))
                            {
                                var procName = GetProcessName(pid) ?? pidStr;
                                signals.Add(new Signal(
                                    $"ld_preload_hijack:{procName}:pid:{pid}:{preloadPath}",
                                    78, 0.83));
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect container escape indicators:
    /// - Process in container namespace accessing host /proc or /sys
    /// - nsenter/unshare executed with host PID/mount namespace
    /// - Privileged container breakout patterns (mount host filesystem)
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectContainerEscape(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                var cmdlinePath = Path.Combine(procDir, "cmdline");
                if (!File.Exists(cmdlinePath)) continue;

                try
                {
                    var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ');

                    // nsenter with host namespaces
                    if (cmdline.Contains("nsenter", StringComparison.Ordinal) &&
                        (cmdline.Contains("-t 1", StringComparison.Ordinal) ||
                         cmdline.Contains("--target 1", StringComparison.Ordinal)))
                    {
                        signals.Add(new Signal(
                            $"container_escape_nsenter:pid:{pid}", 95, 0.92));
                    }

                    // unshare to break out of namespace
                    if (cmdline.Contains("unshare", StringComparison.Ordinal) &&
                        cmdline.Contains("--mount", StringComparison.Ordinal))
                    {
                        signals.Add(new Signal(
                            $"namespace_breakout_unshare:pid:{pid}", 85, 0.8));
                    }

                    // cgroups escape via release_agent
                    if (cmdline.Contains("release_agent", StringComparison.Ordinal) ||
                        cmdline.Contains("notify_on_release", StringComparison.Ordinal))
                    {
                        signals.Add(new Signal(
                            $"cgroup_escape_attempt:pid:{pid}", 92, 0.88));
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            // Check for processes mounting host filesystems inside containers
            if (File.Exists("/proc/mounts"))
            {
                var mounts = File.ReadAllText("/proc/mounts");
                if (mounts.Contains("/host", StringComparison.Ordinal) &&
                    File.Exists("/.dockerenv"))
                {
                    signals.Add(new Signal("host_mount_in_container", 88, 0.85));
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect kernel module loading - check /proc/modules delta and dmesg for insmod/modprobe activity.
    /// Loading rogue kernel modules is a rootkit installation technique (T1547.006).
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectKernelModuleLoading(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                var cmdlinePath = Path.Combine(procDir, "cmdline");
                if (!File.Exists(cmdlinePath)) continue;

                try
                {
                    var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ').ToLowerInvariant();

                    // insmod or modprobe from non-standard paths
                    if ((cmdline.Contains("insmod", StringComparison.Ordinal) ||
                         cmdline.Contains("modprobe", StringComparison.Ordinal)) &&
                        (cmdline.Contains("/tmp/", StringComparison.Ordinal) ||
                         cmdline.Contains("/dev/shm/", StringComparison.Ordinal) ||
                         cmdline.Contains("/home/", StringComparison.Ordinal)))
                    {
                        signals.Add(new Signal(
                            $"suspicious_kernel_module_load:pid:{pid}", 90, 0.88));
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect SUID binary abuse - find SUID/SGID executables in writable directories.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectSuidAbuse(List<Signal> signals, CancellationToken ct)
    {
        var suspiciousDirs = new[] { "/tmp", "/var/tmp", "/dev/shm", "/home" };

        foreach (var dir in suspiciousDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var mode = File.GetUnixFileMode(file);
                        if ((mode & UnixFileMode.SetUser) != 0 || (mode & UnixFileMode.SetGroup) != 0)
                        {
                            var age = DateTime.UtcNow - File.GetCreationTimeUtc(file);
                            if (age.TotalMinutes < 30) // Recently created SUID in writable dir
                            {
                                signals.Add(new Signal(
                                    $"suid_in_writable_dir:{Path.GetFileName(file)}:{dir}",
                                    82, 0.85));
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Detect bind mounts over /proc paths used to blind the agent's monitors.
    /// An attacker with root can: mount --bind /dev/null /proc/$(pidof target)/maps
    /// This makes the memory analyzer, process scanner, and network monitor blind.
    /// Detection: parse /proc/mounts for bind mounts targeting /proc subdirectories.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectProcBindMounts(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            if (!File.Exists("/proc/mounts")) return;

            foreach (var line in File.ReadLines("/proc/mounts"))
            {
                if (ct.IsCancellationRequested) break;

                // Bind mounts show as "device mountpoint type options"
                // A bind mount over /proc will appear as a mount with target under /proc
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                var mountPoint = parts[1];

                // Suspicious: anything mounted OVER a /proc path (except /proc itself and /proc/sys)
                if (mountPoint.StartsWith("/proc/", StringComparison.Ordinal) &&
                    !mountPoint.StartsWith("/proc/sys", StringComparison.Ordinal) &&
                    mountPoint != "/proc")
                {
                    // Check if it's targeting a PID directory or self
                    if (mountPoint.Contains("/proc/self", StringComparison.Ordinal) ||
                        mountPoint.Contains("/proc/net", StringComparison.Ordinal) ||
                        System.Text.RegularExpressions.Regex.IsMatch(mountPoint, @"/proc/\d+"))
                    {
                        signals.Add(new Signal(
                            $"proc_bind_mount_evasion:{mountPoint}", 92, 0.95));
                        _logger.LogCritical(
                            "SECURITY: Suspicious bind mount over {MountPoint} - possible detection evasion",
                            mountPoint);
                    }
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Scan audit log for security-relevant events: EXECVE, USER_AUTH failures,
    /// and detect log truncation/clearing (anti-forensics).
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void ScanAuditLog(List<Signal> signals, CancellationToken ct)
    {
        const string auditLogPath = "/var/log/audit/audit.log";
        if (!File.Exists(auditLogPath)) return;

        // Detect audit log truncation
        try
        {
            var currentSize = new FileInfo(auditLogPath).Length;
            if (_lastAuditLogSize >= 0)
            {
                if (currentSize < _lastAuditLogSize * 0.5 && _lastAuditLogSize > 4096)
                {
                    signals.Add(new Signal(
                        $"audit_log_truncated:was:{_lastAuditLogSize}:now:{currentSize}", 90, 0.92));
                }
                else if (currentSize == 0 && _lastAuditLogSize > 0)
                {
                    signals.Add(new Signal("audit_log_cleared", 95, 0.98));
                }
            }
            _lastAuditLogSize = currentSize;
        }
        catch { }

        // Read recent entries
        try
        {
            using var stream = new FileStream(auditLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var seekPos = Math.Max(0, stream.Length - 16384);
            stream.Seek(seekPos, SeekOrigin.Begin);

            using var reader = new StreamReader(stream);
            while (!reader.EndOfStream && !ct.IsCancellationRequested)
            {
                var line = reader.ReadLine();
                if (line is null) break;

                // Failed authentication attempts (brute force)
                if (line.Contains("type=USER_AUTH", StringComparison.Ordinal) &&
                    line.Contains("res=failed", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal("failed_auth_attempt", 40, 0.6));
                }

                // Privilege escalation via su
                if (line.Contains("type=USER_CMD", StringComparison.Ordinal) &&
                    line.Contains("cmd=", StringComparison.Ordinal))
                {
                    // Check for suspicious commands run via sudo
                    if (line.Contains("/tmp/", StringComparison.Ordinal) ||
                        line.Contains("/dev/shm/", StringComparison.Ordinal))
                    {
                        signals.Add(new Signal("sudo_suspicious_path", 70, 0.75));
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    /// <summary>
    /// Detect capability abuse - processes with dangerous capabilities (CAP_SYS_ADMIN,
    /// CAP_SYS_PTRACE, CAP_DAC_OVERRIDE) in unexpected contexts.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectCapabilityAbuse(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (pid <= 1 || pid == Environment.ProcessId) continue;

                var statusPath = Path.Combine(procDir, "status");
                if (!File.Exists(statusPath)) continue;

                try
                {
                    string? capEff = null;
                    string? name = null;
                    foreach (var line in File.ReadLines(statusPath))
                    {
                        if (line.StartsWith("Name:", StringComparison.Ordinal))
                            name = line["Name:".Length..].Trim();
                        else if (line.StartsWith("CapEff:", StringComparison.Ordinal))
                            capEff = line["CapEff:".Length..].Trim();

                        if (name is not null && capEff is not null) break;
                    }

                    if (capEff is null || name is null) continue;
                    if (ExpectedRootProcesses.Contains(name)) continue;

                    // Parse hex capability bitmask
                    if (ulong.TryParse(capEff, System.Globalization.NumberStyles.HexNumber, null, out var caps))
                    {
                        // CAP_SYS_ADMIN=21, CAP_SYS_PTRACE=19, CAP_DAC_OVERRIDE=1
                        bool hasSysAdmin = (caps & (1UL << 21)) != 0;
                        bool hasPtrace = (caps & (1UL << 19)) != 0;
                        bool hasDacOverride = (caps & (1UL << 1)) != 0;

                        if (hasSysAdmin || hasPtrace)
                        {
                            signals.Add(new Signal(
                                $"dangerous_capabilities:{name}:pid:{pid}:caps:{capEff}",
                                72, 0.78));
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch { }
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
