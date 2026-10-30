namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Real-time file execution and access monitoring via Linux fanotify.
/// Uses FAN_OPEN_EXEC for notification of every binary execution system-wide.
///
/// Fanotify operates at the VFS layer in the kernel, providing:
/// - Real-time notification of file opens for execution (eliminating polling gaps)
/// - File path attribution via /proc/self/fd resolution
/// - System-wide coverage (all mount points)
///
/// This is a NOTIFY-only monitor (not using FAN_OPEN_EXEC_PERM which would block).
/// Blocking execution requires additional policy configuration and is not appropriate
/// for an EDR that lacks code-signing infrastructure.
///
/// Requires: CAP_SYS_ADMIN or CAP_AUDIT_READ (depending on kernel version).
/// Available since: Linux 5.1+ (FAN_OPEN_EXEC), Linux 2.6.37 (base fanotify).
/// No kernel module, no code signing required - pure userland via syscall.
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxFanotifyMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxFanotifyMonitor> _logger;
    private int _fanotifyFd = -1;
    private bool _initialized;
    private bool _permMode;
    private readonly Queue<FanotifyExecEvent> _events = new();
    private readonly object _lock = new();
    private const int MaxBufferedEvents = 300;

    // Suspicious execution locations (binaries executed from here are noteworthy)
    private static readonly string[] SuspiciousExecPaths =
    [
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
        "/home/", "/root/",
    ];

    // Known-good execution paths (suppress noise)
    private static readonly string[] TrustedExecPaths =
    [
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/usr/lib/", "/lib/", "/opt/behavedr/",
        "/usr/libexec/", "/snap/",
    ];

    public string PlatformName => "LinuxFanotify";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxFanotifyMonitor(ILogger<LinuxFanotifyMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxFanotifyMonitor>.Instance;
    }

    /// <summary>
    /// Initialize fanotify file descriptor and mark the root filesystem for exec events.
    /// </summary>
    [SupportedOSPlatform("linux")]
    public bool TryInitialize()
    {
        if (_initialized) return _fanotifyFd >= 0;

        _initialized = true;

        try
        {
            // Optional PERM mode: BEHAVEDR_FANOTIFY_PERM=1 (allowlist trusted paths, deny tmp droppers)
            _permMode = string.Equals(
                Environment.GetEnvironmentVariable("BEHAVEDR_FANOTIFY_PERM"), "1", StringComparison.Ordinal);

            const uint FAN_CLASS_NOTIF = 0x00000000;
            const uint FAN_CLASS_CONTENT = 0x00000004; // required for PERM events
            const uint FAN_NONBLOCK = 0x00000002;
            const int O_RDONLY = 0;
            const int O_LARGEFILE = 0x8000;

            uint cls = _permMode ? FAN_CLASS_CONTENT : FAN_CLASS_NOTIF;
            _fanotifyFd = fanotify_init(cls | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
            if (_fanotifyFd < 0 && _permMode)
            {
                // Fall back to notify-only
                _permMode = false;
                _fanotifyFd = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
                _logger.LogWarning("[LinuxFanotify] PERM class init failed - using NOTIF only");
            }

            if (_fanotifyFd < 0)
            {
                _logger.LogWarning(
                    "[LinuxFanotify] fanotify_init failed (errno {Errno}). " +
                    "Requires CAP_SYS_ADMIN. Falling back to polling.",
                    Marshal.GetLastPInvokeError());
                return false;
            }

            const ulong FAN_OPEN_EXEC = 0x00001000;
            const ulong FAN_OPEN_EXEC_PERM = 0x00040000;
            const uint FAN_MARK_ADD = 0x00000001;
            const uint FAN_MARK_MOUNT = 0x00000010;
            const int AT_FDCWD = -100;

            ulong mask = _permMode ? (FAN_OPEN_EXEC | FAN_OPEN_EXEC_PERM) : FAN_OPEN_EXEC;
            var result = fanotify_mark(_fanotifyFd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, "/");

            if (result < 0)
            {
                _logger.LogWarning(
                    "[LinuxFanotify] fanotify_mark failed for / (errno {Errno}). " +
                    "FAN_OPEN_EXEC requires kernel 5.1+.",
                    Marshal.GetLastPInvokeError());
                close(_fanotifyFd);
                _fanotifyFd = -1;
                return false;
            }

            _logger.LogInformation(
                "[LinuxFanotify] Initialized - exec monitoring on / ({Mode})",
                _permMode ? "NOTIFY+PERM allowlist" : "NOTIFY");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[LinuxFanotify] Initialization failed");
            return false;
        }
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_initialized)
            TryInitialize();

        if (_fanotifyFd < 0)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        // Read pending fanotify events
        DrainFanotifyEvents(ct);

        // Process buffered events into signals
        lock (_lock)
        {
            while (_events.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var evt = _events.Dequeue();
                AnalyzeExecEvent(evt, signals);
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Read fanotify events from the fd. Each event is a fanotify_event_metadata struct.
    /// We resolve the file path from the event's fd via /proc/self/fd/N readlink.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DrainFanotifyEvents(CancellationToken ct)
    {
        // fanotify_event_metadata is 24 bytes on x86_64
        var buffer = new byte[4096]; // Room for ~170 events per read
        var iterations = 0;

        while (!ct.IsCancellationRequested && iterations++ < 50)
        {
            var bytesRead = read(_fanotifyFd, buffer, buffer.Length);
            if (bytesRead <= 0) break;

            var offset = 0;
            while (offset + 24 <= bytesRead)
            {
                // Parse fanotify_event_metadata
                var eventLen = BitConverter.ToUInt32(buffer, offset);
                // var vers = buffer[offset + 4];
                // var reserved = buffer[offset + 5];
                // var metadataLen = BitConverter.ToUInt16(buffer, offset + 6);
                var mask = BitConverter.ToUInt64(buffer, offset + 8);
                var fd = BitConverter.ToInt32(buffer, offset + 16);
                var pid = BitConverter.ToInt32(buffer, offset + 20);

                if (fd >= 0)
                {
                    var filePath = ResolveFdPath(fd);

                    // PERM events require an explicit response before close
                    const ulong FAN_OPEN_EXEC_PERM = 0x00040000;
                    if (_permMode && (mask & FAN_OPEN_EXEC_PERM) != 0)
                    {
                        bool allow = ShouldAllowExec(filePath);
                        WriteFanotifyResponse(fd, allow);
                        if (!allow && filePath is not null)
                        {
                            lock (_lock)
                            {
                                if (_events.Count >= MaxBufferedEvents)
                                    _events.Dequeue();
                                _events.Enqueue(new FanotifyExecEvent(pid, filePath + ":DENIED",
                                    Environment.TickCount64));
                            }
                        }
                    }

                    close(fd);

                    if (filePath is not null && !filePath.EndsWith(":DENIED", StringComparison.Ordinal))
                    {
                        lock (_lock)
                        {
                            if (_events.Count >= MaxBufferedEvents)
                                _events.Dequeue();
                            _events.Enqueue(new FanotifyExecEvent(pid, filePath,
                                Environment.TickCount64));
                        }
                    }
                }

                offset += (int)(eventLen > 0 ? eventLen : 24);
            }
        }
    }

    private void AnalyzeExecEvent(FanotifyExecEvent evt, List<Signal> signals)
    {
        // Skip our own process and trusted paths
        if (evt.Pid == Environment.ProcessId) return;
        if (Response.ResponseSafety.IsOwnAgentImage(evt.FilePath)) return;

        if (evt.FilePath.EndsWith(":DENIED", StringComparison.Ordinal))
        {
            signals.Add(new Signal(
                $"fanotify_exec_denied:{Path.GetFileName(evt.FilePath.Replace(":DENIED", "", StringComparison.Ordinal))}:pid:{evt.Pid}",
                88, 0.95));
            return;
        }

        if (TrustedExecPaths.Any(p => evt.FilePath.StartsWith(p, StringComparison.Ordinal)))
            return;

        // Rename-resistant heuristics (staging path beats tool name alone)
        var off = ThreatHeuristics.Evaluate(Path.GetFileName(evt.FilePath), evt.FilePath);
        if (off is { } o)
        {
            signals.Add(new Signal(
                $"fanotify_offensive:{o.Tag}:{o.Detail}:pid:{evt.Pid}",
                o.Weight, o.Confidence));
        }

        // Execution of hidden files (dotfiles) outside trusted paths
        var name = Path.GetFileName(evt.FilePath);
        if (name.StartsWith('.') && !name.StartsWith("..", StringComparison.Ordinal))
        {
            signals.Add(new Signal(
                $"hidden_file_execution:{name}:pid:{evt.Pid}", 58, 0.68));
        }

        // Execution from deleted path (memfd_create or unlinked binary)
        if (evt.FilePath.Contains("(deleted)", StringComparison.Ordinal) ||
            evt.FilePath.Contains("memfd:", StringComparison.Ordinal))
        {
            signals.Add(new Signal(
                $"fileless_execution_fanotify:{Path.GetFileName(evt.FilePath)}:pid:{evt.Pid}",
                88, 0.9));
        }
    }

    private static string? ResolveFdPath(int fd)
    {
        try
        {
            var linkPath = $"/proc/self/fd/{fd}";
            return File.ResolveLinkTarget(linkPath, returnFinalTarget: true)?.ToString();
        }
        catch { return null; }
    }

    /// <summary>
    /// PERM policy: allow trusted system prefixes; deny exec from tmp/devshm and hidden droppers.
    /// Default-allow for unknown paths to limit business impact.
    /// </summary>
    private static bool ShouldAllowExec(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return true;
        // Never block our own install (self-DoS)
        if (Response.ResponseSafety.IsOwnAgentImage(filePath) ||
            filePath.StartsWith("/opt/behavedr/", StringComparison.Ordinal))
            return true;
        if (TrustedExecPaths.Any(p => filePath.StartsWith(p, StringComparison.Ordinal)))
            return true;
        if (filePath.Contains("memfd:", StringComparison.Ordinal) ||
            filePath.Contains("(deleted)", StringComparison.Ordinal))
            return false;
        // Staging paths - deny exec regardless of binary name (rename-resistant)
        if (ThreatHeuristics.IsStagingPath(filePath) && ThreatHeuristics.LooksLikeExecutableName(filePath))
            return false;
        return true;
    }

    private void WriteFanotifyResponse(int fd, bool allow)
    {
        // struct fanotify_response { __s32 fd; __u32 response; }
        // FAN_ALLOW=0x01, FAN_DENY=0x02
        try
        {
            Span<byte> buf = stackalloc byte[8];
            BitConverter.TryWriteBytes(buf[..4], fd);
            BitConverter.TryWriteBytes(buf.Slice(4, 4), allow ? 0x01u : 0x02u);
            write(_fanotifyFd, buf.ToArray(), 8);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxFanotify] PERM response failed");
        }
    }

    // P/Invoke for fanotify syscalls
    [DllImport("libc", EntryPoint = "fanotify_init", SetLastError = true)]
    private static extern int fanotify_init(uint flags, int event_f_flags);

    [DllImport("libc", EntryPoint = "fanotify_mark", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int fanotify_mark(int fanotify_fd, uint flags, ulong mask, int dirfd, string pathname);

    [DllImport("libc", EntryPoint = "read", SetLastError = true)]
    private static extern int read(int fd, byte[] buf, int count);

    [DllImport("libc", EntryPoint = "write", SetLastError = true)]
    private static extern int write(int fd, byte[] buf, int count);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int close(int fd);

    private record FanotifyExecEvent(int Pid, string FilePath, long TimestampMs);
}
