namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Real-time process monitoring on Android via inotify on /proc.
/// When a new process is created, a new directory appears in /proc.
/// inotify IN_CREATE on /proc gives us immediate notification.
///
/// On rooted devices: Full /proc visibility for all processes.
/// On non-rooted: Only our own UID's processes visible (still useful
/// for detecting child process spawning from compromised app context).
///
/// Combined with platform injection (UsageStatsManager, ActivityLifecycleCallbacks)
/// for comprehensive coverage on non-rooted devices.
///
/// v0.2.0 audit fix A-1: Eliminates the polling blind spot on Android.
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidProcessConnector : IPlatformMonitor
{
    private readonly ILogger<AndroidProcessConnector> _logger;
    private int _inotifyFd = -1;
    private int _watchFd = -1;
    private bool _initialized;
    private readonly Queue<AndroidProcEvent> _events = new();
    private readonly object _lock = new();
    private const int MaxBufferedEvents = 300;

    private readonly Dictionary<int, long> _execTimestamps = new();
    private const int EphemeralThresholdMs = 2000;

    public string PlatformName => "AndroidProcessConnector";
    public bool IsSupported => OperatingSystem.IsAndroid();

    public AndroidProcessConnector(ILogger<AndroidProcessConnector>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidProcessConnector>.Instance;
    }

    [SupportedOSPlatform("android")]
    public bool TryInitialize()
    {
        if (_initialized) return _inotifyFd >= 0;
        _initialized = true;

        try
        {
            // IN_NONBLOCK = 0x800
            _inotifyFd = inotify_init1(0x00000800);
            if (_inotifyFd < 0)
            {
                _logger.LogWarning("[AndroidProcConnector] inotify_init1 failed");
                return false;
            }

            // IN_CREATE = 0x100, IN_ONLYDIR = 0x01000000
            _watchFd = inotify_add_watch(_inotifyFd, "/proc", 0x00000100 | 0x01000000);
            if (_watchFd < 0)
            {
                _logger.LogWarning("[AndroidProcConnector] Cannot watch /proc");
                close(_inotifyFd);
                _inotifyFd = -1;
                return false;
            }

            _logger.LogInformation(
                "[AndroidProcConnector] Initialized - real-time /proc inotify monitoring active");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[AndroidProcConnector] Init failed");
            return false;
        }
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_initialized && !TryInitialize())
            return Task.FromResult<IEnumerable<Signal>>(signals);

        if (_inotifyFd < 0)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        DrainInotifyEvents(ct);
        DetectEphemeralExits();

        lock (_lock)
        {
            while (_events.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var evt = _events.Dequeue();
                AnalyzeEvent(evt, signals);
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("android")]
    private void DrainInotifyEvents(CancellationToken ct)
    {
        var buffer = new byte[4096];
        var iterations = 0;

        while (!ct.IsCancellationRequested && iterations++ < 50)
        {
            var bytesRead = read(_inotifyFd, buffer, buffer.Length);
            if (bytesRead <= 0) break;

            var offset = 0;
            while (offset + 16 <= bytesRead)
            {
                // struct inotify_event: int wd(4), uint32 mask(4), uint32 cookie(4), uint32 len(4), char name[]
                var nameLen = (int)BitConverter.ToUInt32(buffer, offset + 12);
                var nameEnd = Math.Min(offset + 16 + nameLen, bytesRead);
                var nameSpan = buffer.AsSpan(offset + 16, nameEnd - (offset + 16));
                var name = System.Text.Encoding.UTF8.GetString(nameSpan).TrimEnd('\0');

                offset = offset + 16 + nameLen;

                if (!int.TryParse(name, out var pid)) continue;
                if (pid <= 1 || pid == Environment.ProcessId) continue;

                var comm = GetProcessComm(pid);
                var cmdline = GetProcessCmdline(pid);

                lock (_lock)
                {
                    if (_events.Count >= MaxBufferedEvents)
                        _events.Dequeue();
                    _events.Enqueue(new AndroidProcEvent(pid, comm, cmdline, Environment.TickCount64));
                    _execTimestamps[pid] = Environment.TickCount64;
                }
            }
        }
    }

    private void DetectEphemeralExits()
    {
        lock (_lock)
        {
            var now = Environment.TickCount64;
            var toRemove = new List<int>();

            foreach (var (pid, startTime) in _execTimestamps)
            {
                var age = now - startTime;
                if (age < EphemeralThresholdMs) continue;

                if (!Directory.Exists($"/proc/{pid}"))
                {
                    if (age < EphemeralThresholdMs + 2000)
                    {
                        _events.Enqueue(new AndroidProcEvent(
                            pid, $"[ephemeral:{age}ms]", null, now));
                    }
                    toRemove.Add(pid);
                }
                else if (age > 30_000)
                {
                    toRemove.Add(pid);
                }
            }

            foreach (var pid in toRemove)
                _execTimestamps.Remove(pid);
        }
    }

    private void AnalyzeEvent(AndroidProcEvent evt, List<Signal> signals)
    {
        if (string.IsNullOrEmpty(evt.Comm)) return;

        if (evt.Comm.StartsWith("[ephemeral:", StringComparison.Ordinal))
        {
            signals.Add(new Signal(
                $"ephemeral_process_android:{evt.Comm}:pid:{evt.Pid}", 55, 0.68));
            return;
        }

        if (evt.Pid == Environment.ProcessId) return;

        string? exePath = null;
        try
        {
            exePath = File.ResolveLinkTarget($"/proc/{evt.Pid}/exe", returnFinalTarget: true)?.FullName;
        }
        catch { /* permission */ }

        if (Response.ResponseSafety.IsOwnAgentImage(exePath)) return;

        // Path + staging heuristics (rename-resistant); name alone stays low weight
        var off = ThreatHeuristics.Evaluate(evt.Comm, exePath ?? evt.Cmdline);
        if (off is { } o)
        {
            signals.Add(new Signal(
                $"realtime_offensive_android:{o.Tag}:{o.Detail}:pid:{evt.Pid}",
                o.Weight, o.Confidence));
        }

        // Behavioral cmdline patterns (not tool product names)
        if (evt.Cmdline is not null &&
            (evt.Cmdline.Contains("/dev/tcp/", StringComparison.Ordinal) ||
             (evt.Cmdline.Contains("sh", StringComparison.Ordinal) &&
              evt.Cmdline.Contains("-i", StringComparison.Ordinal) &&
              evt.Cmdline.Contains(">&", StringComparison.Ordinal))))
        {
            signals.Add(new Signal(
                $"reverse_shell_android:{evt.Comm}:pid:{evt.Pid}", 92, 0.94));
        }

        if (evt.Cmdline is not null &&
            evt.Cmdline.Contains("base64", StringComparison.OrdinalIgnoreCase) &&
            (evt.Cmdline.Contains("| sh", StringComparison.Ordinal) ||
             evt.Cmdline.Contains("|sh", StringComparison.Ordinal)))
        {
            signals.Add(new Signal(
                $"encoded_exec_android:{evt.Comm}:pid:{evt.Pid}", 72, 0.78));
        }
    }

    private static string? GetProcessComm(int pid)
    {
        try { return File.ReadAllText($"/proc/{pid}/comm").Trim(); }
        catch { return null; }
    }

    private static string? GetProcessCmdline(int pid)
    {
        try { return File.ReadAllText($"/proc/{pid}/cmdline").Replace('\0', ' ').Trim(); }
        catch { return null; }
    }

    [DllImport("libc", EntryPoint = "inotify_init1", SetLastError = true)]
    private static extern int inotify_init1(int flags);

    [DllImport("libc", EntryPoint = "inotify_add_watch", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int inotify_add_watch(int fd, string pathname, uint mask);

    [DllImport("libc", EntryPoint = "read", SetLastError = true)]
    private static extern int read(int fd, byte[] buf, int count);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int close(int fd);

    private record AndroidProcEvent(int Pid, string? Comm, string? Cmdline, long TimestampMs);
}
