namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS real-time process execution monitor using kqueue EVFILT_PROC.
/// 
/// RT-1 FIX: Provides real-time process event notification on macOS, eliminating
/// the 5-second polling blind spot identified in the security audit.
///
/// Architecture:
/// - Uses kqueue(2) to subscribe to NOTE_EXEC|NOTE_FORK|NOTE_EXIT events
/// - Periodically discovers new PIDs via process enumeration and subscribes them
/// - Detects ephemeral processes (exec->exit within 2 seconds)
/// - Complements MacOSMonitor (which does deeper behavioral analysis per-process)
///
/// Limitations vs EndpointSecurity.framework:
/// - Can only monitor PIDs we explicitly subscribe to (requires discovery loop)
/// - Cannot block execution (notify-only)
/// - Requires root or matching UID to monitor other processes
///
/// For full real-time coverage equivalent to Linux cn_proc + fanotify, 
/// EndpointSecurity.framework (System Extension) is needed (future work).
///
/// Requires: root privileges (to monitor other users' processes).
/// Available since: macOS 10.0 (kqueue is fundamental to macOS/BSD).
/// </summary>
[SupportedOSPlatform("macos")]
public class MacOSKqueueMonitor : IPlatformMonitor
{
    private readonly ILogger<MacOSKqueueMonitor> _logger;
    private int _kqueueFd = -1;
    private bool _initialized;
    private readonly HashSet<int> _monitoredPids = new();
    private readonly Queue<KqueueProcessEvent> _events = new();
    private readonly object _lock = new();
    private const int MaxBufferedEvents = 500;
    private DateTime _lastPidScan = DateTime.MinValue;
    // v0.2.6: 200ms discovery - further shrinks ephemeral blind spots (still not EndpointSecurity)
    private readonly TimeSpan _pidScanInterval = TimeSpan.FromMilliseconds(200);

    // Track exec timestamps for ephemeral process detection
    private readonly Dictionary<int, long> _execTimestamps = new();
    private const int EphemeralThresholdMs = 2000;

    public string PlatformName => "MacOSKqueue";
    public bool IsSupported => OperatingSystem.IsMacOS();

    public MacOSKqueueMonitor(ILogger<MacOSKqueueMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSKqueueMonitor>.Instance;
    }

    /// <summary>
    /// Initialize kqueue file descriptor for process event monitoring.
    /// </summary>
    [SupportedOSPlatform("macos")]
    public bool TryInitialize()
    {
        if (_initialized) return _kqueueFd >= 0;
        _initialized = true;

        try
        {
            _kqueueFd = kqueue();
            if (_kqueueFd < 0)
            {
                _logger.LogWarning("[MacOSKqueue] kqueue() failed - real-time process monitoring unavailable");
                return false;
            }

            _logger.LogInformation("[MacOSKqueue] Initialized - real-time process event monitoring active");

            // Subscribe to all currently running processes
            SubscribeToRunningProcesses();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[MacOSKqueue] Initialization failed");
            return false;
        }
    }

    [SupportedOSPlatform("macos")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_initialized && !TryInitialize())
            return Task.FromResult<IEnumerable<Signal>>(signals);

        if (_kqueueFd < 0)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        // Periodically discover and subscribe to new PIDs
        if (DateTime.UtcNow - _lastPidScan > _pidScanInterval)
        {
            SubscribeToRunningProcesses();
            _lastPidScan = DateTime.UtcNow;
        }

        // Drain pending kqueue events
        DrainEvents();

        // Process buffered events into signals
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

    /// <summary>
    /// Subscribe to EVFILT_PROC events for all currently running processes.
    /// Only subscribes PIDs not already monitored.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void SubscribeToRunningProcesses()
    {
        try
        {
            var processes = Process.GetProcesses();
            var changes = new List<KEvent>();

            foreach (var proc in processes)
            {
                try
                {
                    var pid = proc.Id;
                    if (pid <= 1) continue; // Skip kernel/launchd
                    if (pid == Environment.ProcessId) continue; // Skip self

                    lock (_lock)
                    {
                        if (_monitoredPids.Contains(pid)) continue;
                        _monitoredPids.Add(pid);
                    }

                    changes.Add(new KEvent
                    {
                        ident = (ulong)pid,
                        filter = EVFILT_PROC,
                        flags = EV_ADD | EV_ENABLE,
                        fflags = NOTE_EXEC | NOTE_FORK | NOTE_EXIT,
                        data = 0,
                        udata = IntPtr.Zero,
                    });
                }
                catch { }
                finally { proc.Dispose(); }
            }

            if (changes.Count > 0)
            {
                RegisterEvents(changes);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSKqueue] Error subscribing to processes");
        }
    }

    /// <summary>
    /// Register a batch of kevent changes with the kqueue.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void RegisterEvents(List<KEvent> changes)
    {
        if (_kqueueFd < 0 || changes.Count == 0) return;

        var changeArray = changes.ToArray();
        // kevent with timeout=0 for non-blocking registration
        var timeout = new TimeSpec { tv_sec = 0, tv_nsec = 0 };
        kevent(_kqueueFd, changeArray, changeArray.Length, null, 0, ref timeout);
    }

    /// <summary>
    /// Drain pending process events from kqueue (non-blocking).
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void DrainEvents()
    {
        if (_kqueueFd < 0) return;

        var eventBuf = new KEvent[64];
        var timeout = new TimeSpec { tv_sec = 0, tv_nsec = 0 }; // Non-blocking

        var iterations = 0;
        while (iterations++ < 10)
        {
            var count = kevent(_kqueueFd, null, 0, eventBuf, eventBuf.Length, ref timeout);
            if (count <= 0) break;

            for (int i = 0; i < count; i++)
            {
                var evt = eventBuf[i];
                var pid = (int)evt.ident;
                var fflags = evt.fflags;

                if ((fflags & NOTE_EXEC) != 0)
                {
                    var procName = GetProcessName(pid);
                    lock (_lock)
                    {
                        if (_events.Count >= MaxBufferedEvents)
                            _events.Dequeue();
                        _events.Enqueue(new KqueueProcessEvent(pid, procName, KqueueEventType.Exec,
                            Environment.TickCount64));
                        _execTimestamps[pid] = Environment.TickCount64;
                    }
                }

                if ((fflags & NOTE_EXIT) != 0)
                {
                    lock (_lock)
                    {
                        _monitoredPids.Remove(pid);
                        if (_execTimestamps.TryGetValue(pid, out var execTime))
                        {
                            var lifeMs = Environment.TickCount64 - execTime;
                            if (lifeMs < EphemeralThresholdMs)
                            {
                                _events.Enqueue(new KqueueProcessEvent(
                                    pid, $"[ephemeral:{lifeMs}ms]", KqueueEventType.EphemeralExit,
                                    Environment.TickCount64));
                            }
                            _execTimestamps.Remove(pid);
                        }
                    }
                }

                if ((fflags & NOTE_FORK) != 0)
                {
                    // A new child was forked - we'll pick it up in the next PID scan
                }
            }
        }
    }

    private void AnalyzeEvent(KqueueProcessEvent evt, List<Signal> signals)
    {
        if (string.IsNullOrEmpty(evt.ProcessName)) return;

        if (evt.EventType == KqueueEventType.EphemeralExit)
        {
            signals.Add(new Signal(
                $"ephemeral_process_macos:{evt.ProcessName}:pid:{evt.Pid}", 55, 0.68));
            return;
        }

        if (evt.Pid == Environment.ProcessId) return;

        // Name + best-effort path (proc_pidpath when available is heavier; name/staging heuristics)
        string? path = null;
        try
        {
            using var p = Process.GetProcessById(evt.Pid);
            path = p.MainModule?.FileName;
        }
        catch { /* permission */ }

        if (Response.ResponseSafety.IsOwnAgentImage(path)) return;

        var off = ThreatHeuristics.Evaluate(evt.ProcessName, path);
        if (off is { } o)
        {
            signals.Add(new Signal(
                $"realtime_offensive_macos:{o.Tag}:{o.Detail}:pid:{evt.Pid}",
                o.Weight, o.Confidence));
        }
    }

    private static string? GetProcessName(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return null; }
    }

    // --- P/Invoke declarations for kqueue ---

    private const short EVFILT_PROC = -5;
    private const ushort EV_ADD = 0x0001;
    private const ushort EV_ENABLE = 0x0004;
    private const uint NOTE_EXIT = 0x80000000;
    private const uint NOTE_FORK = 0x40000000;
    private const uint NOTE_EXEC = 0x20000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct KEvent
    {
        public ulong ident;      // identifier (PID for EVFILT_PROC)
        public short filter;     // filter type (EVFILT_PROC)
        public ushort flags;     // action flags (EV_ADD, EV_ENABLE, etc.)
        public uint fflags;      // filter-specific flags (NOTE_EXEC, NOTE_EXIT, etc.)
        public long data;        // filter-specific data
        public IntPtr udata;     // opaque user data
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TimeSpec
    {
        public long tv_sec;
        public long tv_nsec;
    }

    [DllImport("libc", EntryPoint = "kqueue")]
    private static extern int kqueue();

    [DllImport("libc", EntryPoint = "kevent")]
    private static extern int kevent(
        int kq,
        KEvent[]? changelist, int nchanges,
        KEvent[]? eventlist, int nevents,
        ref TimeSpec timeout);

    private record KqueueProcessEvent(int Pid, string? ProcessName, KqueueEventType EventType, long TimestampMs);

    private enum KqueueEventType
    {
        Exec,
        Fork,
        Exit,
        EphemeralExit,
    }
}
