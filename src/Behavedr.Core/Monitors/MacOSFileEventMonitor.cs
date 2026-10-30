namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Real-time file system monitoring on macOS via kqueue EVFILT_VNODE on high-value paths.
/// Bridges the gap until a full EndpointSecurity System Extension is packaged:
/// - LaunchDaemon / LaunchAgent directories (persistence)
/// - /etc and /usr/local/bin (supply-chain / LOLBin drops)
/// - /tmp and /private/tmp (staging)
/// - /Library/PrivilegedHelperTools
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacOSFileEventMonitor : IPlatformMonitor
{
    private readonly ILogger<MacOSFileEventMonitor> _logger;
    private int _kq = -1;
    private bool _initialized;
    private readonly Dictionary<int, string> _fdToPath = new();
    private readonly Queue<string> _events = new();
    private readonly object _lock = new();
    private const int MaxEvents = 200;

    private static readonly string[] WatchPaths =
    [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/Library/PrivilegedHelperTools",
        "/Library/Extensions",
        "/etc",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/tmp",
        "/private/tmp",
        "/var/root/Library/LaunchAgents",
    ];

    public string PlatformName => "MacOSFileEvents";
    public bool IsSupported => OperatingSystem.IsMacOS();

    public MacOSFileEventMonitor(ILogger<MacOSFileEventMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSFileEventMonitor>.Instance;
    }

    [SupportedOSPlatform("macos")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_initialized)
            TryInitialize();

        if (_kq < 0)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        DrainVnodeEvents();

        lock (_lock)
        {
            while (_events.Count > 0 && !ct.IsCancellationRequested)
            {
                var path = _events.Dequeue();
                Classify(path, signals);
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("macos")]
    private void TryInitialize()
    {
        _initialized = true;
        try
        {
            _kq = kqueue();
            if (_kq < 0)
            {
                _logger.LogWarning("[MacOSFileEvents] kqueue() failed");
                return;
            }

            var homeAgents = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "LaunchAgents");

            var paths = WatchPaths.Concat(new[] { homeAgents }).Distinct();
            foreach (var dir in paths)
            {
                if (!Directory.Exists(dir)) continue;
                WatchDirectory(dir);
            }

            _logger.LogInformation("[MacOSFileEvents] Watching {Count} high-value directories via EVFILT_VNODE",
                _fdToPath.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[MacOSFileEvents] Init failed");
            _kq = -1;
        }
    }

    [SupportedOSPlatform("macos")]
    private void WatchDirectory(string path)
    {
        try
        {
            var fd = open(path, O_EVTONLY);
            if (fd < 0) return;

            var kev = new KEvent
            {
                ident = (ulong)fd,
                filter = EVFILT_VNODE,
                flags = EV_ADD | EV_ENABLE | EV_CLEAR,
                fflags = NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_DELETE | NOTE_RENAME | NOTE_LINK,
                data = 0,
                udata = IntPtr.Zero,
            };

            var changes = new[] { kev };
            var timeout = new Timespec { tv_sec = 0, tv_nsec = 0 };
            var n = kevent(_kq, changes, 1, Array.Empty<KEvent>(), 0, ref timeout);
            if (n < 0)
            {
                close(fd);
                return;
            }

            _fdToPath[fd] = path;
        }
        catch { }
    }

    [SupportedOSPlatform("macos")]
    private void DrainVnodeEvents()
    {
        try
        {
            var events = new KEvent[32];
            var timeout = new Timespec { tv_sec = 0, tv_nsec = 0 };
            var n = kevent(_kq, Array.Empty<KEvent>(), 0, events, events.Length, ref timeout);
            if (n <= 0) return;

            lock (_lock)
            {
                for (var i = 0; i < n; i++)
                {
                    var fd = (int)events[i].ident;
                    if (!_fdToPath.TryGetValue(fd, out var path))
                        continue;

                    if (_events.Count >= MaxEvents)
                        _events.Dequeue();
                    _events.Enqueue(path);
                }
            }
        }
        catch { }
    }

    private static void Classify(string dirPath, List<Signal> signals)
    {
        var lower = dirPath.ToLowerInvariant();
        if (lower.Contains("launchdaemon") || lower.Contains("launchagent"))
        {
            signals.Add(new Signal($"macos_file_event:persistence_dir:{Path.GetFileName(dirPath)}", 80, 0.85));
            return;
        }

        if (lower.Contains("privilegedhelper") || lower.Contains("/library/extensions"))
        {
            signals.Add(new Signal($"macos_file_event:privileged_path:{Path.GetFileName(dirPath)}", 85, 0.88));
            return;
        }

        if (lower.Contains("/tmp") || lower.Contains("/private/tmp"))
        {
            signals.Add(new Signal("macos_file_event:tmp_write", 45, 0.55));
            return;
        }

        signals.Add(new Signal($"macos_file_event:sensitive_dir:{Path.GetFileName(dirPath)}", 55, 0.65));
    }

    // --- kqueue P/Invoke (aligned with MacOSKqueueMonitor) ---
    private const short EVFILT_VNODE = -4;
    private const ushort EV_ADD = 0x0001;
    private const ushort EV_ENABLE = 0x0004;
    private const ushort EV_CLEAR = 0x0020;
    private const uint NOTE_DELETE = 0x00000001;
    private const uint NOTE_WRITE = 0x00000002;
    private const uint NOTE_EXTEND = 0x00000004;
    private const uint NOTE_ATTRIB = 0x00000008;
    private const uint NOTE_LINK = 0x00000010;
    private const uint NOTE_RENAME = 0x00000020;
    private const int O_EVTONLY = 0x8000;

    [StructLayout(LayoutKind.Sequential)]
    private struct KEvent
    {
        public ulong ident;
        public short filter;
        public ushort flags;
        public uint fflags;
        public long data;
        public IntPtr udata;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Timespec
    {
        public long tv_sec;
        public long tv_nsec;
    }

    [DllImport("libc", EntryPoint = "kqueue", SetLastError = true)]
    private static extern int kqueue();

    [DllImport("libc", EntryPoint = "kevent", SetLastError = true)]
    private static extern int kevent(
        int kq,
        KEvent[] changelist,
        int nchanges,
        KEvent[] eventlist,
        int nevents,
        ref Timespec timeout);

    [DllImport("libc", EntryPoint = "open", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int open(string path, int flags);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int close(int fd);
}
