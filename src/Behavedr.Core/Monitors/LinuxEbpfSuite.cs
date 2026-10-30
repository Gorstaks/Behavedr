namespace Behavedr.Core.Monitors;

using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Shared production eBPF suite session (0.3.3).
/// One loader + one poll thread; exec/file/net monitors drain by event kind.
/// Avoids loading the same BPF object three times and keeps map cursor consistent.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfSuite : IDisposable
{
    public const int KindExec = 1;
    public const int KindOpen = 2;
    public const int KindConnect = 3;

    private static readonly object Gate = new();
    private static LinuxEbpfSuite? _instance;

    private readonly ILogger _logger;
    private readonly ConcurrentQueue<LinuxEbpfLoader.EbpfMapEvent> _exec = new();
    private readonly ConcurrentQueue<LinuxEbpfLoader.EbpfMapEvent> _open = new();
    private readonly ConcurrentQueue<LinuxEbpfLoader.EbpfMapEvent> _connect = new();
    private const int MaxPerQueue = 2000;

    private LinuxEbpfLoader? _loader;
    private Thread? _pollThread;
    private volatile bool _stop;
    private bool _startAttempted;
    private bool _active;

    public bool IsActive => _active;
    public string? LoadedObjectPath => _loader?.LoadedObjectPath;
    public string ActiveMode => _active ? "suite-pinned-maps" : "inactive";

    private LinuxEbpfSuite(ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>Process-wide shared suite (lazy). Safe to call from multiple monitors.</summary>
    public static LinuxEbpfSuite Shared(ILogger? logger = null)
    {
        if (_instance is not null)
            return _instance;
        lock (Gate)
        {
            _instance ??= new LinuxEbpfSuite(logger ?? NullLogger.Instance);
            return _instance;
        }
    }

    /// <summary>
    /// Load object + start poller once. Returns true when maps are readable.
    /// Soft-fails (false) when object/caps/bpftool missing.
    /// </summary>
    public bool TryStart()
    {
        if (_active)
            return true;

        lock (Gate)
        {
            if (_active)
                return true;
            if (_startAttempted)
                return false;
            _startAttempted = true;

            if (!OperatingSystem.IsLinux())
                return false;

            try
            {
                _loader = new LinuxEbpfLoader(_logger);
                if (!_loader.TryLoad())
                {
                    _loader.Dispose();
                    _loader = null;
                    Telemetry.SecurityTelemetry.ReportPlatformSoftFail("ebpf");
                    _logger.LogWarning(
                        "[eBPF-suite] Not active. Install behavedr_exec.bpf.o, bpftool, CAP_BPF. " +
                        "cn_proc / fanotify /proc remain primary.");
                    return false;
                }

                _stop = false;
                _pollThread = new Thread(PollLoop)
                {
                    IsBackground = true,
                    Name = "Behavedr-eBPF-suite",
                };
                _pollThread.Start();
                _active = true;
                _logger.LogInformation("[eBPF-suite] Active - {Obj}", _loader.LoadedObjectPath);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[eBPF-suite] Start failed");
                Telemetry.SecurityTelemetry.ReportPlatformSoftFail("ebpf");
                _loader?.Dispose();
                _loader = null;
                return false;
            }
        }
    }

    public List<LinuxEbpfLoader.EbpfMapEvent> DrainExec(int max = 500) => Drain(_exec, max);
    public List<LinuxEbpfLoader.EbpfMapEvent> DrainOpen(int max = 500) => Drain(_open, max);
    public List<LinuxEbpfLoader.EbpfMapEvent> DrainConnect(int max = 500) => Drain(_connect, max);

    public void Dispose()
    {
        _stop = true;
        try { _pollThread?.Join(1500); } catch { /* ignore */ }
        _loader?.Dispose();
        _loader = null;
        _active = false;
    }

    private void PollLoop()
    {
        while (!_stop)
        {
            try
            {
                if (_loader is null)
                    break;
                var drained = _loader.DrainNewEvents();
                foreach (var e in drained)
                {
                    switch (e.Kind)
                    {
                        case KindExec:
                            Enqueue(_exec, e);
                            break;
                        case KindOpen:
                            Enqueue(_open, e);
                            break;
                        case KindConnect:
                            Enqueue(_connect, e);
                            break;
                        default:
                            Enqueue(_exec, e);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[eBPF-suite] poll error");
            }
            Thread.Sleep(40);
        }
    }

    private static void Enqueue(ConcurrentQueue<LinuxEbpfLoader.EbpfMapEvent> q, LinuxEbpfLoader.EbpfMapEvent e)
    {
        q.Enqueue(e);
        while (q.Count > MaxPerQueue && q.TryDequeue(out _)) { }
    }

    private static List<LinuxEbpfLoader.EbpfMapEvent> Drain(
        ConcurrentQueue<LinuxEbpfLoader.EbpfMapEvent> q, int max)
    {
        var list = new List<LinuxEbpfLoader.EbpfMapEvent>();
        while (list.Count < max && q.TryDequeue(out var e))
            list.Add(e);
        return list;
    }
}
