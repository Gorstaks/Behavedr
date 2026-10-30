namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS EndpointSecurity client (production, 0.3.5).
/// Primary: libbehavedr_es.dylib poll ABI (in-process, needs ES entitlement).
/// Secondary: JSONL from ES host binary at /var/run/behavedr/es.events
/// (when agent is not entitled but host extension/daemon is publishing).
/// Soft-fails to <see cref="MacOSKqueueMonitor"/> when neither path works.
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacOSEndpointSecurityMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<MacOSEndpointSecurityMonitor> _logger;
    private readonly object _lock = new();
    private readonly Queue<EsEvent> _events = new();
    private const int MaxEvents = 2000;

    private IntPtr _client = IntPtr.Zero;
    private IntPtr _lib = IntPtr.Zero;
    private bool _active;
    private bool _initialized;
    private Thread? _pollThread;
    private volatile bool _stop;
    private string _mode = "inactive";

    // JSONL fallback state
    private string? _jsonlPath;
    private long _jsonlOffset;
    private DateTime _jsonlLastRotateCheck = DateTime.MinValue;

    private BehavedrEsCreate? _create;
    private BehavedrEsSubscribeDefault? _subscribeDefault;
    private BehavedrEsSubscribe? _subscribeLegacy;
    private BehavedrEsPoll? _poll;
    private BehavedrEsDelete? _delete;
    private BehavedrEsSetAuth? _setAuth;

    public string ActiveMode => _mode;
    public string PlatformName => "MacOSEndpointSecurity";
    public bool IsSupported => OperatingSystem.IsMacOS();
    public bool IsActive => _active;

    public MacOSEndpointSecurityMonitor(ILogger<MacOSEndpointSecurityMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSEndpointSecurityMonitor>.Instance;
    }

    public bool TryConnect()
    {
        if (_initialized) return _active;
        _initialized = true;
        if (!OperatingSystem.IsMacOS()) return false;

        try
        {
            if (TryStartInProcess())
                return true;

            if (TryStartJsonlFallback())
                return true;

            Telemetry.SecurityTelemetry.ReportPlatformSoftFail("endpointsecurity");
            _logger.LogWarning(
                "[ES] Inactive - no dylib/entitlement and no host JSONL. kqueue remains primary. " +
                "See packaging/unix/macos-endpointsecurity.md");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ES] Connect failed");
            Telemetry.SecurityTelemetry.ReportPlatformSoftFail("endpointsecurity");
            return false;
        }
    }

    private bool TryStartInProcess()
    {
        if (!TryBindLibrary(out var err))
        {
            _logger.LogDebug("[ES] dylib path unavailable: {Err}", err);
            return false;
        }

        int rc = _create!(out _client);
        if (rc != 0 || _client == IntPtr.Zero)
        {
            _logger.LogDebug("[ES] es_new_client failed rc={Rc} (need entitlement)", rc);
            return false;
        }

        var authMode = string.Equals(
            Environment.GetEnvironmentVariable("BEHAVEDR_ES_AUTH"), "1", StringComparison.Ordinal);
        _setAuth?.Invoke(authMode ? 1 : 0);

        if (_subscribeDefault is not null)
        {
            rc = _subscribeDefault(_client, authMode ? 1 : 0);
            if (rc < 0)
            {
                _logger.LogWarning("[ES] subscribe_default failed rc={Rc}", rc);
                _delete!(_client);
                _client = IntPtr.Zero;
                return false;
            }
            if (authMode)
                _logger.LogWarning("[ES] AUTH_EXEC denylist enabled");
        }
        else if (_subscribeLegacy is not null)
        {
            var events = BuildDefaultEventIds(authMode);
            rc = _subscribeLegacy(_client, events, events.Length);
            if (rc != 0)
            {
                _delete!(_client);
                _client = IntPtr.Zero;
                return false;
            }
        }
        else
        {
            _delete!(_client);
            _client = IntPtr.Zero;
            return false;
        }

        _mode = "poll-ring-bridge";
        _active = true;
        _stop = false;
        _pollThread = new Thread(PollLoopDylib)
        {
            IsBackground = true,
            Name = "Behavedr-ES-poll",
        };
        _pollThread.Start();
        _logger.LogInformation("[ES] Active - in-process poll bridge, auth={Auth}", authMode);
        return true;
    }

    private bool TryStartJsonlFallback()
    {
        var path = Environment.GetEnvironmentVariable("BEHAVEDR_ES_EVENTS_PATH");
        if (string.IsNullOrWhiteSpace(path))
            path = "/var/run/behavedr/es.events";

        if (!File.Exists(path))
        {
            _logger.LogDebug("[ES] JSONL host file not present at {Path}", path);
            return false;
        }

        try
        {
            // Start at end so we only consume new events (avoid flood on restart)
            var fi = new FileInfo(path);
            _jsonlOffset = fi.Length;
            _jsonlPath = path;
            _mode = "jsonl-host";
            _active = true;
            _stop = false;
            _pollThread = new Thread(PollLoopJsonl)
            {
                IsBackground = true,
                Name = "Behavedr-ES-jsonl",
            };
            _pollThread.Start();
            _logger.LogInformation(
                "[ES] Active - JSONL host fallback ({Path}). In-process dylib preferred when entitled.",
                path);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[ES] JSONL fallback open failed");
            return false;
        }
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        if (!_initialized)
            TryConnect();

        var signals = new List<Signal>();
        if (!_active)
            return Task.FromResult<IEnumerable<Signal>>(signals); // kqueue primary; no per-cycle noise

        List<EsEvent> batch;
        lock (_lock)
        {
            batch = _events.ToList();
            _events.Clear();
        }

        foreach (var e in batch)
        {
            var baseWeight = e.Kind is "exec" or "auth_exec" or "auth_denied" ? 40 : 22;
            signals.Add(new Signal(
                $"es_{e.Kind}:{e.ProcessName}:pid:{e.Pid}:{Truncate(e.Path, 80)}",
                baseWeight, 0.88));

            if (e.Kind is "exec" or "auth_exec" or "auth_denied")
            {
                var off = ThreatHeuristics.Evaluate(e.ProcessName, e.Path);
                if (off is { } o)
                {
                    signals.Add(new Signal(
                        $"es_offensive:{o.Tag}:{o.Detail}:pid:{e.Pid}",
                        o.Weight, o.Confidence));
                }
            }

            if (e.Kind == "auth_denied")
                signals.Add(new Signal($"es_auth_denied:{e.ProcessName}:pid:{e.Pid}:{Truncate(e.Path, 64)}", 90, 0.95));
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    public void Dispose()
    {
        _stop = true;
        try { _pollThread?.Join(1000); } catch { /* ignore */ }
        if (_client != IntPtr.Zero && _delete is not null)
        {
            try { _delete(_client); } catch { /* ignore */ }
            _client = IntPtr.Zero;
        }
        _active = false;
        _mode = "inactive";
    }

    private void PollLoopDylib()
    {
        var kind = new byte[32];
        var name = new byte[64];
        var path = new byte[512];
        while (!_stop)
        {
            try
            {
                int n = 0;
                while (n++ < 200 && _poll is not null)
                {
                    int rc = _poll(kind, kind.Length, out int pid, name, name.Length, path, path.Length);
                    if (rc <= 0) break;
                    Enqueue(new EsEvent(CString(kind), pid, CString(name), CString(path)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ES] dylib poll error");
            }
            Thread.Sleep(25);
        }
    }

    private void PollLoopJsonl()
    {
        while (!_stop)
        {
            try
            {
                DrainJsonl();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ES] jsonl poll error");
            }
            Thread.Sleep(100);
        }
    }

    private void DrainJsonl()
    {
        if (_jsonlPath is null) return;

        // Detect truncate/rotate
        if ((DateTime.UtcNow - _jsonlLastRotateCheck).TotalSeconds > 2)
        {
            _jsonlLastRotateCheck = DateTime.UtcNow;
            try
            {
                var len = new FileInfo(_jsonlPath).Length;
                if (len < _jsonlOffset)
                    _jsonlOffset = 0;
            }
            catch { return; }
        }

        using var fs = new FileStream(
            _jsonlPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (fs.Length <= _jsonlOffset)
            return;
        fs.Seek(_jsonlOffset, SeekOrigin.Begin);
        using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        string? line;
        int read = 0;
        while ((line = reader.ReadLine()) is not null && read < 500)
        {
            read++;
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (TryParseJsonl(line, out var ev))
                Enqueue(ev);
        }
        _jsonlOffset = fs.Position;
    }

    private static bool TryParseJsonl(string line, out EsEvent ev)
    {
        ev = default;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var kind = root.TryGetProperty("kind", out var k) ? k.GetString() ?? "event" : "event";
            var pid = root.TryGetProperty("pid", out var p) ? p.GetInt32() : 0;
            var name = root.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            var path = root.TryGetProperty("path", out var pa) ? pa.GetString() ?? "" : "";
            if (pid <= 0 && string.IsNullOrEmpty(kind)) return false;
            ev = new EsEvent(kind, pid, name, path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void Enqueue(EsEvent ev)
    {
        lock (_lock)
        {
            _events.Enqueue(ev);
            while (_events.Count > MaxEvents)
                _events.Dequeue();
        }
    }

    private bool TryBindLibrary(out string error)
    {
        error = "";
        foreach (var path in LibraryCandidates())
        {
            if (!File.Exists(path)) continue;
            _lib = dlopen(path, RTLD_NOW);
            if (_lib == IntPtr.Zero) continue;

            _create = Load<BehavedrEsCreate>("behavedr_es_create");
            _subscribeDefault = LoadOptional<BehavedrEsSubscribeDefault>("behavedr_es_subscribe_default");
            _subscribeLegacy = LoadOptional<BehavedrEsSubscribe>("behavedr_es_subscribe");
            _poll = Load<BehavedrEsPoll>("behavedr_es_poll");
            _delete = Load<BehavedrEsDelete>("behavedr_es_delete");
            _setAuth = LoadOptional<BehavedrEsSetAuth>("behavedr_es_set_auth_mode");

            if (_create is null || _poll is null || _delete is null ||
                (_subscribeDefault is null && _subscribeLegacy is null))
            {
                error = $"incomplete ABI in {path}";
                continue;
            }
            _logger.LogInformation(
                "[ES] Bound library {Path} (subscribe_default={Def})",
                path, _subscribeDefault is not null);
            return true;
        }
        error = "libbehavedr_es.dylib not found or incomplete";
        return false;
    }

    private T? Load<T>(string symbol) where T : Delegate
    {
        var sym = dlsym(_lib, symbol);
        return sym == IntPtr.Zero ? null : Marshal.GetDelegateForFunctionPointer<T>(sym);
    }

    private T? LoadOptional<T>(string symbol) where T : Delegate => Load<T>(symbol);

    private static IEnumerable<string> LibraryCandidates()
    {
        yield return Path.Combine(AppContext.BaseDirectory, "libbehavedr_es.dylib");
        yield return "/opt/behavedr/libbehavedr_es.dylib";
        yield return Path.Combine(Directory.GetCurrentDirectory(), "libbehavedr_es.dylib");
        yield return Path.Combine(Directory.GetCurrentDirectory(), "native", "macos", "es_bridge", "libbehavedr_es.dylib");
    }

    private static string CString(byte[] buf)
    {
        var n = Array.IndexOf(buf, (byte)0);
        if (n < 0) n = buf.Length;
        return Encoding.UTF8.GetString(buf, 0, n);
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= n ? s : s[..n];

    private static uint[] BuildDefaultEventIds(bool authMode)
    {
        var list = new List<uint> { 9, 11, 15, 10, 13 };
        if (authMode) list.Add(0);
        return list.ToArray();
    }

    private readonly record struct EsEvent(string Kind, int Pid, string ProcessName, string Path);

    private const int RTLD_NOW = 2;

    [DllImport("libSystem.B.dylib")]
    private static extern IntPtr dlopen(string path, int mode);

    [DllImport("libSystem.B.dylib")]
    private static extern IntPtr dlsym(IntPtr handle, string symbol);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsCreate(out IntPtr client);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsSubscribeDefault(IntPtr client, int authMode);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsSubscribe(IntPtr client, uint[] events, int count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsPoll(
        byte[] kind, int kindLen,
        out int pid,
        byte[] name, int nameLen,
        byte[] path, int pathLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void BehavedrEsDelete(IntPtr client);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsSetAuth(int enabled);
}
