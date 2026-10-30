namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux network depth monitor (production, 0.3.3).
/// Primary: suite EV_CONNECT events (connect() peer address from eBPF).
/// Secondary: /proc/net/{tcp,tcp6,udp} scan when suite inactive.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfNetMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxEbpfNetMonitor> _logger;
    private bool _initialized;
    private bool _suiteActive;
    private readonly Dictionary<string, int> _remoteHits = new(StringComparer.Ordinal);
    private DateTime _lastProcScan = DateTime.MinValue;
    private readonly TimeSpan _procInterval = TimeSpan.FromSeconds(2);

    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 6666, 1337, 31337, 8080, 8443, 8888, 9999, 4443, 9001, 9030,
    };

    public string PlatformName => "LinuxEbpfNet";
    public bool IsSupported => OperatingSystem.IsLinux();
    public bool IsActive => _suiteActive;
    public string ActiveMode => _suiteActive ? "suite-connect" : "proc-net-scan";

    public LinuxEbpfNetMonitor(ILogger<LinuxEbpfNetMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxEbpfNetMonitor>.Instance;
    }

    public bool TryInitialize()
    {
        if (_initialized) return _suiteActive;
        _initialized = true;
        if (!OperatingSystem.IsLinux()) return false;
        _suiteActive = LinuxEbpfSuite.Shared(_logger).TryStart();
        _logger.LogInformation("[eBPF-net] Mode={Mode}", ActiveMode);
        return _suiteActive;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        if (!_initialized)
            TryInitialize();

        var signals = new List<Signal>();
        if (_suiteActive)
            DrainSuiteConnect(signals);
        else
            ScanProcNetAll(signals);

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void DrainSuiteConnect(List<Signal> signals)
    {
        var batch = LinuxEbpfSuite.Shared().DrainConnect();
        foreach (var e in batch)
        {
            if (e.Pid <= 1) continue;
            var comm = string.IsNullOrEmpty(e.Comm) ? "unknown" : e.Comm;
            var peer = e.Path ?? "";

            if (TryParsePort(peer, out var port) && SuspiciousPorts.Contains(port))
            {
                signals.Add(new Signal(
                    $"ebpf_net_suspicious_port:{peer}:pid:{e.Pid}:{comm}",
                    78, 0.85));
            }
            else if (!string.IsNullOrEmpty(peer))
            {
                // Low-weight connect telemetry (not every connect is malicious)
                signals.Add(new Signal(
                    $"ebpf_connect:{comm}:pid:{e.Pid}:{Truncate(peer, 48)}",
                    20, 0.55));
            }

            if (!string.IsNullOrEmpty(peer))
            {
                _remoteHits.TryGetValue(peer, out var hits);
                hits++;
                _remoteHits[peer] = hits;
                if (hits >= 20)
                {
                    signals.Add(new Signal(
                        $"ebpf_net_connect_storm:{peer}:hits:{hits}:pid:{e.Pid}",
                        70, 0.75));
                    _remoteHits[peer] = 0;
                }
            }
        }

        if (_remoteHits.Count > 2000)
            _remoteHits.Clear();
    }

    private void ScanProcNetAll(List<Signal> signals)
    {
        if ((DateTime.UtcNow - _lastProcScan) < _procInterval)
            return;
        _lastProcScan = DateTime.UtcNow;

        try
        {
            ScanProcNet("/proc/net/tcp", 4, signals);
            ScanProcNet("/proc/net/tcp6", 6, signals);
            ScanProcNet("/proc/net/udp", 4, signals);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[eBPF-net] proc scan failed");
            signals.Add(new Signal("ebpf_net_scan_error", 10, 0.3));
        }
    }

    private void ScanProcNet(string path, int family, List<Signal> signals)
    {
        if (!File.Exists(path)) return;

        var lines = File.ReadLines(path).Skip(1);
        int total = 0;
        int suspicious = 0;
        foreach (var line in lines)
        {
            total++;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;

            var rem = parts[2];
            var state = parts[3];
            if (!TryParseHexEndpoint(rem, family, out var ip, out var port))
                continue;

            if (ip is "0.0.0.0" or "::" or "127.0.0.1" or "::1")
                continue;

            bool established = state.Equals("01", StringComparison.OrdinalIgnoreCase);
            if (!established && !path.Contains("udp", StringComparison.Ordinal))
                continue;

            var key = $"{ip}:{port}";
            _remoteHits.TryGetValue(key, out var hits);
            hits++;
            _remoteHits[key] = hits;

            if (SuspiciousPorts.Contains(port))
            {
                suspicious++;
                signals.Add(new Signal(
                    $"ebpf_net_suspicious_port:{ip}:{port}:pid_unknown",
                    75, 0.8));
            }

            if (hits >= 20)
            {
                signals.Add(new Signal(
                    $"ebpf_net_connect_storm:{ip}:{port}:hits:{hits}",
                    70, 0.75));
                _remoteHits[key] = 0;
            }
        }

        if (_remoteHits.Count > 2000)
            _remoteHits.Clear();

        if (suspicious > 0)
            signals.Add(new Signal($"ebpf_net_batch_suspicious:{suspicious}:of:{total}", 40, 0.6));
    }

    private static bool TryParsePort(string peer, out int port)
    {
        port = 0;
        if (string.IsNullOrEmpty(peer)) return false;
        var idx = peer.LastIndexOf(':');
        if (idx < 0 || idx >= peer.Length - 1) return false;
        return int.TryParse(peer.AsSpan(idx + 1), out port);
    }

    private static bool TryParseHexEndpoint(string hex, int family, out string ip, out int port)
    {
        ip = "";
        port = 0;
        var segs = hex.Split(':');
        if (segs.Length != 2) return false;
        if (!int.TryParse(segs[1], System.Globalization.NumberStyles.HexNumber, null, out port))
            return false;

        try
        {
            if (family == 4)
            {
                var addr = Convert.ToUInt32(segs[0], 16);
                var b0 = (byte)(addr & 0xff);
                var b1 = (byte)((addr >> 8) & 0xff);
                var b2 = (byte)((addr >> 16) & 0xff);
                var b3 = (byte)((addr >> 24) & 0xff);
                ip = $"{b0}.{b1}.{b2}.{b3}";
                return true;
            }

            ip = "v6:" + segs[0][..Math.Min(8, segs[0].Length)];
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= n ? s : s[..n];
}
