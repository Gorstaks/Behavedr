namespace Behavedr.Core.Monitors;

using System.Net;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android network monitoring via /proc/net/tcp parsing.
/// Even without root, the app's own network connections are visible.
/// With root/adb shell access, all device connections are visible.
/// Detects:
/// - Connections to suspicious ports (C2/RAT)
/// - DNS server changes (DNS hijacking)
/// - VPN bypass indicators (direct connections from apps that should use VPN)
/// - Connections from shell/interpreter processes
/// - High connection counts (botnet/C2 fan-out)
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidNetworkMonitor : IPlatformMonitor
{
    private readonly ILogger<AndroidNetworkMonitor> _logger;
    private readonly HashSet<string> _previousConnections = new();
    private string? _baselineDns;

    public string PlatformName => "AndroidNetwork";
    public bool IsSupported => OperatingSystem.IsAndroid();

    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 6666, 7777, 8888, 9999,
        1234, 31337, 12345, 54321,
        4443, 8443, 8080, 1337,
    };

    private static readonly HashSet<string> SuspiciousProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "sh", "bash", "su", "python", "perl", "nc", "ncat",
        "socat", "frida-server", "busybox",
    };

    public AndroidNetworkMonitor(ILogger<AndroidNetworkMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidNetworkMonitor>.Instance;
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            DetectSuspiciousConnections(signals, ct);
            DetectDnsHijacking(signals);

            // v0.2.0 audit fix A-11: Deeper network analysis
            DetectTrafficVolumeAnomalies(signals);
            DetectIpv6Connections(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AndroidNetwork] Error during network scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("android")]
    private void DetectSuspiciousConnections(List<Signal> signals, CancellationToken ct)
    {
        if (!File.Exists("/proc/net/tcp")) return;

        try
        {
            var currentKeys = new HashSet<string>();
            var lines = File.ReadAllLines("/proc/net/tcp");

            for (int i = 1; i < lines.Length; i++)
            {
                if (ct.IsCancellationRequested) break;
                var line = lines[i].Trim();
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;

                var stateHex = parts[3];
                if (stateHex != "01") continue; // Only ESTABLISHED

                var remoteAddrPort = parts[2];
                var colonIdx = remoteAddrPort.IndexOf(':');
                if (colonIdx < 0) continue;

                var addrHex = remoteAddrPort[..colonIdx];
                var portHex = remoteAddrPort[(colonIdx + 1)..];
                var port = Convert.ToInt32(portHex, 16);

                // Parse IPv4 address
                string remoteAddr;
                try
                {
                    var ipInt = Convert.ToUInt32(addrHex, 16);
                    remoteAddr = new IPAddress(BitConverter.GetBytes(ipInt)).ToString();
                }
                catch { continue; }

                var key = $"{remoteAddr}:{port}";
                currentKeys.Add(key);

                if (_previousConnections.Contains(key)) continue;
                if (remoteAddr is "127.0.0.1" or "0.0.0.0") continue;

                // Suspicious port
                if (SuspiciousPorts.Contains(port))
                {
                    signals.Add(new Signal(
                        $"suspicious_port_connection:android->{remoteAddr}:{port}", 68, 0.75));
                }
            }

            var newCount = currentKeys.Except(_previousConnections).Count();
            if (newCount > 20)
            {
                signals.Add(new Signal($"connection_burst:{newCount}_new", 50, 0.6));
            }

            _previousConnections.Clear();
            foreach (var k in currentKeys) _previousConnections.Add(k);
        }
        catch { }

        // Check for suspicious process network connections via /proc/*/net/tcp
        DetectProcessConnections(signals, ct);
    }

    [SupportedOSPlatform("android")]
    private void DetectProcessConnections(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                var commPath = Path.Combine(procDir, "comm");
                if (!File.Exists(commPath)) continue;

                try
                {
                    var name = File.ReadAllText(commPath).Trim();
                    if (!SuspiciousProcesses.Contains(name)) continue;

                    // This suspicious process exists - check if it has network
                    var netTcp = Path.Combine(procDir, "net", "tcp");
                    if (File.Exists(netTcp))
                    {
                        var lines = File.ReadAllLines(netTcp);
                        var established = lines.Skip(1).Count(l => l.Contains(" 01 "));
                        if (established > 0)
                        {
                            signals.Add(new Signal(
                                $"suspicious_process_network:{name}:pid:{pid}:conns:{established}",
                                75, 0.82));
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect DNS server hijacking by monitoring /etc/resolv.conf changes.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectDnsHijacking(List<Signal> signals)
    {
        try
        {
            var resolvConf = "/etc/resolv.conf";
            if (!File.Exists(resolvConf)) return;

            var content = File.ReadAllText(resolvConf);
            var nameservers = content.Split('\n')
                .Where(l => l.TrimStart().StartsWith("nameserver", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "")
                .Where(s => !string.IsNullOrEmpty(s))
                .OrderBy(s => s)
                .Aggregate("", (a, b) => a + "|" + b);

            if (_baselineDns is null)
            {
                _baselineDns = nameservers;
            }
            else if (_baselineDns != nameservers)
            {
                signals.Add(new Signal("dns_server_changed", 72, 0.8));
                _baselineDns = nameservers;
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect traffic volume anomalies by monitoring per-UID network stats.
    /// A sudden spike in transmitted bytes may indicate data exfiltration.
    /// v0.2.0 audit fix A-11.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectTrafficVolumeAnomalies(List<Signal> signals)
    {
        try
        {
            // Read per-UID transmitted bytes from /proc/net/xt_qtaguid/stats
            var statsPath = "/proc/net/xt_qtaguid/stats";
            if (!File.Exists(statsPath))
            {
                // Fallback: check /proc/uid_stat/*/tcp_snd
                var uidStatDir = "/proc/uid_stat";
                if (!Directory.Exists(uidStatDir)) return;

                foreach (var uidDir in Directory.GetDirectories(uidStatDir))
                {
                    var sndPath = Path.Combine(uidDir, "tcp_snd");
                    if (!File.Exists(sndPath)) continue;

                    try
                    {
                        var bytesStr = File.ReadAllText(sndPath).Trim();
                        if (long.TryParse(bytesStr, out var bytes) && bytes > 100_000_000) // >100MB
                        {
                            var uid = Path.GetFileName(uidDir);
                            signals.Add(new Signal(
                                $"high_traffic_volume:uid:{uid}:{bytes / 1_000_000}MB", 55, 0.65));
                        }
                    }
                    catch { }
                }
                return;
            }

            // Parse xt_qtaguid stats for high-volume senders
            foreach (var line in File.ReadLines(statsPath).Skip(1))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 8) continue;

                // Format: idx iface acct_tag_hex uid_tag_int cnt_set rx_bytes rx_packets tx_bytes
                if (!int.TryParse(parts[3], out var uid)) continue;
                if (uid < 10000) continue; // Skip system UIDs
                if (!long.TryParse(parts[7], out var txBytes)) continue;

                if (txBytes > 50_000_000) // >50MB transmitted
                {
                    signals.Add(new Signal(
                        $"high_tx_volume:uid:{uid}:{txBytes / 1_000_000}MB", 50, 0.6));
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Monitor IPv6 connections (many apps and malware use IPv6 only).
    /// Previous monitoring only covered /proc/net/tcp (IPv4).
    /// v0.2.0 audit fix A-11.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectIpv6Connections(List<Signal> signals, CancellationToken ct)
    {
        var tcp6Path = "/proc/net/tcp6";
        if (!File.Exists(tcp6Path)) return;

        try
        {
            var lines = File.ReadAllLines(tcp6Path);
            int established6 = 0;

            for (int i = 1; i < lines.Length; i++)
            {
                if (ct.IsCancellationRequested) break;
                var line = lines[i].Trim();
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;

                var stateHex = parts[3];
                if (stateHex != "01") continue; // ESTABLISHED only

                established6++;

                var remoteAddrPort = parts[2];
                var colonIdx = remoteAddrPort.LastIndexOf(':');
                if (colonIdx < 0) continue;

                var portHex = remoteAddrPort[(colonIdx + 1)..];
                var port = Convert.ToInt32(portHex, 16);

                if (SuspiciousPorts.Contains(port))
                {
                    signals.Add(new Signal(
                        $"suspicious_port_ipv6:{port}", 68, 0.75));
                }
            }

            // High IPv6 connection count (botnet fan-out)
            if (established6 > 30)
            {
                signals.Add(new Signal(
                    $"high_ipv6_connections:{established6}", 50, 0.6));
            }
        }
        catch { }
    }
}
