namespace Behavedr.Core.Monitors;

using System.Net;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux network connection monitor using /proc/net/tcp{,6} and /proc/net/udp{,6}.
/// Provides PID-attributed connection tracking by resolving socket inodes via /proc/*/fd.
/// Detects:
/// - Connections to suspicious ports (common C2/RAT)
/// - High connection counts from non-browser processes
/// - Connection bursts (rapid fan-out)
/// - Listening sockets on unexpected ports (backdoor listeners)
/// - Connections from shell/LOLBin processes
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxNetworkMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxNetworkMonitor> _logger;
    private readonly HashSet<string> _previousConnections = new();

    public string PlatformName => "LinuxNetwork";
    public bool IsSupported => OperatingSystem.IsLinux();

    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 6666, 7777, 8888, 9999,
        1234, 31337, 12345, 54321,
        2222, 3333, 4443, 8443, 8080,
    };

    private static readonly HashSet<string> HighConnectionAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "chromium", "brave", "opera",
        "nginx", "apache2", "httpd", "node", "java",
        "docker", "containerd", "code", "electron",
    };

    private static readonly HashSet<string> SuspiciousConnectors = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash", "sh", "dash", "zsh", "fish", "csh",
        "python", "python3", "perl", "ruby", "php",
        "curl", "wget", "nc", "ncat", "socat",
        "certutil", "openssl",
    };

    public LinuxNetworkMonitor(ILogger<LinuxNetworkMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxNetworkMonitor>.Instance;
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var inodeToPid = BuildInodeToPidMap(ct);
            var connections = ParseProcNetTcp("/proc/net/tcp", inodeToPid, ct);
            connections.AddRange(ParseProcNetTcp("/proc/net/tcp6", inodeToPid, ct));

            var currentKeys = new HashSet<string>();

            // Per-PID connection count
            var pidConnectionCount = new Dictionary<int, int>();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;

                var key = $"{conn.Pid}:{conn.RemoteAddr}:{conn.RemotePort}";
                currentKeys.Add(key);

                // Skip loopback
                if (conn.RemoteAddr is "127.0.0.1" or "0.0.0.0" or "::1" or "::") continue;

                // Track per-PID counts
                pidConnectionCount.TryGetValue(conn.Pid, out var count);
                pidConnectionCount[conn.Pid] = count + 1;

                // Skip already known
                if (_previousConnections.Contains(key)) continue;

                var procName = GetProcessName(conn.Pid) ?? $"pid:{conn.Pid}";

                // Suspicious port connections (ESTABLISHED only)
                if (conn.State == TcpState.Established && SuspiciousPorts.Contains(conn.RemotePort))
                {
                    signals.Add(new Signal(
                        $"suspicious_port_connection:{procName}->{conn.RemoteAddr}:{conn.RemotePort}:pid:{conn.Pid}",
                        65, 0.72));
                }

                // Shell/interpreter making outbound connections
                if (conn.State == TcpState.Established && SuspiciousConnectors.Contains(procName))
                {
                    signals.Add(new Signal(
                        $"shell_outbound_connection:{procName}->{conn.RemoteAddr}:{conn.RemotePort}:pid:{conn.Pid}",
                        72, 0.78));
                }
            }

            // High connection count per process
            foreach (var (pid, connCount) in pidConnectionCount)
            {
                if (connCount > 50)
                {
                    var procName = GetProcessName(pid) ?? $"pid:{pid}";
                    if (!HighConnectionAllowlist.Contains(procName))
                    {
                        signals.Add(new Signal(
                            $"high_connection_count:{procName}({connCount}):pid:{pid}", 50, 0.62));
                    }
                }
            }

            // Connection burst detection
            var newConnections = currentKeys.Except(_previousConnections).Count();
            if (newConnections > 30)
            {
                signals.Add(new Signal($"connection_burst:{newConnections}_new", 45, 0.55));
            }

            // Detect unexpected listeners (backdoor)
            DetectBackdoorListeners(signals, inodeToPid, ct);

            _previousConnections.Clear();
            foreach (var k in currentKeys) _previousConnections.Add(k);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxNetwork] Error during network scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect listening sockets on unexpected ports from shell/suspicious processes (backdoor indicators).
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectBackdoorListeners(List<Signal> signals, Dictionary<long, int> inodeToPid, CancellationToken ct)
    {
        var listeners = ParseProcNetTcp("/proc/net/tcp", inodeToPid, ct)
            .Where(c => c.State == TcpState.Listen)
            .ToList();

        foreach (var listener in listeners)
        {
            if (ct.IsCancellationRequested) break;
            var procName = GetProcessName(listener.Pid) ?? $"pid:{listener.Pid}";

            // Shell processes listening on ports = almost certainly a backdoor
            if (SuspiciousConnectors.Contains(procName))
            {
                signals.Add(new Signal(
                    $"backdoor_listener:{procName}:port:{listener.LocalPort}:pid:{listener.Pid}",
                    88, 0.9));
            }
        }
    }

    /// <summary>
    /// Build inode -> PID mapping by scanning /proc/*/fd for socket inodes.
    /// This is how we attribute network connections to specific processes on Linux.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static Dictionary<long, int> BuildInodeToPidMap(CancellationToken ct)
    {
        var map = new Dictionary<long, int>();

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                var fdDir = Path.Combine(procDir, "fd");
                if (!Directory.Exists(fdDir)) continue;

                try
                {
                    foreach (var fdPath in Directory.GetFiles(fdDir))
                    {
                        try
                        {
                            var target = File.ResolveLinkTarget(fdPath, false)?.ToString() ?? "";
                            // Format: socket:[12345]
                            if (target.StartsWith("socket:[", StringComparison.Ordinal) &&
                                target.EndsWith(']'))
                            {
                                var inodeStr = target["socket:[".Length..^1];
                                if (long.TryParse(inodeStr, out var inode))
                                {
                                    map.TryAdd(inode, pid);
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch { }

        return map;
    }

    /// <summary>
    /// Parse /proc/net/tcp or /proc/net/tcp6 into connection records with PID attribution.
    /// Format: sl local_address rem_address st tx_queue:rx_queue ... inode
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static List<LinuxConnection> ParseProcNetTcp(string path, Dictionary<long, int> inodeToPid, CancellationToken ct)
    {
        var results = new List<LinuxConnection>();
        if (!File.Exists(path)) return results;

        try
        {
            var lines = File.ReadAllLines(path);
            // Skip header line
            for (int i = 1; i < lines.Length; i++)
            {
                if (ct.IsCancellationRequested) break;
                var line = lines[i].Trim();
                if (string.IsNullOrEmpty(line)) continue;

                try
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 10) continue;

                    var localAddrPort = parts[1]; // hex addr:hex port
                    var remoteAddrPort = parts[2];
                    var stateHex = parts[3];
                    var inode = long.Parse(parts[9]);

                    var state = (TcpState)Convert.ToInt32(stateHex, 16);
                    var (localAddr, localPort) = ParseHexAddrPort(localAddrPort);
                    var (remoteAddr, remotePort) = ParseHexAddrPort(remoteAddrPort);

                    inodeToPid.TryGetValue(inode, out var pid);

                    results.Add(new LinuxConnection
                    {
                        LocalAddr = localAddr,
                        LocalPort = localPort,
                        RemoteAddr = remoteAddr,
                        RemotePort = remotePort,
                        State = state,
                        Pid = pid,
                    });
                }
                catch { }
            }
        }
        catch { }

        return results;
    }

    /// <summary>
    /// Parse hex address:port format from /proc/net/tcp.
    /// IPv4: "0100007F:0050" -> ("127.0.0.1", 80)
    /// </summary>
    private static (string Addr, int Port) ParseHexAddrPort(string hexAddrPort)
    {
        var colonIdx = hexAddrPort.IndexOf(':');
        if (colonIdx < 0) return ("0.0.0.0", 0);

        var addrHex = hexAddrPort[..colonIdx];
        var portHex = hexAddrPort[(colonIdx + 1)..];

        var port = Convert.ToInt32(portHex, 16);

        string addr;
        if (addrHex.Length == 8)
        {
            // IPv4 - stored in little-endian
            var ipInt = Convert.ToUInt32(addrHex, 16);
            var bytes = BitConverter.GetBytes(ipInt);
            addr = new IPAddress(bytes).ToString();
        }
        else
        {
            // IPv6 - 32 hex chars
            addr = "::"; // Simplified; full parsing for IPv6
            try
            {
                var ipBytes = new byte[16];
                for (int j = 0; j < 16 && j * 2 + 1 < addrHex.Length; j++)
                {
                    // /proc/net/tcp6 stores in groups of 4 bytes, each group in network order
                    int groupIdx = j / 4;
                    int byteInGroup = j % 4;
                    int srcIdx = groupIdx * 8 + (3 - byteInGroup) * 2;
                    if (srcIdx + 1 < addrHex.Length)
                        ipBytes[j] = Convert.ToByte(addrHex.Substring(srcIdx, 2), 16);
                }
                addr = new IPAddress(ipBytes).ToString();
            }
            catch { }
        }

        return (addr, port);
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

    private record LinuxConnection
    {
        public string LocalAddr { get; init; } = "";
        public int LocalPort { get; init; }
        public string RemoteAddr { get; init; } = "";
        public int RemotePort { get; init; }
        public TcpState State { get; init; }
        public int Pid { get; init; }
    }

    private enum TcpState
    {
        Established = 1, SynSent = 2, SynRecv = 3, FinWait1 = 4,
        FinWait2 = 5, TimeWait = 6, Close = 7, CloseWait = 8,
        LastAck = 9, Listen = 10, Closing = 11,
    }
}
