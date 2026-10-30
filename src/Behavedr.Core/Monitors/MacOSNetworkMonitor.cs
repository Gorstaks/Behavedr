namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS network connection monitor using lsof for PID-attributed connection tracking.
/// Detects:
/// - Connections to suspicious ports (common C2/RAT)
/// - High connection counts from non-browser processes
/// - Connection bursts (rapid fan-out)
/// - Shell/interpreter processes making outbound connections
/// - Listening sockets from unexpected processes (backdoor indicators)
/// </summary>
[SupportedOSPlatform("macos")]
public class MacOSNetworkMonitor : IPlatformMonitor
{
    private readonly ILogger<MacOSNetworkMonitor> _logger;
    private readonly HashSet<string> _previousConnections = new();

    public string PlatformName => "MacOSNetwork";
    public bool IsSupported => OperatingSystem.IsMacOS();

    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 6666, 7777, 8888, 9999,
        1234, 31337, 12345, 54321,
        2222, 3333, 4443, 8443, 8080,
    };

    private static readonly HashSet<string> HighConnectionAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "Google Chrome", "firefox", "Safari", "brave", "opera",
        "com.apple.WebKit", "nsurlsessiond", "mDNSResponder",
        "node", "java", "code", "electron",
    };

    private static readonly HashSet<string> SuspiciousConnectors = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash", "sh", "zsh", "fish", "csh", "tcsh",
        "python", "python3", "perl", "ruby", "php",
        "curl", "wget", "nc", "ncat", "socat", "openssl",
    };

    // Regex to parse lsof -i output
    // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    private static readonly Regex LsofLineRegex = new(
        @"^(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(TCP|UDP)\s+(.+)$",
        RegexOptions.Compiled);

    public MacOSNetworkMonitor(ILogger<MacOSNetworkMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSNetworkMonitor>.Instance;
    }

    [SupportedOSPlatform("macos")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var connections = GetConnections(ct);
            var currentKeys = new HashSet<string>();
            var pidConnectionCount = new Dictionary<int, int>();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;

                var key = $"{conn.Pid}:{conn.RemoteAddr}:{conn.RemotePort}";
                currentKeys.Add(key);

                if (conn.RemoteAddr is "127.0.0.1" or "::1" or "*" or "localhost") continue;

                pidConnectionCount.TryGetValue(conn.Pid, out var count);
                pidConnectionCount[conn.Pid] = count + 1;

                if (_previousConnections.Contains(key)) continue;

                // Suspicious port
                if (conn.State == "ESTABLISHED" && SuspiciousPorts.Contains(conn.RemotePort))
                {
                    signals.Add(new Signal(
                        $"suspicious_port_connection:{conn.ProcessName}->{conn.RemoteAddr}:{conn.RemotePort}:pid:{conn.Pid}",
                        65, 0.72));
                }

                // Shell outbound
                if (conn.State == "ESTABLISHED" && SuspiciousConnectors.Contains(conn.ProcessName))
                {
                    signals.Add(new Signal(
                        $"shell_outbound_connection:{conn.ProcessName}->{conn.RemoteAddr}:{conn.RemotePort}:pid:{conn.Pid}",
                        72, 0.78));
                }

                // Backdoor listener
                if (conn.State == "LISTEN" && SuspiciousConnectors.Contains(conn.ProcessName))
                {
                    signals.Add(new Signal(
                        $"backdoor_listener:{conn.ProcessName}:port:{conn.LocalPort}:pid:{conn.Pid}",
                        88, 0.9));
                }
            }

            // High connection count
            foreach (var (pid, connCount) in pidConnectionCount)
            {
                if (connCount <= 50) continue;
                var name = connections.FirstOrDefault(c => c.Pid == pid)?.ProcessName ?? $"pid:{pid}";
                if (!HighConnectionAllowlist.Contains(name))
                {
                    signals.Add(new Signal(
                        $"high_connection_count:{name}({connCount}):pid:{pid}", 50, 0.62));
                }
            }

            // Connection burst
            var newConnections = currentKeys.Except(_previousConnections).Count();
            if (newConnections > 30)
            {
                signals.Add(new Signal($"connection_burst:{newConnections}_new", 45, 0.55));
            }

            _previousConnections.Clear();
            foreach (var k in currentKeys) _previousConnections.Add(k);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSNetwork] Error during network scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Parse connections from lsof -i -n -P output.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private static List<MacOSConnection> GetConnections(CancellationToken ct)
    {
        var connections = new List<MacOSConnection>();

        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/usr/sbin/lsof",
                Arguments = "-i -n -P",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            foreach (var line in output.Split('\n'))
            {
                if (ct.IsCancellationRequested) break;
                var match = LsofLineRegex.Match(line);
                if (!match.Success) continue;

                var processName = match.Groups[1].Value;
                var pid = int.Parse(match.Groups[2].Value);
                var proto = match.Groups[3].Value;
                var nameField = match.Groups[4].Value;

                // Parse NAME field: "host:port->remotehost:remoteport (STATE)"
                // or "host:port (LISTEN)"
                var conn = ParseLsofName(nameField, processName, pid);
                if (conn is not null)
                    connections.Add(conn);
            }
        }
        catch { }

        return connections;
    }

    private static MacOSConnection? ParseLsofName(string name, string processName, int pid)
    {
        var state = "UNKNOWN";
        var stateMatch = Regex.Match(name, @"\((\w+)\)$");
        if (stateMatch.Success)
        {
            state = stateMatch.Groups[1].Value;
            name = name[..stateMatch.Index].Trim();
        }

        var arrowIdx = name.IndexOf("->", StringComparison.Ordinal);
        string localPart, remotePart;

        if (arrowIdx >= 0)
        {
            localPart = name[..arrowIdx];
            remotePart = name[(arrowIdx + 2)..];
        }
        else
        {
            localPart = name;
            remotePart = "*:*";
        }

        var (localAddr, localPort) = ParseHostPort(localPart);
        var (remoteAddr, remotePort) = ParseHostPort(remotePart);

        return new MacOSConnection
        {
            ProcessName = processName,
            Pid = pid,
            LocalAddr = localAddr,
            LocalPort = localPort,
            RemoteAddr = remoteAddr,
            RemotePort = remotePort,
            State = state,
        };
    }

    private static (string Addr, int Port) ParseHostPort(string hostPort)
    {
        var lastColon = hostPort.LastIndexOf(':');
        if (lastColon < 0) return (hostPort, 0);
        var addr = hostPort[..lastColon];
        var portStr = hostPort[(lastColon + 1)..];
        int.TryParse(portStr, out var port);
        return (addr, port);
    }

    private record MacOSConnection
    {
        public string ProcessName { get; init; } = "";
        public int Pid { get; init; }
        public string LocalAddr { get; init; } = "";
        public int LocalPort { get; init; }
        public string RemoteAddr { get; init; } = "";
        public int RemotePort { get; init; }
        public string State { get; init; } = "";
    }
}
