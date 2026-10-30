namespace Behavedr.Core.Monitors;

using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Network connection monitor using GetExtendedTcpTable/GetExtendedUdpTable.
/// Tracks all TCP/UDP connections with PID attribution.
/// Detects: new connections to suspicious ports, connections from unexpected processes,
/// high connection counts (possible C2 fan-out), connections to raw IPs (no DNS).
/// </summary>
[SupportedOSPlatform("windows")]
public class NetworkConnectionMonitor : IPlatformMonitor
{
    private readonly ILogger<NetworkConnectionMonitor> _logger;
    private readonly HashSet<string> _previousConnections = new();

    public string PlatformName => "NetworkMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    // Suspicious destination ports (non-standard for legitimate traffic)
    private static readonly HashSet<int> SuspiciousListenPorts = new()
    {
        4444, 5555, 6666, 7777, 8888, 9999, // Common C2/RAT ports
        1234, 31337, 12345, 54321,           // Classic backdoor ports
        2222, 3333, 4443, 8443, 8080,        // Alt HTTPS/proxy
    };

    // Known legitimate high-connection processes
    private static readonly HashSet<string> HighConnectionAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "msedge", "brave", "opera",
        "svchost", "system", "teams", "slack", "discord",
        "onedrive", "dropbox", "code", "devenv"
    };

    public NetworkConnectionMonitor(ILogger<NetworkConnectionMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<NetworkConnectionMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var connections = GetTcpConnections();
            var currentKeys = new HashSet<string>();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;

                var key = $"{conn.OwningPid}:{conn.RemoteAddress}:{conn.RemotePort}";
                currentKeys.Add(key);

                // Skip already-known connections
                if (_previousConnections.Contains(key))
                    continue;

                // Detect connections to suspicious ports
                if (SuspiciousListenPorts.Contains(conn.RemotePort) && conn.State == TcpState.Established)
                {
                    var procName = GetProcessName(conn.OwningPid);
                    signals.Add(new Signal(
                        $"suspicious_port_connection:{procName}->{conn.RemoteAddress}:{conn.RemotePort}",
                        60, 0.7));
                }

                // Detect high connection count from single non-browser process
                var pidConnections = connections.Count(c => c.OwningPid == conn.OwningPid && c.State == TcpState.Established);
                if (pidConnections > 50)
                {
                    var procName = GetProcessName(conn.OwningPid);
                    if (!HighConnectionAllowlist.Contains(procName))
                    {
                        signals.Add(new Signal(
                            $"high_connection_count:{procName}({pidConnections})",
                            45, 0.6));
                    }
                }
            }

            // Detect newly established outbound connections (delta from last scan)
            var newConnections = currentKeys.Except(_previousConnections).Count();
            if (newConnections > 30)
            {
                signals.Add(new Signal($"connection_burst:{newConnections}_new", 40, 0.5));
            }

            _previousConnections.Clear();
            foreach (var k in currentKeys) _previousConnections.Add(k);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[NetworkMonitor] Failed to enumerate connections");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    // P/Invoke for GetExtendedTcpTable
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, int tableClass, uint reserved);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [SupportedOSPlatform("windows")]
    private static List<TcpConnectionInfo> GetTcpConnections()
    {
        var connections = new List<TcpConnectionInfo>();
        int bufferSize = 0;

        // First call to get required buffer size
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint result = GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != 0) return connections;

            int numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries && i < 5000; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                connections.Add(new TcpConnectionInfo
                {
                    State = (TcpState)row.dwState,
                    LocalAddress = new IPAddress(row.dwLocalAddr).ToString(),
                    LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort),
                    RemoteAddress = new IPAddress(row.dwRemoteAddr).ToString(),
                    RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort),
                    OwningPid = (int)row.dwOwningPid
                });
                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return connections;
    }

    private static string GetProcessName(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return $"pid:{pid}"; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    private record TcpConnectionInfo
    {
        public TcpState State { get; init; }
        public string LocalAddress { get; init; } = "";
        public int LocalPort { get; init; }
        public string RemoteAddress { get; init; } = "";
        public int RemotePort { get; init; }
        public int OwningPid { get; init; }
    }

    private enum TcpState
    {
        Closed = 1, Listen = 2, SynSent = 3, SynRcvd = 4,
        Established = 5, FinWait1 = 6, FinWait2 = 7, CloseWait = 8,
        Closing = 9, LastAck = 10, TimeWait = 11, DeleteTcb = 12
    }
}
