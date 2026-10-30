namespace Behavedr.Core.Monitors;

using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Data exfiltration detection monitor.
/// Tracks cumulative bytes sent per (PID, RemoteAddress) over a sliding window.
/// Detects:
/// - Large outbound transfers from non-browser processes (>50MB in 5 minutes)
/// - High upload-to-download ratio (exfiltration pattern)
/// - Unusual outbound volume from LOLBins or shell processes
///
/// Uses GetPerTcpConnectionEStats or GetExtendedTcpTable with MIB_TCP_STATE
/// to estimate data volumes per connection.
/// </summary>
[SupportedOSPlatform("windows")]
public class DataExfiltrationMonitor : IPlatformMonitor
{
    private readonly ILogger<DataExfiltrationMonitor> _logger;
    private readonly Dictionary<string, TransferRecord> _transferHistory = new();
    private readonly object _lock = new();
    private DateTime _lastCheck = DateTime.MinValue;
    private const int CheckIntervalSeconds = 30;
    private const long ExfilThresholdBytes = 50 * 1024 * 1024; // 50 MB
    private const int MaxTrackedConnections = 2000;

    // Processes that legitimately send large amounts of data
    private static readonly HashSet<string> HighUploadAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "msedge", "brave", "opera",
        "onedrive", "dropbox", "googledrivesync", "icloud",
        "teams", "slack", "discord", "zoom", "webex",
        "code", "devenv", "git", "ssh", "scp", "rsync",
        "backblaze", "crashplan", "veeam",
    };

    // Processes that should NEVER send large data volumes
    private static readonly HashSet<string> SuspiciousUploaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "wscript", "cscript",
        "certutil", "bitsadmin", "curl", "wget",
        "mshta", "regsvr32", "rundll32",
    };

    public string PlatformName => "DataExfiltration";
    public bool IsSupported => OperatingSystem.IsWindows();

    public DataExfiltrationMonitor(ILogger<DataExfiltrationMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<DataExfiltrationMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if ((DateTime.UtcNow - _lastCheck).TotalSeconds < CheckIntervalSeconds)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        _lastCheck = DateTime.UtcNow;

        try
        {
            var connections = GetTcpConnectionsWithBytes();

            lock (_lock)
            {
                foreach (var conn in connections)
                {
                    if (ct.IsCancellationRequested) break;

                    // Skip loopback and private addresses
                    if (IsLocalAddress(conn.RemoteAddress)) continue;

                    var key = $"{conn.Pid}:{conn.RemoteAddress}";
                    if (!_transferHistory.TryGetValue(key, out var record))
                    {
                        if (_transferHistory.Count >= MaxTrackedConnections)
                            EvictOldest();
                        record = new TransferRecord();
                        _transferHistory[key] = record;
                    }

                    record.AddSample(conn.BytesSent, conn.BytesReceived);
                }

                // Analyze transfer patterns
                AnalyzeTransfers(signals);

                // Prune old entries
                PruneExpired();
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DataExfiltration] Failed to analyze transfers");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void AnalyzeTransfers(List<Signal> signals)
    {
        foreach (var (key, record) in _transferHistory)
        {
            var parts = key.Split(':', 2);
            if (parts.Length != 2) continue;
            if (!int.TryParse(parts[0], out var pid)) continue;

            var totalSent = record.TotalBytesSent;
            var totalReceived = record.TotalBytesReceived;
            var procName = GetProcessName(pid);

            if (procName is null) continue;

            // Skip allowlisted processes
            if (HighUploadAllowlist.Contains(procName)) continue;

            // Large outbound transfer detection
            if (totalSent > ExfilThresholdBytes)
            {
                var mbSent = totalSent / (1024 * 1024);
                var confidence = SuspiciousUploaders.Contains(procName) ? 0.9 : 0.75;
                var weight = SuspiciousUploaders.Contains(procName) ? 85.0 : 65.0;

                signals.Add(new Signal(
                    $"large_outbound_transfer:{procName}->{parts[1]}({mbSent}MB)",
                    weight, confidence));

                _logger.LogWarning(
                    "[DataExfiltration] {Process} sent {MB}MB to {Dest}",
                    procName, mbSent, parts[1]);
            }

            // High upload ratio (>5:1 upload to download ratio with significant volume)
            if (totalSent > 10 * 1024 * 1024 && totalReceived > 0)
            {
                var ratio = (double)totalSent / totalReceived;
                if (ratio > 5.0)
                {
                    var confidence = ratio > 20.0 ? 0.85 : 0.7;
                    signals.Add(new Signal(
                        $"high_upload_ratio:{procName}(ratio:{ratio:F1},sent:{totalSent / 1024 / 1024}MB)",
                        60, confidence));
                }
            }

            // Shell/LOLBin sending ANY significant data is suspicious
            if (SuspiciousUploaders.Contains(procName) && totalSent > 5 * 1024 * 1024)
            {
                signals.Add(new Signal(
                    $"shell_data_upload:{procName}({totalSent / 1024 / 1024}MB)",
                    75, 0.85));
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static List<ConnectionStats> GetTcpConnectionsWithBytes()
    {
        var results = new List<ConnectionStats>();
        int bufferSize = 0;

        // Get TCP table with PID
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2 /* AF_INET */,
            5 /* TCP_TABLE_OWNER_PID_ALL */, 0);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, true, 2, 5, 0) != 0)
                return results;

            int numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = 24; // Size of MIB_TCPROW_OWNER_PID

            for (int i = 0; i < numEntries && i < 3000; i++)
            {
                var state = Marshal.ReadInt32(rowPtr);
                if (state != 5) // Only ESTABLISHED
                {
                    rowPtr += rowSize;
                    continue;
                }

                var localAddr = (uint)Marshal.ReadInt32(rowPtr + 4);
                var localPort = (ushort)IPAddress.NetworkToHostOrder((short)Marshal.ReadInt32(rowPtr + 8));
                var remoteAddrInt = Marshal.ReadInt32(rowPtr + 12);
                var remoteAddr = new IPAddress(remoteAddrInt);
                var remotePort = (ushort)IPAddress.NetworkToHostOrder((short)Marshal.ReadInt32(rowPtr + 16));
                var pid = Marshal.ReadInt32(rowPtr + 20);

                // Query per-connection byte counters via GetPerTcpConnectionEStats
                long bytesSent = 0;
                long bytesReceived = 0;

                var row = new MIB_TCPROW
                {
                    dwState = 5, // ESTABLISHED
                    dwLocalAddr = localAddr,
                    dwLocalPort = (uint)IPAddress.HostToNetworkOrder((short)localPort),
                    dwRemoteAddr = (uint)remoteAddrInt,
                    dwRemotePort = (uint)IPAddress.HostToNetworkOrder((short)remotePort),
                };

                try
                {
                    // Try to enable stats and read data transfer counters
                    // First, enable the data stats object for this connection
                    var enableRw = new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 };
                    int enableSize = Marshal.SizeOf<TCP_ESTATS_DATA_RW_v0>();
                    var enablePtr = Marshal.AllocHGlobal(enableSize);
                    try
                    {
                        Marshal.StructureToPtr(enableRw, enablePtr, false);
                        // SetPerTcpConnectionEStats - enable data collection (best effort)
                        SetPerTcpConnectionEStats(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                            enablePtr, 0, (uint)enableSize, 0);
                    }
                    finally { Marshal.FreeHGlobal(enablePtr); }

                    // Read the data ROD (read-only dynamic) stats
                    int rodSize = Marshal.SizeOf<TCP_ESTATS_DATA_ROD_v0>();
                    var rodPtr = Marshal.AllocHGlobal(rodSize);
                    try
                    {
                        // Zero the buffer
                        for (int j = 0; j < rodSize; j++)
                            Marshal.WriteByte(rodPtr, j, 0);

                        var result = GetPerTcpConnectionEStats(ref row,
                            TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                            IntPtr.Zero, 0, 0,   // RW (not reading)
                            IntPtr.Zero, 0, 0,   // ROS (not reading)
                            rodPtr, 0, (uint)rodSize); // ROD (dynamic counters)

                        if (result == 0) // ERROR_SUCCESS
                        {
                            var rod = Marshal.PtrToStructure<TCP_ESTATS_DATA_ROD_v0>(rodPtr);
                            bytesSent = (long)rod.DataBytesOut;
                            bytesReceived = (long)rod.DataBytesIn;
                        }
                    }
                    finally { Marshal.FreeHGlobal(rodPtr); }
                }
                catch
                {
                    // GetPerTcpConnectionEStats may fail on older Windows or without admin
                    // Fall back to zero (will not trigger detection - acceptable degradation)
                }

                results.Add(new ConnectionStats
                {
                    Pid = pid,
                    RemoteAddress = remoteAddr.ToString(),
                    BytesSent = bytesSent,
                    BytesReceived = bytesReceived,
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return results;
    }

    // Per-connection EStats P/Invoke
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcpConnectionEStats(
        ref MIB_TCPROW row, TCP_ESTATS_TYPE statsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        IntPtr rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcpConnectionEStats(
        ref MIB_TCPROW row, TCP_ESTATS_TYPE statsType,
        IntPtr rw, uint rwVersion, uint rwSize, uint offset);

    private enum TCP_ESTATS_TYPE
    {
        TcpConnectionEstatsSynOpts = 0,
        TcpConnectionEstatsData = 1,
        TcpConnectionEstatsSndCong = 2,
        TcpConnectionEstatsPath = 3,
        TcpConnectionEstatsSendBuff = 4,
        TcpConnectionEstatsRec = 5,
        TcpConnectionEstatsObsRec = 6,
        TcpConnectionEstatsBandwidth = 7,
        TcpConnectionEstatsFineRtt = 8,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_RW_v0
    {
        public byte EnableCollection; // BOOLEAN
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_ROD_v0
    {
        public ulong DataBytesOut;
        public ulong DataSegsOut;
        public ulong DataBytesIn;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public ulong SoftErrors;
        public ulong SoftErrorReason;
        public ulong SndUna;
        public ulong SndNxt;
        public ulong SndMax;
        public ulong ThruBytesAcked;
        public ulong RcvNxt;
        public ulong ThruBytesReceived;
    }

    private void PruneExpired()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-5);
        var expired = _transferHistory
            .Where(kv => kv.Value.LastUpdate < cutoff)
            .Select(kv => kv.Key).ToList();
        foreach (var key in expired)
            _transferHistory.Remove(key);
    }

    private void EvictOldest()
    {
        var oldest = _transferHistory
            .OrderBy(kv => kv.Value.LastUpdate)
            .Take(500).Select(kv => kv.Key).ToList();
        foreach (var key in oldest)
            _transferHistory.Remove(key);
    }

    private static bool IsLocalAddress(string ip)
    {
        if (ip is "127.0.0.1" or "0.0.0.0" or "::1") return true;
        if (ip.StartsWith("10.")) return true;
        if (ip.StartsWith("192.168.")) return true;
        if (ip.StartsWith("172."))
        {
            var parts = ip.Split('.');
            if (parts.Length > 1 && int.TryParse(parts[1], out var second))
                if (second >= 16 && second <= 31) return true;
        }
        return false;
    }

    private static string? GetProcessName(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return null; }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
        bool sort, int ipVersion, int tableClass, uint reserved);

    private record ConnectionStats
    {
        public int Pid { get; init; }
        public string RemoteAddress { get; init; } = "";
        public long BytesSent { get; init; }
        public long BytesReceived { get; init; }
    }

    private class TransferRecord
    {
        public long TotalBytesSent { get; private set; }
        public long TotalBytesReceived { get; private set; }
        public DateTime LastUpdate { get; private set; } = DateTime.UtcNow;
        public int SampleCount { get; private set; }

        public void AddSample(long bytesSent, long bytesReceived)
        {
            TotalBytesSent += bytesSent;
            TotalBytesReceived += bytesReceived;
            SampleCount++;
            LastUpdate = DateTime.UtcNow;
        }
    }
}
