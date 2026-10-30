namespace Behavedr.Core.Monitors;

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Real-time process event monitoring via Linux Process Events Connector (cn_proc).
/// Uses NETLINK_CONNECTOR with CN_IDX_PROC to receive kernel notifications for:
/// - Fork events (new child process created)
/// - Exec events (process replaced its image - the critical detection point)
/// - Exit events (process terminated)
/// - UID/GID change events (privilege changes)
///
/// This eliminates the 5-second polling blind spot. Every process execution is seen
/// in real-time (~1ms latency) regardless of how short-lived it is.
///
/// Requires: CAP_NET_ADMIN capability (granted via systemd AmbientCapabilities).
/// Available since: Linux 2.6.15 (universally available on modern kernels).
/// No kernel module, no eBPF, no code signing required - pure userland netlink socket.
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxProcessConnector : IPlatformMonitor
{
    private readonly ILogger<LinuxProcessConnector> _logger;
    private Socket? _netlinkSocket;
    private bool _connected;
    private readonly object _lock = new();

    // Circular buffer of recent exec events for signal generation
    private readonly Queue<ProcessExecEvent> _recentExecs = new();
    private const int MaxBufferedEvents = 500;

    // Track ephemeral processes: exec -> exit within 2 seconds
    private readonly Dictionary<int, long> _execTimestamps = new();
    private const int EphemeralThresholdMs = 2000;

    public string PlatformName => "LinuxProcessConnector";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxProcessConnector(ILogger<LinuxProcessConnector>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxProcessConnector>.Instance;
    }

    /// <summary>
    /// Initialize the netlink connector socket and subscribe to process events.
    /// Called lazily on first GetSignalsAsync or explicitly during startup.
    /// </summary>
    [SupportedOSPlatform("linux")]
    public bool TryConnect()
    {
        if (_connected) return true;

        try
        {
            // Create NETLINK_CONNECTOR socket
            // AF_NETLINK = 16, SOCK_DGRAM = 2, NETLINK_CONNECTOR = 11
            _netlinkSocket = new Socket(
                (AddressFamily)16,  // AF_NETLINK
                SocketType.Dgram,
                (ProtocolType)11);  // NETLINK_CONNECTOR

            // Bind to CN_IDX_PROC group
            var addr = new NetlinkSockAddr
            {
                nl_family = 16, // AF_NETLINK
                nl_pid = (uint)Environment.ProcessId,
                nl_groups = 1,  // CN_IDX_PROC multicast group
            };

            var addrBytes = StructToBytes(addr);
            _netlinkSocket.Bind(new NetlinkEndPoint(addrBytes));

            // Send subscription message: PROC_CN_MCAST_LISTEN
            SendSubscription(listen: true);

            _netlinkSocket.ReceiveTimeout = 100; // 100ms non-blocking reads
            _connected = true;

            _logger.LogInformation(
                "[LinuxProcessConnector] Connected to cn_proc - real-time process events active");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "[LinuxProcessConnector] Cannot connect to cn_proc (requires CAP_NET_ADMIN). " +
                "Falling back to polling-based detection.");
            _netlinkSocket?.Dispose();
            _netlinkSocket = null;
            return false;
        }
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_connected && !TryConnect())
        {
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        // Drain available events from the netlink socket
        DrainEvents(ct);

        // Generate signals from buffered exec events
        lock (_lock)
        {
            while (_recentExecs.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var evt = _recentExecs.Dequeue();
                AnalyzeExecEvent(evt, signals);
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Read all pending events from the netlink socket (non-blocking).
    /// Parses cn_proc messages into structured events.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DrainEvents(CancellationToken ct)
    {
        if (_netlinkSocket is null) return;

        var buffer = new byte[4096];
        var iterations = 0;
        const int maxIterations = 200; // Prevent unbounded drain

        while (!ct.IsCancellationRequested && iterations++ < maxIterations)
        {
            try
            {
                var bytesRead = _netlinkSocket.Receive(buffer, SocketFlags.None);
                if (bytesRead < 52) break; // Minimum cn_proc message size

                ParseCnProcMessage(buffer.AsSpan(0, bytesRead));
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock ||
                                              ex.SocketErrorCode == SocketError.TimedOut)
            {
                break; // No more data available
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LinuxProcessConnector] Error reading netlink socket");
                break;
            }
        }
    }

    /// <summary>
    /// Parse a cn_proc netlink message. Structure:
    ///   [nlmsghdr][cn_msg][proc_event]
    ///
    /// proc_event.what:
    ///   PROC_EVENT_EXEC = 0x00000002
    ///   PROC_EVENT_EXIT = 0x80000000
    ///   PROC_EVENT_FORK = 0x00000001
    ///   PROC_EVENT_UID  = 0x00000004
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void ParseCnProcMessage(ReadOnlySpan<byte> data)
    {
        // nlmsghdr (16 bytes) + cn_msg header (20 bytes) = 36 bytes before proc_event
        if (data.Length < 52) return;

        const int procEventOffset = 36;
        var what = BitConverter.ToUInt32(data[procEventOffset..]);

        const uint PROC_EVENT_EXEC = 0x00000002;
        const uint PROC_EVENT_EXIT = 0x80000000;
        const uint PROC_EVENT_FORK = 0x00000001;

        switch (what)
        {
            case PROC_EVENT_EXEC:
            {
                // exec_proc_event: process_pid at offset +8, process_tgid at +12
                if (data.Length < procEventOffset + 16) return;
                var pid = BitConverter.ToInt32(data[(procEventOffset + 8)..]);
                var tgid = BitConverter.ToInt32(data[(procEventOffset + 12)..]);

                var procName = GetProcessName(pid);
                var cmdline = GetCommandLine(pid);

                lock (_lock)
                {
                    if (_recentExecs.Count >= MaxBufferedEvents)
                        _recentExecs.Dequeue();

                    _recentExecs.Enqueue(new ProcessExecEvent(pid, tgid, procName, cmdline,
                        Environment.TickCount64));

                    _execTimestamps[pid] = Environment.TickCount64;
                }
                break;
            }
            case PROC_EVENT_EXIT:
            {
                if (data.Length < procEventOffset + 16) return;
                var pid = BitConverter.ToInt32(data[(procEventOffset + 8)..]);

                lock (_lock)
                {
                    if (_execTimestamps.TryGetValue(pid, out var execTime))
                    {
                        var lifeMs = Environment.TickCount64 - execTime;
                        if (lifeMs < EphemeralThresholdMs)
                        {
                            // Ephemeral process detected (exec->exit in <2s)
                            var procName = GetProcessName(pid) ?? $"pid:{pid}";
                            _recentExecs.Enqueue(new ProcessExecEvent(
                                pid, pid, procName, $"[ephemeral:{lifeMs}ms]",
                                Environment.TickCount64));
                        }
                        _execTimestamps.Remove(pid);
                    }
                }
                break;
            }
            case PROC_EVENT_FORK:
                // Could track parent-child relationships here
                break;
        }

        // Prune old exec timestamps (prevent unbounded growth)
        lock (_lock)
        {
            if (_execTimestamps.Count > 5000)
            {
                var cutoff = Environment.TickCount64 - 30_000; // 30s
                var old = _execTimestamps.Where(kv => kv.Value < cutoff)
                    .Select(kv => kv.Key).Take(1000).ToList();
                foreach (var k in old) _execTimestamps.Remove(k);
            }
        }
    }

    private void AnalyzeExecEvent(ProcessExecEvent evt, List<Signal> signals)
    {
        if (string.IsNullOrEmpty(evt.ProcessName)) return;
        if (evt.Pid == Environment.ProcessId) return;

        // Path from /proc (rename of argv[0] does not hide image path)
        var exePath = GetExePath(evt.Pid);
        if (Response.ResponseSafety.IsOwnAgentImage(exePath)) return;

        var off = ThreatHeuristics.Evaluate(evt.ProcessName, exePath ?? evt.CommandLine);
        if (off is { } o)
        {
            signals.Add(new Signal(
                $"realtime_offensive:{o.Tag}:{o.Detail}:pid:{evt.Pid}",
                o.Weight, o.Confidence));
        }

        // Ephemeral process (from exit handler)
        if (evt.CommandLine?.StartsWith("[ephemeral:", StringComparison.Ordinal) == true)
        {
            signals.Add(new Signal(
                $"ephemeral_process:{evt.ProcessName}:pid:{evt.Pid}:{evt.CommandLine}", 55, 0.68));
        }

        // Reverse shell / encoded patterns (behavior, not tool name)
        if (!string.IsNullOrEmpty(evt.CommandLine))
        {
            if (evt.CommandLine.Contains("/dev/tcp/", StringComparison.Ordinal) ||
                (evt.CommandLine.Contains("bash", StringComparison.Ordinal) &&
                 evt.CommandLine.Contains("-i", StringComparison.Ordinal)))
            {
                signals.Add(new Signal(
                    $"realtime_reverse_shell:{evt.ProcessName}:pid:{evt.Pid}", 92, 0.9));
            }

            if (evt.CommandLine.Contains("base64 -d", StringComparison.Ordinal) &&
                evt.CommandLine.Contains("| bash", StringComparison.Ordinal))
            {
                signals.Add(new Signal(
                    $"realtime_encoded_exec:{evt.ProcessName}:pid:{evt.Pid}", 70, 0.75));
            }
        }
    }

    private static string? GetExePath(int pid)
    {
        try
        {
            return File.ResolveLinkTarget($"/proc/{pid}/exe", returnFinalTarget: true)?.FullName;
        }
        catch { return null; }
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

    private static string? GetCommandLine(int pid)
    {
        try
        {
            var path = $"/proc/{pid}/cmdline";
            return File.Exists(path) ? File.ReadAllText(path).Replace('\0', ' ').Trim() : null;
        }
        catch { return null; }
    }

    [SupportedOSPlatform("linux")]
    private void SendSubscription(bool listen)
    {
        if (_netlinkSocket is null) return;

        // Build: [nlmsghdr][cn_msg][enum proc_cn_mcast_op]
        // PROC_CN_MCAST_LISTEN = 1, PROC_CN_MCAST_IGNORE = 2
        var msg = new byte[40];

        // nlmsghdr (16 bytes)
        BitConverter.TryWriteBytes(msg.AsSpan(0), 40);      // nlmsg_len
        BitConverter.TryWriteBytes(msg.AsSpan(4), (ushort)0); // nlmsg_type (NLMSG_DONE)
        BitConverter.TryWriteBytes(msg.AsSpan(6), (ushort)0); // nlmsg_flags
        BitConverter.TryWriteBytes(msg.AsSpan(8), 0);        // nlmsg_seq
        BitConverter.TryWriteBytes(msg.AsSpan(12), Environment.ProcessId); // nlmsg_pid

        // cn_msg header (20 bytes)
        BitConverter.TryWriteBytes(msg.AsSpan(16), 1);  // idx = CN_IDX_PROC
        BitConverter.TryWriteBytes(msg.AsSpan(20), 1);  // val = CN_VAL_PROC
        BitConverter.TryWriteBytes(msg.AsSpan(24), 0);  // seq
        BitConverter.TryWriteBytes(msg.AsSpan(28), 0);  // ack
        BitConverter.TryWriteBytes(msg.AsSpan(32), (ushort)4); // len (4 bytes payload)
        BitConverter.TryWriteBytes(msg.AsSpan(34), (ushort)0); // flags

        // proc_cn_mcast_op (4 bytes)
        BitConverter.TryWriteBytes(msg.AsSpan(36), listen ? 1 : 2);

        _netlinkSocket.Send(msg);
    }

    public void Dispose()
    {
        if (_connected && _netlinkSocket is not null)
        {
            try { SendSubscription(listen: false); } catch { }
            _netlinkSocket.Dispose();
            _connected = false;
        }
    }

    private record ProcessExecEvent(int Pid, int Tgid, string? ProcessName, string? CommandLine, long TimestampMs);

    // Netlink address structure for binding
    [StructLayout(LayoutKind.Sequential)]
    private struct NetlinkSockAddr
    {
        public ushort nl_family;
        public ushort nl_pad;
        public uint nl_pid;
        public uint nl_groups;
    }

    private static byte[] StructToBytes<T>(T str) where T : struct
    {
        var size = Marshal.SizeOf(str);
        var arr = new byte[size];
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(str, ptr, false);
            Marshal.Copy(ptr, arr, 0, size);
            return arr;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    /// <summary>
    /// Custom EndPoint for netlink socket binding.
    /// </summary>
    private sealed class NetlinkEndPoint : EndPoint
    {
        private readonly byte[] _address;
        public NetlinkEndPoint(byte[] address) => _address = address;
        public override AddressFamily AddressFamily => (AddressFamily)16;
        public override SocketAddress Serialize()
        {
            var sa = new SocketAddress((AddressFamily)16, _address.Length + 2);
            for (int i = 0; i < _address.Length; i++)
                sa[i + 2] = _address[i];
            return sa;
        }
        public override EndPoint Create(SocketAddress socketAddress) => this;
    }
}
