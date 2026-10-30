namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects "ghost" processes - PIDs with active outbound network connections
/// whose process name cannot be resolved or is empty. Catches process hollowing,
/// orphaned RAT sockets, and DLL-sideloaded backdoors (T1055.012).
/// </summary>
[SupportedOSPlatform("windows")]
public class GhostProcessMonitor : IPlatformMonitor
{
    private readonly ILogger<GhostProcessMonitor> _logger;
    private readonly HashSet<int> _alertedPids = new();

    public string PlatformName => "GhostProcessMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
        bool bOrder, int ulAf, int tableClass, uint reserved);

    public GhostProcessMonitor(ILogger<GhostProcessMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<GhostProcessMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var connections = GetEstablishedOutbound();
            var byPid = connections.GroupBy(c => c.Pid);

            foreach (var group in byPid)
            {
                if (ct.IsCancellationRequested) break;
                int pid = group.Key;
                if (pid <= 4 || pid == Environment.ProcessId) continue;
                if (_alertedPids.Contains(pid)) continue;

                var resolution = ResolveProcess(pid);
                if (resolution.IsGhost || resolution.IsEmptyName)
                {
                    var dests = string.Join(",", group.Select(c => $"{c.RemoteAddr}:{c.RemotePort}").Distinct().Take(5));
                    var confidence = resolution.IsGhost ? 0.88 : 0.78;
                    signals.Add(new Signal(
                        $"ghost_process:pid:{pid}:connections:{group.Count()}:dests:{dests}",
                        80, confidence));
                    _alertedPids.Add(pid);
                    _logger.LogCritical(
                        "SECURITY: Ghost process PID {Pid} has {Count} active connections to [{Dests}] but cannot be resolved",
                        pid, group.Count(), dests);
                }
            }

            if (_alertedPids.Count > 500) _alertedPids.Clear();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[GhostProcessMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private static (bool IsGhost, bool IsEmptyName) ResolveProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (string.IsNullOrEmpty(proc.ProcessName))
                return (false, true);
            return (false, false);
        }
        catch (ArgumentException) { return (true, false); }
        catch (InvalidOperationException) { return (true, false); }
        catch { return (false, false); }
    }

    [SupportedOSPlatform("windows")]
    private static List<(int Pid, string RemoteAddr, int RemotePort)> GetEstablishedOutbound()
    {
        var results = new List<(int, string, int)>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5, 0);

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0) != 0)
                return results;

            int numEntries = Marshal.ReadInt32(buffer);
            int rowSize = 24;
            for (int i = 0; i < numEntries && i < 5000; i++)
            {
                var rowPtr = buffer + 4 + i * rowSize;
                var state = Marshal.ReadInt32(rowPtr);
                if (state != 5) continue; // ESTABLISHED only

                var remoteAddrInt = Marshal.ReadInt32(rowPtr + 12);
                var remoteAddr = new IPAddress(BitConverter.GetBytes(remoteAddrInt)).ToString();
                if (remoteAddr.StartsWith("127.") || remoteAddr == "0.0.0.0") continue;

                var remotePort = (ushort)IPAddress.NetworkToHostOrder((short)Marshal.ReadInt32(rowPtr + 16));
                var pid = Marshal.ReadInt32(rowPtr + 20);

                results.Add((pid, remoteAddr, remotePort));
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return results;
    }
}
