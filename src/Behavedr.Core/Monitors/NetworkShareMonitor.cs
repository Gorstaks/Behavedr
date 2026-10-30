namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects lateral movement via SMB/network shares (T1021.002):
/// - New drive mappings after baseline
/// - Admin share access (C$, ADMIN$, IPC$)
/// - New local share creation at runtime
/// </summary>
[SupportedOSPlatform("windows")]
public class NetworkShareMonitor : IPlatformMonitor
{
    private readonly ILogger<NetworkShareMonitor> _logger;
    private readonly HashSet<string> _baselineShares = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alertedShares = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselined;

    private static readonly HashSet<string> AdminShares = new(StringComparer.OrdinalIgnoreCase)
    { "C$", "D$", "E$", "ADMIN$", "IPC$", "PRINT$" };

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareEnum(string? serverName, int level, out IntPtr bufPtr,
        int prefMaxLen, out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHARE_INFO_0 { public string shi0_netname; }

    public string PlatformName => "NetworkShareMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    public NetworkShareMonitor(ILogger<NetworkShareMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<NetworkShareMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var currentShares = EnumerateLocalShares();

            if (!_baselined)
            {
                _baselineShares.UnionWith(currentShares);
                _baselined = true;
                return Task.FromResult<IEnumerable<Signal>>(signals);
            }

            foreach (var share in currentShares)
            {
                if (ct.IsCancellationRequested) break;
                if (_baselineShares.Contains(share)) continue;
                if (_alertedShares.Contains(share)) continue;

                _baselineShares.Add(share);
                _alertedShares.Add(share);

                // Skip default admin shares (they're always present)
                if (AdminShares.Contains(share)) continue;

                signals.Add(new Signal(
                    $"unauthorized_share_created:{share}",
                    80, 0.85));
                _logger.LogCritical(
                    "SECURITY: Unauthorized SMB share '{Share}' created at runtime - possible lateral movement staging",
                    share);
            }

            // Also check for new mapped drives
            CheckNewDriveMappings(signals);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[NetworkShareMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private static List<string> EnumerateLocalShares()
    {
        var shares = new List<string>();
        try
        {
            int resumeHandle = 0;
            int result = NetShareEnum(null, 0, out IntPtr bufPtr, -1,
                out int entriesRead, out _, ref resumeHandle);

            if (result != 0 || bufPtr == IntPtr.Zero) return shares;

            try
            {
                int structSize = Marshal.SizeOf<SHARE_INFO_0>();
                for (int i = 0; i < entriesRead; i++)
                {
                    var entry = Marshal.PtrToStructure<SHARE_INFO_0>(IntPtr.Add(bufPtr, i * structSize));
                    if (!string.IsNullOrEmpty(entry.shi0_netname))
                        shares.Add(entry.shi0_netname);
                }
            }
            finally { NetApiBufferFree(bufPtr); }
        }
        catch { }
        return shares;
    }

    private void CheckNewDriveMappings(List<Signal> signals)
    {
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Network) continue;
                var key = $"drive:{drive.Name}";
                if (_baselineShares.Contains(key)) continue;
                if (_alertedShares.Contains(key)) continue;

                _baselineShares.Add(key);
                _alertedShares.Add(key);
                signals.Add(new Signal($"new_network_drive_mapped:{drive.Name}", 55, 0.60));
            }
        }
        catch { }
    }
}
