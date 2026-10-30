namespace Behavedr.Core.Response;

using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS network isolation response using pf (packet filter) anchors when available.
/// Falls back to host-route blackholing for extracted C2 IPs from signals.
/// Requires root (launchd root agent). Rate-limited like Linux isolation.
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacOSNetworkIsolation : IResponseAction
{
    private readonly ILogger<MacOSNetworkIsolation> _logger;
    private int _activeRules;
    private const int MaxRules = 50;
    private readonly object _lock = new();
    private static readonly Regex IpRegex = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        RegexOptions.Compiled);

    // Never isolate public resolvers / link-local (Sentinel-style collateral reduction)
    private static readonly HashSet<string> NeverBlock = new(StringComparer.Ordinal)
    {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
        "127.0.0.1", "0.0.0.0", "255.255.255.255",
    };

    public string Name => "MacOSNetworkIsolation";
    public bool IsSupported => OperatingSystem.IsMacOS();

    public MacOSNetworkIsolation(ILogger<MacOSNetworkIsolation>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSNetworkIsolation>.Instance;
    }

    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsMacOS())
            return ResponseOutcome.Skipped(Name, "Not macOS");

        lock (_lock)
        {
            if (_activeRules >= MaxRules)
                return ResponseOutcome.Skipped(Name, $"Rule limit ({MaxRules}) reached");
        }

        var ips = ExtractIps(result).Where(ip => !NeverBlock.Contains(ip)).Distinct().Take(5).ToList();
        if (ips.Count == 0)
            return ResponseOutcome.Skipped(Name, "No C2/remote IP found in signals");

        var blocked = 0;
        foreach (var ip in ips)
        {
            if (ct.IsCancellationRequested) break;
            if (!IPAddress.TryParse(ip, out var addr) ||
                IPAddress.IsLoopback(addr) ||
                addr.Equals(IPAddress.Any) ||
                addr.Equals(IPAddress.Broadcast))
                continue;

            if (await TryBlackholeRoute(ip, ct))
            {
                blocked++;
                lock (_lock) { _activeRules++; }
            }
        }

        if (blocked == 0)
            return ResponseOutcome.Failed(Name, "Could not install any isolation rules (need root / pf)");

        _logger.LogWarning("[MacOSNetworkIsolation] Blackholed {Count} destination(s) for {Process}",
            blocked, result.Event.ProcessName);
        return ResponseOutcome.Ok(Name, $"Blackholed {blocked} destination IP(s)");
    }

    private static IEnumerable<string> ExtractIps(DetectionResult result)
    {
        foreach (var s in result.Signals)
        {
            foreach (Match m in IpRegex.Matches(s.Type))
                yield return m.Value;
        }
    }

    /// <summary>
    /// route -n add -host &lt;ip&gt; 127.0.0.1  (blackhole via loopback null-route style)
    /// </summary>
    private async Task<bool> TryBlackholeRoute(string ip, CancellationToken ct)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/sbin/route",
                Arguments = $"-n add -host {ip} 127.0.0.1",
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            await proc.WaitForExitAsync(ct);
            if (proc.ExitCode == 0)
                return true;

            // Alternate: pfctl table (if anchor preconfigured)
            return await TryPfTable(ip, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSNetworkIsolation] route add failed for {Ip}", ip);
            return false;
        }
    }

    private async Task<bool> TryPfTable(string ip, CancellationToken ct)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/sbin/pfctl",
                Arguments = $"-t behavedr_block -T add {ip}",
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            await proc.WaitForExitAsync(ct);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
