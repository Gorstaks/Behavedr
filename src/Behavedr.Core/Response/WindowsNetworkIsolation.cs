namespace Behavedr.Core.Response;

using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Windows network isolation (0.3.3 production path).
/// Order: Firewall COM (HNetCfg) -> direct WFP engine -> netsh advfirewall.
/// All three ultimately use WFP BFE; COM is the most reliable user-mode API.
/// No callout driver required.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsNetworkIsolation : IResponseAction, IDisposable
{
    private readonly ILogger<WindowsNetworkIsolation> _logger;
    private readonly WindowsFirewallEngine _fwCom;
    private readonly WindowsWfpEngine _wfp;
    private readonly HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private const int MaxRules = 100;

    private static readonly HashSet<string> NeverBlock = new(StringComparer.OrdinalIgnoreCase)
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
        "208.67.222.222", "208.67.220.220", "127.0.0.1", "::1",
    };

    public string Name => "WindowsNetworkIsolation";
    public bool IsSupported => OperatingSystem.IsWindows();

    public WindowsNetworkIsolation(ILogger<WindowsNetworkIsolation>? logger = null)
    {
        _logger = logger ?? NullLogger<WindowsNetworkIsolation>.Instance;
        _fwCom = new WindowsFirewallEngine(_logger);
        _wfp = new WindowsWfpEngine(_logger);
    }

    public void Dispose()
    {
        _fwCom.Dispose();
        _wfp.Dispose();
    }

    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return ResponseOutcome.Skipped(Name, "Not Windows");

        var ips = ExtractRemoteIps(result);
        if (ips.Count == 0)
        {
            if (int.TryParse(result.Event.ProcessId, out var pid) && pid > 4)
            {
                var image = TryGetProcessImage(pid);
                if (!string.IsNullOrEmpty(image) && File.Exists(image))
                    return await BlockProcessImageAsync(image, result.Event.ProcessName, ct);
            }
            return ResponseOutcome.Skipped(Name, "No remote IPs or process image to isolate");
        }

        int blocked = 0;
        foreach (var ip in ips)
        {
            ct.ThrowIfCancellationRequested();
            if (await BlockIpAsync(ip, result.Event.ProcessName, ct))
                blocked++;
        }

        return blocked > 0
            ? ResponseOutcome.Ok(Name, $"Blocked {blocked} remote IP(s) for {result.Event.ProcessName}")
            : ResponseOutcome.Skipped(Name, "No new IPs blocked (limit, protect-list, or elevation missing)");
    }

    private Task<bool> BlockIpAsync(string ip, string processName, CancellationToken ct)
    {
        _ = ct;
        if (NeverBlock.Contains(ip) || IsPrivateOrLinkLocal(ip))
            return Task.FromResult(false);

        lock (_lock)
        {
            if (_blockedIps.Count >= MaxRules)
            {
                _logger.LogWarning("[WinNetIsolation] Rule limit {Max} reached", MaxRules);
                return Task.FromResult(false);
            }
            if (!_blockedIps.Add(ip))
                return Task.FromResult(false);
        }

        if (!IPAddress.TryParse(ip, out var addr))
        {
            lock (_lock) _blockedIps.Remove(ip);
            return Task.FromResult(false);
        }

        var comment = $"Behavedr isolation for {Sanitize(processName)}";

        // 1) Firewall COM (production primary)
        if (_fwCom.IsAvailable && _fwCom.BlockRemoteAddress(addr, comment))
        {
            Telemetry.SecurityTelemetry.ReportIsolationAction();
            return Task.FromResult(true);
        }

        // 2) Direct WFP filter engine
        var preferWfp = !string.Equals(
            Environment.GetEnvironmentVariable("BEHAVEDR_PREFER_WFP"), "0", StringComparison.Ordinal);
        if (preferWfp && _wfp.BlockRemoteAddress(addr, comment))
        {
            Telemetry.SecurityTelemetry.ReportIsolationAction();
            return Task.FromResult(true);
        }

        // 3) netsh last resort
        return BlockIpNetshAsync(ip, processName, ct);
    }

    private async Task<bool> BlockIpNetshAsync(string ip, string processName, CancellationToken ct)
    {
        var safeName = $"BehavedrBlock_{ip.Replace(':', '_').Replace('.', '_')}";
        var argsOut =
            $"advfirewall firewall add rule name=\"{safeName}\" " +
            $"dir=out action=block remoteip={ip} enable=yes " +
            $"description=\"Behavedr isolation for {Sanitize(processName)}\"";
        var argsIn =
            $"advfirewall firewall add rule name=\"{safeName}_in\" " +
            $"dir=in action=block remoteip={ip} enable=yes " +
            $"description=\"Behavedr isolation inbound for {Sanitize(processName)}\"";

        var ok = await RunNetshAsync(argsOut, ct);
        _ = await RunNetshAsync(argsIn, ct);
        if (ok)
        {
            _logger.LogWarning("[WinNetIsolation] netsh blocked {Ip}", ip);
            Telemetry.SecurityTelemetry.ReportIsolationAction();
            return true;
        }

        lock (_lock) { _blockedIps.Remove(ip); }
        return false;
    }

    private async Task<ResponseOutcome> BlockProcessImageAsync(string imagePath, string processName, CancellationToken ct)
    {
        if (ResponseSafety.ShouldRefuseAppNetworkBlock(imagePath, out var refuse))
        {
            _logger.LogWarning("[WinNetIsolation] Refusing app block {Path}: {Reason}", imagePath, refuse);
            return ResponseOutcome.Skipped(Name, $"Safety: {refuse}");
        }

        if (_fwCom.IsAvailable && _fwCom.BlockApplication(imagePath, $"Behavedr process {processName}"))
        {
            Telemetry.SecurityTelemetry.ReportIsolationAction();
            return ResponseOutcome.Ok(Name, $"Blocked outbound for {processName} image (FwCOM)");
        }

        var hash = Math.Abs(imagePath.GetHashCode(StringComparison.OrdinalIgnoreCase));
        var ruleName = $"BehavedrBlockProg_{hash:X8}";
        var args =
            $"advfirewall firewall add rule name=\"{ruleName}\" " +
            $"dir=out action=block program=\"{imagePath}\" enable=yes " +
            $"description=\"Behavedr process isolation for {Sanitize(processName)}\"";

        var ok = await RunNetshAsync(args, ct);
        if (ok)
        {
            Telemetry.SecurityTelemetry.ReportIsolationAction();
            return ResponseOutcome.Ok(Name, $"Blocked outbound for {processName} image (netsh)");
        }
        return ResponseOutcome.Failed(Name, "process image block failed (need elevation?)");
    }

    private static async Task<bool> RunNetshAsync(string arguments, CancellationToken ct)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                },
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

    private static List<string> ExtractRemoteIps(DetectionResult result)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ipv4 = Ipv4Regex();
        // Bracketed or bare IPv6 (simplified; covers common signal encodings)
        var ipv6 = Ipv6Regex();
        foreach (var signal in result.Signals)
        {
            var text = signal.Type ?? "";
            foreach (Match m in ipv4.Matches(text))
                found.Add(m.Value);
            foreach (Match m in ipv6.Matches(text))
                found.Add(m.Value.Trim('[', ']'));
        }
        foreach (Match m in ipv4.Matches(result.Event.ProcessName ?? ""))
            found.Add(m.Value);
        return found.ToList();
    }

    private static string? TryGetProcessImage(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch { return null; }
    }

    private static bool IsPrivateOrLinkLocal(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return true;
        if (IPAddress.IsLoopback(addr))
            return true;
        var b = addr.GetAddressBytes();
        if (b.Length == 4)
        {
            if (b[0] == 10) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            return false;
        }
        if (b.Length == 16)
        {
            // fe80::/10 link-local, fc00::/7 unique local
            if ((b[0] & 0xFE) == 0xFC) return true;
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;
        }
        return false;
    }

    private static string Sanitize(string s) =>
        string.Concat(s.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.').Take(40));

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")]
    private static partial Regex Ipv4Regex();

    // Matches forms like 2001:db8::1 or [fe80::1] (not exhaustive RFC, good enough for signal parse)
    [GeneratedRegex(@"\[?(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\]?")]
    private static partial Regex Ipv6Regex();
}
