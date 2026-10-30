namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Windows script abuse: encoded PowerShell, AMSI bypass, download cradles, WMI/MSHTA parents.
/// Complements BehavioralMonitor with deeper script-focused scoring.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ScriptExecutionMonitor : IPlatformMonitor
{
    private readonly ILogger<ScriptExecutionMonitor> _logger;
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastPrune = DateTime.UtcNow;

    public string PlatformName => "ScriptExecution";
    public bool IsSupported => OperatingSystem.IsWindows();

    private static readonly Regex EncodedPs = new(
        @"-(?:enc|encodedcommand|e|ec)\s+[A-Za-z0-9+/=]{20,}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Bypass = new(
        @"-(?:ep|executionpolicy)\s+(bypass|unrestricted)|-noprofile|-w\s+hidden|-windowstyle\s+hidden",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DownloadCradle = new(
        @"(Invoke-WebRequest|IWR|wget|curl|Net\.WebClient|DownloadString|DownloadFile|Start-BitsTransfer|Invoke-RestMethod|iwr\s+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AmsiBypass = new(
        @"(amsiInitFailed|AmsiScanBuffer|System\.Management\.Automation\.AmsiUtils|amsi\.dll)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FromBase64 = new(
        @"FromBase64String|\[Convert\]::|iex\s*\(|Invoke-Expression",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ScriptExecutionMonitor(ILogger<ScriptExecutionMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<ScriptExecutionMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if (!OperatingSystem.IsWindows()) return Task.FromResult<IEnumerable<Signal>>(signals);

        try
        {
            ScanWindows(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[ScriptExecutionMonitor] error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void ScanWindows(List<Signal> signals, CancellationToken ct)
    {
        if ((DateTime.UtcNow - _lastPrune).TotalMinutes > 10)
        {
            _alerted.Clear();
            _lastPrune = DateTime.UtcNow;
        }

        using var searcher = new System.Management.ManagementObjectSearcher(
            "SELECT ProcessId, Name, CommandLine, ParentProcessId FROM Win32_Process WHERE Name LIKE 'powershell%' OR Name LIKE 'pwsh%' OR Name = 'cmd.exe' OR Name = 'wscript.exe' OR Name = 'cscript.exe' OR Name = 'mshta.exe'");

        foreach (System.Management.ManagementObject obj in searcher.Get())
        {
            if (ct.IsCancellationRequested) break;
            var name = obj["Name"]?.ToString() ?? "";
            var cmd = obj["CommandLine"]?.ToString() ?? "";
            var pid = Convert.ToInt32(obj["ProcessId"] ?? 0);
            if (string.IsNullOrWhiteSpace(cmd)) continue;

            var normalized = CommandLineAnalyzer.Normalize(cmd);
            var keyBase = $"{pid}:{normalized.GetHashCode():X8}";

            if (AmsiBypass.IsMatch(normalized) && _alerted.Add("amsi:" + keyBase))
                signals.Add(new Signal($"script_amsi_bypass:{name}:pid={pid}", 90, 0.92));

            if (EncodedPs.IsMatch(normalized) && _alerted.Add("enc:" + keyBase))
                signals.Add(new Signal($"script_encoded_ps:{name}:pid={pid}", 85, 0.88));

            if (DownloadCradle.IsMatch(normalized) && Bypass.IsMatch(normalized) && _alerted.Add("dl:" + keyBase))
                signals.Add(new Signal($"script_download_cradle:{name}:pid={pid}", 88, 0.90));
            else if (DownloadCradle.IsMatch(normalized) && _alerted.Add("dl2:" + keyBase))
                signals.Add(new Signal($"script_download:{name}:pid={pid}", 70, 0.75));

            if (FromBase64.IsMatch(normalized) && EncodedPs.IsMatch(normalized) && _alerted.Add("b64:" + keyBase))
                signals.Add(new Signal($"script_iex_base64:{name}:pid={pid}", 87, 0.89));

            var (entScore, entConf, _) = CommandLineAnalyzer.AnalyzeCommandLine(cmd);
            if (entScore >= 70 && _alerted.Add("ent:" + keyBase))
                signals.Add(new Signal($"script_high_entropy_cmdline:{name}:pid={pid}", entScore, entConf));
        }
    }
}
