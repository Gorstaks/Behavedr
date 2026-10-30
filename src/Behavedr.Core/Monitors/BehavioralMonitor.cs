namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Behavioral detection monitor for Windows. Detects:
/// - Suspicious parent-child process relationships (Office -> shell)
/// - Encoded PowerShell commands (download cradles, AMSI bypass)
/// - LOLBin abuse (certutil, mshta, regsvr32, rundll32, bitsadmin)
/// - Command-line obfuscation indicators
/// - Suspicious script execution patterns
/// </summary>
[SupportedOSPlatform("windows")]
public class BehavioralMonitor : IPlatformMonitor
{
    private readonly ILogger<BehavioralMonitor> _logger;
    private readonly NativeEtwSession? _etwSession;

    public string PlatformName => "BehavioralAnalysis";
    public bool IsSupported => OperatingSystem.IsWindows();

    // Suspicious parent -> child relationships
    private static readonly Dictionary<string, HashSet<string>> SuspiciousParentChild =
        new(StringComparer.OrdinalIgnoreCase)
    {
        ["winword"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "certutil" },
        ["excel"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "certutil" },
        ["outlook"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript" },
        ["explorer"] = new(StringComparer.OrdinalIgnoreCase) { "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin" },
        ["svchost"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd" },
        ["wmiprvse"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd" },
    };

    // LOLBin patterns in command lines
    private static readonly (string Pattern, string Description, double Weight, double Confidence)[] LolBinPatterns =
    [
        (@"certutil\s+.*-urlcache", "certutil download", 70, 0.8),
        (@"certutil\s+.*-decode", "certutil decode", 60, 0.75),
        (@"bitsadmin\s+/transfer", "bitsadmin download", 65, 0.8),
        (@"mshta\s+(http|vbscript|javascript)", "mshta script execution", 80, 0.85),
        (@"regsvr32\s+/s\s+/n\s+/u\s+/i:", "regsvr32 squiblydoo", 85, 0.9),
        (@"rundll32\s+.*,\s*(DllRegisterServer|Control_RunDLL)", "rundll32 abuse", 55, 0.65),
        (@"wmic\s+.*process\s+call\s+create", "wmic process create", 70, 0.8),
        (@"forfiles\s+/p\s+.*\s+/c", "forfiles command execution", 50, 0.6),
    ];

    // Encoded PowerShell indicators
    private static readonly Regex EncodedPsRegex = new(
        @"-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{20,}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BypassRegex = new(
        @"-(?:ep|executionpolicy)\s+(bypass|unrestricted)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DownloadCradleRegex = new(
        @"(Invoke-WebRequest|wget|curl|Net\.WebClient|DownloadString|DownloadFile|Start-BitsTransfer|Invoke-RestMethod)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AmsiBypassRegex = new(
        @"(amsiInitFailed|AmsiScanBuffer|amsi\.dll|SetProtectionLevel|Unload\(|Remove-MpThreat)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public BehavioralMonitor(NativeEtwSession? etwSession = null, ILogger<BehavioralMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<BehavioralMonitor>.Instance;
        _etwSession = etwSession;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            // Process ETW events if available (real-time process starts)
            if (_etwSession?.IsActive == true)
            {
                var etwEvents = _etwSession.DrainProcessEvents();
                foreach (var evt in etwEvents)
                {
                    AnalyzeProcessStart(evt, signals);
                }
            }

            // Also scan running processes for command-line indicators
            ScanRunningProcesses(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[BehavioralMonitor] Error during behavioral analysis");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void AnalyzeProcessStart(EtwProcessEvent evt, List<Signal> signals)
    {
        var childName = Path.GetFileNameWithoutExtension(evt.ProcessName).ToLowerInvariant();

        // Check parent-child anomalies
        var parentName = GetProcessName(evt.ParentProcessId);
        if (parentName is not null)
        {
            var parentKey = Path.GetFileNameWithoutExtension(parentName).ToLowerInvariant();
            if (SuspiciousParentChild.TryGetValue(parentKey, out var suspiciousChildren) &&
                suspiciousChildren.Contains(childName))
            {
                signals.Add(new Signal(
                    $"suspicious_parent_child:{parentKey}->{childName}(pid:{evt.ProcessId})",
                    75, 0.85));
            }
        }

        // Analyze command line if available
        if (!string.IsNullOrEmpty(evt.CommandLine))
        {
            AnalyzeCommandLine(evt.CommandLine, childName, evt.ProcessId, signals);
        }
    }

    [SupportedOSPlatform("windows")]
    private void ScanRunningProcesses(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            // Use WMI to get command lines (requires elevation for other users' processes)
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine, ParentProcessId FROM Win32_Process");

            foreach (var obj in searcher.Get())
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var pid = Convert.ToInt32(obj["ProcessId"]);
                    var name = obj["Name"]?.ToString() ?? "";
                    var cmdLine = obj["CommandLine"]?.ToString() ?? "";
                    var parentPid = Convert.ToInt32(obj["ParentProcessId"] ?? 0);

                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    var processName = Path.GetFileNameWithoutExtension(name).ToLowerInvariant();
                    AnalyzeCommandLine(cmdLine, processName, pid, signals);

                    // Check parent-child (WMI gives us ParentProcessId)
                    var parentName = GetProcessName(parentPid);
                    if (parentName is not null)
                    {
                        var parentKey = Path.GetFileNameWithoutExtension(parentName).ToLowerInvariant();
                        if (SuspiciousParentChild.TryGetValue(parentKey, out var children) &&
                            children.Contains(processName))
                        {
                            signals.Add(new Signal(
                                $"suspicious_parent_child:{parentKey}->{processName}(pid:{pid})",
                                75, 0.85));
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[BehavioralMonitor] WMI process scan failed");
        }
    }

    private static void AnalyzeCommandLine(string cmdLine, string processName, int pid, List<Signal> signals)
    {
        // Normalize command line to defeat evasion (caret, env vars, ticks)
        var normalizedCmdLine = CommandLineAnalyzer.Normalize(cmdLine);

        // Entropy-based encoded payload detection
        var (entropyScore, entropyConf, entropyReason) = CommandLineAnalyzer.AnalyzeCommandLine(cmdLine);
        if (entropyScore >= 50)
        {
            signals.Add(new Signal(
                $"obfuscated_cmdline:{processName}:pid:{pid}:{entropyReason}",
                entropyScore, entropyConf));
        }

        // Encoded PowerShell detection (use normalized for matching)
        if ((processName is "powershell" or "pwsh") && EncodedPsRegex.IsMatch(normalizedCmdLine))
        {
            signals.Add(new Signal($"encoded_powershell:pid:{pid}", 70, 0.8));
        }

        // Execution policy bypass
        if ((processName is "powershell" or "pwsh") && BypassRegex.IsMatch(normalizedCmdLine))
        {
            signals.Add(new Signal($"execution_policy_bypass:pid:{pid}", 40, 0.6));
        }

        // Download cradles
        if (DownloadCradleRegex.IsMatch(normalizedCmdLine))
        {
            signals.Add(new Signal($"download_cradle:{processName}:pid:{pid}", 65, 0.75));
        }

        // AMSI bypass attempts
        if (AmsiBypassRegex.IsMatch(normalizedCmdLine))
        {
            signals.Add(new Signal($"amsi_bypass_attempt:pid:{pid}", 85, 0.9));
        }

        // LOLBin pattern matching (use normalized)
        foreach (var (pattern, description, weight, confidence) in LolBinPatterns)
        {
            if (Regex.IsMatch(normalizedCmdLine, pattern, RegexOptions.IgnoreCase))
            {
                signals.Add(new Signal($"lolbin:{description}:pid:{pid}", weight, confidence));
                break; // One LOLBin signal per process
            }
        }

        // Hidden window + NoProfile (common in malicious PS)
        if ((processName is "powershell" or "pwsh") &&
            normalizedCmdLine.Contains("-w hidden", StringComparison.OrdinalIgnoreCase) &&
            normalizedCmdLine.Contains("-nop", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add(new Signal($"hidden_powershell:pid:{pid}", 60, 0.7));
        }
    }

    private static string? GetProcessName(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return null; }
    }
}
