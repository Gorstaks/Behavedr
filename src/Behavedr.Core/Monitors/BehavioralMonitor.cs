namespace Behavedr.Core.Monitors;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Behavioral detection monitor for Windows. Detects:
/// - Suspicious parent-child process relationships (Office -> shell)
/// - Command-line tradecraft (encoded PowerShell, download cradles, AMSI bypass, LOLBins).
///   The command-line rules live in <see cref="CommandLineThreatRules"/>.
/// The agent's own processes and their children are never analyzed.
/// </summary>
[SupportedOSPlatform("windows")]
public class BehavioralMonitor : IPlatformMonitor
{
    private readonly ILogger<BehavioralMonitor> _logger;
    private readonly NativeEtwSession? _etwSession;

    // Command-line analysis per PID. Results are replayed while the command line is unchanged,
    // so the regex and entropy work runs once per process instead of once per cycle.
    private readonly ConcurrentDictionary<int, (string CmdLine, List<Signal> Signals)> _cmdLineCache = new();

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
        if (AgentProcessIdentity.IsAgentOwned(evt.ProcessId, evt.ParentProcessId)) return;

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
            signals.AddRange(CommandLineThreatRules.Evaluate(childName, evt.CommandLine, evt.ProcessId));
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

            // One WMI pass gives every process name, so parent lookups need no extra Process calls.
            var rows = new List<(int Pid, string Name, string CmdLine, int ParentPid)>();
            foreach (var obj in searcher.Get())
            {
                try
                {
                    rows.Add((
                        Convert.ToInt32(obj["ProcessId"]),
                        obj["Name"]?.ToString() ?? "",
                        obj["CommandLine"]?.ToString() ?? "",
                        Convert.ToInt32(obj["ParentProcessId"] ?? 0)));
                }
                catch { }
            }

            var nameByPid = rows.ToDictionary(r => r.Pid, r => r.Name);
            var seenPids = new HashSet<int>();
            bool completed = true;

            foreach (var (pid, name, cmdLine, parentPid) in rows)
            {
                if (ct.IsCancellationRequested)
                {
                    completed = false;
                    break;
                }

                // Never analyze the agent, its children, or processes it launched.
                if (AgentProcessIdentity.IsAgentOwned(pid, parentPid)) continue;
                if (string.IsNullOrEmpty(cmdLine)) continue;

                seenPids.Add(pid);
                var processName = Path.GetFileNameWithoutExtension(name).ToLowerInvariant();

                if (!_cmdLineCache.TryGetValue(pid, out var cached) || cached.CmdLine != cmdLine)
                {
                    cached = (cmdLine, CommandLineThreatRules.Evaluate(processName, cmdLine, pid));
                    _cmdLineCache[pid] = cached;
                }
                signals.AddRange(cached.Signals);

                // Check parent-child (parent name comes from the same WMI pass)
                if (nameByPid.TryGetValue(parentPid, out var parentName))
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

            // Drop cache entries for processes that have exited.
            if (completed)
            {
                foreach (var stale in _cmdLineCache.Keys.Where(pid => !seenPids.Contains(pid)).ToList())
                    _cmdLineCache.TryRemove(stale, out _);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[BehavioralMonitor] WMI process scan failed");
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
