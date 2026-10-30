namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;

/// <summary>
/// Windows behavioral monitor using real-time process telemetry.
/// Uses WMI Win32_Process events and Process class for live data.
/// ETW (TraceEvent) can be layered on in a future version for kernel-level hooks.
/// </summary>
public class WindowsMonitor : IPlatformMonitor
{
    public string PlatformName => "Windows";
    public bool IsSupported => OperatingSystem.IsWindows();

    // Suspicious parent-child relationships moved to BehavioralMonitor (v0.0.7)
    // WindowsMonitor now focuses on process-level heuristics; behavioral analysis
    // is handled by the dedicated BehavioralMonitor with command-line scanning.

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var processes = Process.GetProcesses();

            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    if (proc.Id == Environment.ProcessId) continue;
                    var name = proc.ProcessName;
                    string? path = null;
                    try { path = proc.MainModule?.FileName; } catch { /* access denied */ }
                    if (Response.ResponseSafety.IsOwnAgentImage(path)) continue;

                    // Rename-resistant scoring (name alone is low weight; Temp+exe high)
                    var off = ThreatHeuristics.Evaluate(name, path);
                    if (off is { } o)
                    {
                        signals.Add(new Signal(
                            $"suspicious_process:{o.Tag}:{o.Detail}:pid:{proc.Id}",
                            o.Weight, o.Confidence));
                    }

                    // Detect processes with unusually high thread counts (possible injection)
                    var nameLower = name.ToLowerInvariant();
                    if (proc.Threads.Count > 200)
                    {
                        signals.Add(new Signal($"high_thread_count:{nameLower}({proc.Threads.Count})", 25, 0.4));
                    }

                    // Detect processes consuming excessive memory relative to their type
                    var memMb = proc.WorkingSet64 / (1024 * 1024);
                    if (memMb > 2048 && !IsKnownHighMemProcess(nameLower))
                    {
                        signals.Add(new Signal($"high_memory:{nameLower}({memMb}MB)", 20, 0.3));
                    }
                }
                catch (Exception)
                {
                    // Access denied for system processes - expected
                }
                finally
                {
                    proc.Dispose();
                }
            }

            // Check for PowerShell with suspicious flags in command line (if accessible)
            DetectSuspiciousPowerShell(signals);

            // Check for recently started processes (last interval)
            DetectNewProcesses(signals);
        }
        catch (Exception)
        {
            // Fallback: return empty signals if process enumeration fails entirely
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private static void DetectSuspiciousPowerShell(List<Signal> signals)
    {
        try
        {
            var psProcesses = Process.GetProcessesByName("powershell")
                .Concat(Process.GetProcessesByName("pwsh"));

            foreach (var ps in psProcesses)
            {
                try
                {
                    // PowerShell running with -EncodedCommand, -Bypass, -Hidden, -NoProfile
                    // We can't always read command line without elevation, but we can detect
                    // the process existing in certain suspicious contexts
                    var startTime = ps.StartTime;
                    var runTime = DateTime.Now - startTime;

                    // Very short-lived PowerShell (< 3 seconds) is suspicious - may be download cradle
                    if (runTime.TotalSeconds < 3)
                    {
                        signals.Add(new Signal("short_lived_powershell", 40, 0.6));
                    }
                }
                catch { }
                finally
                {
                    ps.Dispose();
                }
            }
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private static void DetectNewProcesses(List<Signal> signals)
    {
        try
        {
            var recentThreshold = DateTime.Now.AddSeconds(-10);
            var processes = Process.GetProcesses();

            int recentCount = 0;
            foreach (var proc in processes)
            {
                try
                {
                    if (proc.StartTime > recentThreshold)
                        recentCount++;
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }

            // Burst of new processes in a short window (possible fork bomb or spray)
            if (recentCount > 20)
            {
                signals.Add(new Signal($"process_burst:{recentCount}_in_10s", 50, 0.7));
            }
        }
        catch { }
    }

    private static bool IsKnownHighMemProcess(string name) =>
        name is "chrome" or "firefox" or "msedge" or "devenv" or "code"
            or "java" or "node" or "sqlservr" or "teams" or "slack";
}
