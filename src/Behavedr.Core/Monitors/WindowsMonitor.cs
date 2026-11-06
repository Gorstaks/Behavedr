namespace Behavedr.Core.Monitors;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;

/// <summary>
/// Windows process-level heuristics. One process enumeration per cycle covers image
/// heuristics, thread and memory outliers, PowerShell lifetime, and new-process bursts.
/// Command-line analysis lives in <see cref="BehavioralMonitor"/>.
/// Signals carry a PID whenever one exists, so they can be scored per process.
/// </summary>
public class WindowsMonitor : IPlatformMonitor
{
    public string PlatformName => "Windows";
    public bool IsSupported => OperatingSystem.IsWindows();

    private static readonly TimeSpan NewProcessWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ShortLivedPowerShell = TimeSpan.FromSeconds(3);

    // Image path by PID. The entry is reused only while the process start time is unchanged.
    private readonly ConcurrentDictionary<int, (DateTime Start, string? Path)> _imageCache = new();

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var processes = Process.GetProcesses();
            var livePids = new HashSet<int>();
            int recentCount = 0;
            var now = DateTime.Now;

            foreach (var proc in processes)
            {
                try
                {
                    if (ct.IsCancellationRequested) break;

                    livePids.Add(proc.Id);
                    DateTime? start = TryGetStartTime(proc);
                    if (start is { } started && now - started < NewProcessWindow)
                        recentCount++;

                    if (AgentProcessIdentity.IsAgentOwned(proc.Id)) continue;

                    var name = proc.ProcessName;
                    var path = GetImagePath(proc, start);
                    var pidTag = $"pid:{proc.Id}";

                    // Rename-resistant scoring (name alone is low weight; staging path + exe is high)
                    var off = ThreatHeuristics.Evaluate(name, path);
                    if (off is { } o)
                    {
                        signals.Add(new Signal(
                            $"suspicious_process:{o.Tag}:{o.Detail}:{pidTag}",
                            o.Weight, o.Confidence));
                    }

                    var nameLower = name.ToLowerInvariant();

                    // Thread count outliers can indicate injection. Enumerating threads is costly,
                    // so this check reads only the count.
                    int threads = proc.Threads.Count;
                    if (threads > 200)
                    {
                        signals.Add(new Signal($"high_thread_count:{nameLower}({threads}):{pidTag}", 25, 0.4));
                    }

                    // Memory outliers, excluding known heavy applications
                    var memMb = proc.WorkingSet64 / (1024 * 1024);
                    if (memMb > 2048 && !IsKnownHighMemProcess(nameLower))
                    {
                        signals.Add(new Signal($"high_memory:{nameLower}({memMb}MB):{pidTag}", 20, 0.3));
                    }

                    // Short-lived PowerShell may be a download cradle. Weak on its own, so it
                    // only matters when the same PID has other signals.
                    if (nameLower is "powershell" or "pwsh" && start is { } ps && now - ps < ShortLivedPowerShell)
                    {
                        signals.Add(new Signal($"short_lived_powershell:{pidTag}", 25, 0.5));
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

            // Burst of new processes on the whole machine. Carries no PID, so it is never
            // attributed to a process. It is machine context only.
            if (recentCount > 20)
            {
                signals.Add(new Signal($"process_burst:{recentCount}_in_10s", 50, 0.7));
            }

            // Forget cached images for processes that no longer exist
            foreach (var pid in _imageCache.Keys.Where(pid => !livePids.Contains(pid)).ToList())
                _imageCache.TryRemove(pid, out _);
        }
        catch (Exception)
        {
            // Fallback: return empty signals if process enumeration fails entirely
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private string? GetImagePath(Process proc, DateTime? start)
    {
        if (start is not { } started)
            return null;

        if (_imageCache.TryGetValue(proc.Id, out var cached) && cached.Start == started)
            return cached.Path;

        string? path = null;
        try { path = proc.MainModule?.FileName; } catch { /* access denied */ }
        _imageCache[proc.Id] = (started, path);
        return path;
    }

    private static DateTime? TryGetStartTime(Process proc)
    {
        try { return proc.StartTime; }
        catch { return null; }
    }

    private static bool IsKnownHighMemProcess(string name) =>
        name is "chrome" or "firefox" or "msedge" or "devenv" or "code"
            or "java" or "node" or "sqlservr" or "teams" or "slack";
}
