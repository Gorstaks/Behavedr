namespace Behavedr.Core.Response;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Behavedr.Core.Models;
using Behavedr.Core.Monitors;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Attack chain tracer - ported from Sentinel v2.0.
/// Traces the full attack chain from a detected malicious process back to its origin.
/// Walks the parent process tree, identifies the attack root, and performs chain-level response:
///   1. Kill processes in the chain (except system hosts and legitimate browsers/IDEs)
///   2. Quarantine non-system, unsigned binaries
///   3. Remove persistence (platform-specific)
///   4. Log complete chain evidence
///
/// Platform-specific implementations:
///   - Windows: WMI/Win32 API for parent PID, registry for persistence
///   - Linux: /proc/pid/status for PPid, cron/systemd for persistence
///   - macOS: sysctl for parent PID, LaunchAgents for persistence
/// </summary>
public sealed class ChainTracer
{
    private readonly ProcessAncestryCache _ancestry;
    private readonly IQuarantineService _quarantine;
    private readonly ResponsePolicy _policy;
    private readonly ILogger<ChainTracer> _logger;

    // Cache of traced chains to prevent redundant work
    private readonly ConcurrentDictionary<string, DateTime> _recentTraces = new();

    private static readonly HashSet<string> CriticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "registry", "smss", "csrss", "wininit", "services", "lsass", "svchost",
        "explorer", "dwm", "sihost", "fontdrvhost", "winlogon",
        // Linux
        "init", "systemd", "kthreadd", "ksoftirqd", "kworker",
        // macOS
        "launchd", "kernel_task", "WindowServer",
    };

    private static readonly HashSet<string> BrowserHostNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "safari", "chromium",
        "chromesetup", "googleupdate", "microsoftedgeupdate",
    };

    private static readonly HashSet<string> IdeHostNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "code", "kiro", "cursor", "windsurf", "positron", "rider64", "idea64",
        "phpstorm64", "webstorm64", "goland64", "pycharm64", "clion64",
        "devenv", "xcode",
    };

    public ChainTracer(
        ProcessAncestryCache ancestry,
        IQuarantineService quarantine,
        ResponsePolicy policy,
        ILogger<ChainTracer>? logger = null)
    {
        _ancestry = ancestry;
        _quarantine = quarantine;
        _policy = policy;
        _logger = logger ?? NullLogger<ChainTracer>.Instance;
    }

    /// <summary>
    /// Traces and responds to the attack chain rooted at the detected process.
    /// Only invoked for high-confidence terminal detections when Active response is enabled.
    /// </summary>
    public async Task<ChainTraceResult> TraceAndRespondAsync(
        DetectionEvent detection, double score, CancellationToken ct = default)
    {
        var result = new ChainTraceResult
        {
            DetectionEvent = detection,
            Score = score,
            StartTime = DateTime.UtcNow,
        };

        // Debounce: don't re-trace the same PID within 30 seconds
        var traceKey = $"{detection.ProcessId}:{detection.BehaviorType}";
        if (_recentTraces.TryGetValue(traceKey, out var lastTrace) &&
            DateTime.UtcNow - lastTrace < TimeSpan.FromSeconds(30))
        {
            result.Skipped = true;
            result.SkipReason = "Recently traced (30s cooldown)";
            return result;
        }
        _recentTraces[traceKey] = DateTime.UtcNow;

        try
        {
            // 1. Walk parent chain
            var ancestryEntries = _ancestry.GetAncestryChain(int.TryParse(detection.ProcessId, out var pidInt) ? pidInt : 0, 20);
            var chain = ancestryEntries.Select(e => new ProcessNode
            {
                Pid = e.Pid.ToString(),
                Name = e.ProcessName,
                ParentPid = e.ParentPid.ToString(),
            }).ToList();
            result.ParentChain = chain;

            if (chain.Count == 0)
            {
                _logger.LogDebug("[ChainTracer] Empty chain for PID {Pid}", detection.ProcessId);
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            // 2. Identify attack root (first non-system, non-browser host)
            result.AttackRoot = chain.LastOrDefault(n =>
                !IsCriticalSystem(n) && !IsBrowserHost(n) && !IsIdeHost(n))
                ?? chain.LastOrDefault(n => !IsCriticalSystem(n));

            // 3. Response actions (only if policy allows)
            if (_policy.Mode == ResponseMode.Active && score >= _policy.ResponseThreshold)
            {
                await ExecuteChainResponse(chain, detection, result, ct);
            }
            else
            {
                _logger.LogInformation(
                    "[ChainTracer] Observe-only: chain traced for PID {Pid} (mode={Mode}, score={Score:F1})",
                    detection.ProcessId, _policy.Mode, score);
            }

            result.EndTime = DateTime.UtcNow;
            result.Success = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ChainTracer] Failed for PID {Pid}", detection.ProcessId);
            result.Error = ex.Message;
        }

        return result;
    }

    private async Task ExecuteChainResponse(
        List<ProcessNode> chain, DetectionEvent detection, ChainTraceResult result, CancellationToken ct)
    {
        foreach (var node in chain)
        {
            if (ct.IsCancellationRequested) break;

            // Never kill critical system processes
            if (IsCriticalSystem(node)) continue;

            // Preserve browser hosts (kill the child, not the browser)
            if (node.Pid != detection.ProcessId && IsBrowserHost(node))
            {
                _logger.LogInformation("[ChainTracer] Preserving browser host PID {Pid} ({Name})",
                    node.Pid, node.Name);
                continue;
            }

            // Preserve IDE hosts
            if (node.Pid != detection.ProcessId && IsIdeHost(node))
            {
                _logger.LogInformation("[ChainTracer] Preserving IDE host PID {Pid} ({Name})",
                    node.Pid, node.Name);
                continue;
            }

            // ResponseSafety: never kill own process or agent binary
            if (ResponseSafety.ShouldRefuseKill(int.TryParse(node.Pid, out var pidInt) ? pidInt : 0, node.Name, out _))
                continue;

            // Kill the process
            try
            {
                KillProcess(node.Pid);
                result.KilledPids.Add(node.Pid);
                _logger.LogWarning("[ChainTracer] KILLED PID {Pid} ({Name})", node.Pid, node.Name);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ChainTracer] Failed to kill PID {Pid}", node.Pid);
            }

            // Quarantine unsigned binaries (signed hosts are killed but preserved on disk)
            if (!string.IsNullOrEmpty(node.ImagePath) && !IsCriticalSystem(node))
            {
                if (!node.IsSigned)
                {
                    try
                    {
                        await _quarantine.QuarantineAsync(node.ImagePath!, ct);
                        result.QuarantinedFiles.Add(node.ImagePath!);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[ChainTracer] Failed to quarantine {Path}", node.ImagePath);
                    }
                }
            }
        }

        // 4. Remove persistence associated with the attack root
        if (result.AttackRoot != null && !string.IsNullOrEmpty(result.AttackRoot.ImagePath))
        {
            var removed = await RemovePersistenceAsync(result.AttackRoot.ImagePath!, ct);
            result.PersistenceRemoved = removed;
        }
    }

    private async Task<List<string>> RemovePersistenceAsync(string imagePath, CancellationToken ct)
    {
        var removed = new List<string>();

        if (OperatingSystem.IsWindows())
        {
            removed.AddRange(RemoveWindowsPersistence(imagePath));
        }
        else if (OperatingSystem.IsLinux())
        {
            removed.AddRange(await RemoveLinuxPersistenceAsync(imagePath, ct));
        }
        else if (OperatingSystem.IsMacOS())
        {
            removed.AddRange(RemoveMacOsPersistence(imagePath));
        }

        return removed;
    }

    private static List<string> RemoveWindowsPersistence(string imagePath)
    {
        var removed = new List<string>();

        if (!OperatingSystem.IsWindows()) return removed;

        // Check Run keys
        string[] runPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (var hive in new[] { Microsoft.Win32.Registry.LocalMachine, Microsoft.Win32.Registry.CurrentUser })
        {
            foreach (var path in runPaths)
            {
                try
                {
                    using var key = hive.OpenSubKey(path, writable: true);
                    if (key == null) continue;
                    foreach (var name in key.GetValueNames())
                    {
                        var val = key.GetValue(name)?.ToString() ?? "";
                        if (val.Contains(imagePath, StringComparison.OrdinalIgnoreCase) ||
                            val.Contains(Path.GetFileName(imagePath), StringComparison.OrdinalIgnoreCase))
                        {
                            key.DeleteValue(name);
                            removed.Add($"Registry: {hive.Name}\\{path}\\{name}");
                        }
                    }
                }
                catch { }
            }
        }

        return removed;
    }

    private static async Task<List<string>> RemoveLinuxPersistenceAsync(string imagePath, CancellationToken ct)
    {
        var removed = new List<string>();
        var fileName = Path.GetFileName(imagePath);

        // Check user crontabs
        try
        {
            var crontab = await RunCommandAsync("crontab", "-l", ct);
            if (crontab.Contains(fileName, StringComparison.OrdinalIgnoreCase))
            {
                var filtered = string.Join("\n", crontab.Split('\n')
                    .Where(line => !line.Contains(fileName, StringComparison.OrdinalIgnoreCase)));
                var tempFile = Path.GetTempFileName();
                await File.WriteAllTextAsync(tempFile, filtered, ct);
                await RunCommandAsync("crontab", tempFile, ct);
                File.Delete(tempFile);
                removed.Add($"Crontab entry for {fileName}");
            }
        }
        catch { }

        // Check systemd user services
        var userServiceDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".config", "systemd", "user");
        if (Directory.Exists(userServiceDir))
        {
            try
            {
                foreach (var svc in Directory.GetFiles(userServiceDir, "*.service"))
                {
                    var content = await File.ReadAllTextAsync(svc, ct);
                    if (content.Contains(imagePath, StringComparison.OrdinalIgnoreCase) ||
                        content.Contains(fileName, StringComparison.OrdinalIgnoreCase))
                    {
                        File.Delete(svc);
                        removed.Add($"Systemd service: {Path.GetFileName(svc)}");
                    }
                }
            }
            catch { }
        }

        return removed;
    }

    private static List<string> RemoveMacOsPersistence(string imagePath)
    {
        var removed = new List<string>();
        var fileName = Path.GetFileName(imagePath);

        // LaunchAgents
        string[] launchDirs =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        };

        foreach (var dir in launchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var plist in Directory.GetFiles(dir, "*.plist"))
                {
                    var content = File.ReadAllText(plist);
                    if (content.Contains(imagePath, StringComparison.OrdinalIgnoreCase) ||
                        content.Contains(fileName, StringComparison.OrdinalIgnoreCase))
                    {
                        File.Delete(plist);
                        removed.Add($"LaunchAgent: {Path.GetFileName(plist)}");
                    }
                }
            }
            catch { }
        }

        return removed;
    }

    #region Helpers

    private static bool IsCriticalSystem(ProcessNode node)
    {
        var cleanName = Path.GetFileNameWithoutExtension(node.Name ?? "").ToLowerInvariant();
        if (CriticalSystemProcesses.Contains(cleanName)) return true;
        if (string.IsNullOrEmpty(node.ImagePath)) return true; // Unknown path = don't kill

        var lower = node.ImagePath!.ToLowerInvariant();
        if (OperatingSystem.IsWindows())
            return lower.Contains(@"\windows\system32\") || lower.Contains(@"\windows\syswow64\");
        if (OperatingSystem.IsLinux())
            return lower.StartsWith("/usr/bin/") || lower.StartsWith("/usr/sbin/") || lower.StartsWith("/sbin/");
        if (OperatingSystem.IsMacOS())
            return lower.StartsWith("/usr/") || lower.StartsWith("/system/");
        return false;
    }

    private static bool IsBrowserHost(ProcessNode node)
    {
        var cleanName = Path.GetFileNameWithoutExtension(node.Name ?? "").ToLowerInvariant();
        return BrowserHostNames.Contains(cleanName);
    }

    private static bool IsIdeHost(ProcessNode node)
    {
        var cleanName = Path.GetFileNameWithoutExtension(node.Name ?? "").ToLowerInvariant();
        return IdeHostNames.Contains(cleanName);
    }

    private static void KillProcess(string pid)
    {
        if (!int.TryParse(pid, out var pidInt)) return;
        try
        {
            var proc = Process.GetProcessById(pidInt);
            proc.Kill(entireProcessTree: true);
        }
        catch { }
    }

    private static async Task<string> RunCommandAsync(string command, string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(command, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var proc = Process.Start(psi)!;
        var output = await proc.StandardOutput.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);
        return output;
    }

    #endregion
}

/// <summary>Node in the process ancestry chain.</summary>
public sealed class ProcessNode
{
    public string Pid { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? ImagePath { get; set; }
    public string? ParentPid { get; set; }
    public bool IsSigned { get; set; }
}

/// <summary>Result of a chain trace operation.</summary>
public sealed class ChainTraceResult
{
    public DetectionEvent? DetectionEvent { get; set; }
    public double Score { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public bool Success { get; set; }
    public bool Skipped { get; set; }
    public string? SkipReason { get; set; }
    public string? Error { get; set; }
    public List<ProcessNode> ParentChain { get; set; } = [];
    public ProcessNode? AttackRoot { get; set; }
    public List<string> KilledPids { get; set; } = [];
    public List<string> QuarantinedFiles { get; set; } = [];
    public List<string> PersistenceRemoved { get; set; } = [];
}

/// <summary>Quarantine service interface for ChainTracer to use.</summary>
public interface IQuarantineService
{
    Task QuarantineAsync(string filePath, CancellationToken ct = default);
}
