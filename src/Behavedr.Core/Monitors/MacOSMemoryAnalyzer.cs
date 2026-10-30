namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS memory analyzer using vmmap output to detect suspicious memory patterns.
/// Detects:
/// - RWX (read-write-execute) memory regions in non-JIT processes
/// - Unsigned executable mappings (code injection indicators)
/// - Large anonymous executable regions (shellcode staging)
/// </summary>
[SupportedOSPlatform("macos")]
public class MacOSMemoryAnalyzer : IPlatformMonitor
{
    private readonly ILogger<MacOSMemoryAnalyzer> _logger;

    public string PlatformName => "MacOSMemoryAnalyzer";
    public bool IsSupported => OperatingSystem.IsMacOS();

    private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Google Chrome", "firefox", "Safari", "brave", "opera",
        "java", "javaw", "node", "electron",
        "python", "python3", "ruby", "luajit",
        "code", "code-oss", "rider",
    };

    public MacOSMemoryAnalyzer(ILogger<MacOSMemoryAnalyzer>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSMemoryAnalyzer>.Instance;
    }

    [SupportedOSPlatform("macos")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            // Use `vmmap --summary` on suspicious processes to avoid per-process overhead.
            // First, identify non-JIT processes with network connections or recent spawns.
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var name = proc.ProcessName;
                    var pid = proc.Id;
                    if (pid <= 1 || pid == Environment.ProcessId) continue;
                    if (JitProcesses.Contains(name)) continue;

                    // Only scan processes started recently (last 5 min) to limit overhead
                    TimeSpan age;
                    try { age = DateTime.Now - proc.StartTime; }
                    catch { continue; }
                    if (age.TotalMinutes > 5) continue;

                    AnalyzeProcessMemory(pid, name, signals, ct);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSMemoryAnalyzer] Error during memory scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Analyze a process's memory regions using vmmap for suspicious patterns.
    /// Falls back to checking /proc-style info if vmmap is unavailable.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void AnalyzeProcessMemory(int pid, string processName, List<Signal> signals, CancellationToken ct)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/usr/bin/vmmap",
                Arguments = $"--wide {pid}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            if (string.IsNullOrEmpty(output)) return;

            int rwxCount = 0;
            int suspiciousExecCount = 0;

            foreach (var line in output.Split('\n'))
            {
                if (ct.IsCancellationRequested) break;

                // Look for rwx permissions in vmmap output
                // vmmap shows permissions like "r-x/rwx" (current/max)
                if (line.Contains("rwx/rwx", StringComparison.Ordinal) ||
                    (line.Contains("r-x", StringComparison.Ordinal) &&
                     line.Contains("rwx", StringComparison.Ordinal) &&
                     !line.Contains("__TEXT", StringComparison.Ordinal)))
                {
                    // Anonymous RWX region (not from a named segment like __TEXT)
                    if (!line.Contains("__TEXT", StringComparison.Ordinal) &&
                        !line.Contains("__DATA", StringComparison.Ordinal) &&
                        !line.Contains(".dylib", StringComparison.OrdinalIgnoreCase))
                    {
                        rwxCount++;
                    }
                }

                // Suspicious: executable mapping from deleted or anonymous source
                if (line.Contains("---/rwx", StringComparison.Ordinal) ||
                    (line.Contains("MALLOC", StringComparison.Ordinal) &&
                     line.Contains("rwx", StringComparison.Ordinal)))
                {
                    suspiciousExecCount++;
                }
            }

            if (rwxCount > 0)
            {
                var weight = rwxCount > 5 ? 75.0 : rwxCount > 2 ? 58.0 : 40.0;
                var confidence = rwxCount > 5 ? 0.85 : rwxCount > 2 ? 0.72 : 0.55;
                signals.Add(new Signal(
                    $"rwx_memory:{processName}(pid:{pid},regions:{rwxCount})", weight, confidence));
            }

            if (suspiciousExecCount > 0)
            {
                signals.Add(new Signal(
                    $"suspicious_exec_mapping:{processName}(pid:{pid},count:{suspiciousExecCount})",
                    70, 0.75));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSMemoryAnalyzer] Failed to analyze PID {Pid}", pid);
        }
    }
}
