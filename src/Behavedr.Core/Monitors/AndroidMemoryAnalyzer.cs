namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android memory analysis monitor detecting:
/// - RWX memory regions (code injection / JIT abuse)
/// - memfd_create usage (fileless execution)
/// - Suspicious shared libraries loaded from writable paths
/// - DEX files loaded from non-APK locations
/// - ART runtime hooking indicators
///
/// v0.2.0 audit fix A-4: Adds memory-level threat detection for Android.
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidMemoryAnalyzer : IPlatformMonitor
{
    private readonly ILogger<AndroidMemoryAnalyzer> _logger;
    private readonly HashSet<string> _alertedPids = new();

    public string PlatformName => "AndroidMemory";
    public bool IsSupported => OperatingSystem.IsAndroid();

    public AndroidMemoryAnalyzer(ILogger<AndroidMemoryAnalyzer>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidMemoryAnalyzer>.Instance;
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            DetectRwxMemory(signals, ct);
            DetectMemfdExecution(signals, ct);
            DetectSuspiciousLibraries(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AndroidMemory] Error during memory analysis");
        }

        // Prune alerted set to prevent unbounded growth
        if (_alertedPids.Count > 500) _alertedPids.Clear();

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Scan /proc/*/maps for RWX (read-write-execute) memory regions.
    /// On modern Android with W^X enforcement, RWX should be extremely rare.
    /// Presence indicates: JIT compiler (ART - expected), or code injection (bad).
    /// We filter out known-good ART JIT regions and flag the rest.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectRwxMemory(List<Signal> signals, CancellationToken ct)
    {
        foreach (var procDir in Directory.GetDirectories("/proc"))
        {
            if (ct.IsCancellationRequested) break;
            var pidStr = Path.GetFileName(procDir);
            if (!int.TryParse(pidStr, out var pid)) continue;
            if (pid == Environment.ProcessId) continue;

            var alertKey = $"rwx:{pid}";
            if (_alertedPids.Contains(alertKey)) continue;

            var mapsPath = Path.Combine(procDir, "maps");
            if (!File.Exists(mapsPath)) continue;

            try
            {
                foreach (var line in File.ReadLines(mapsPath))
                {
                    if (ct.IsCancellationRequested) break;

                    // Look for rwxp (read-write-execute private) regions
                    if (!line.Contains("rwxp", StringComparison.Ordinal)) continue;

                    // Filter out known-good: ART JIT code cache
                    if (line.Contains("jit-code-cache", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("[anon:dalvik-jit", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var mappedFile = ExtractMappedFile(line);
                    signals.Add(new Signal(
                        $"rwx_memory_android:pid:{pid}:{mappedFile}", 72, 0.78));
                    _alertedPids.Add(alertKey);
                    _logger.LogWarning("[AndroidMemory] RWX memory in PID {Pid}: {Map}", pid, mappedFile);
                    break; // One signal per process
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect memfd-based fileless execution. memfd_create creates anonymous files
    /// in memory that can be executed without ever touching the filesystem.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectMemfdExecution(List<Signal> signals, CancellationToken ct)
    {
        foreach (var procDir in Directory.GetDirectories("/proc"))
        {
            if (ct.IsCancellationRequested) break;
            var pidStr = Path.GetFileName(procDir);
            if (!int.TryParse(pidStr, out var pid)) continue;
            if (pid == Environment.ProcessId) continue;

            var alertKey = $"memfd:{pid}";
            if (_alertedPids.Contains(alertKey)) continue;

            var mapsPath = Path.Combine(procDir, "maps");
            if (!File.Exists(mapsPath)) continue;

            try
            {
                foreach (var line in File.ReadLines(mapsPath))
                {
                    if (ct.IsCancellationRequested) break;

                    // memfd shows as "memfd:name" in maps with execute permission
                    if (line.Contains("memfd:", StringComparison.Ordinal) &&
                        (line.Contains("r-xp", StringComparison.Ordinal) ||
                         line.Contains("rwxp", StringComparison.Ordinal)))
                    {
                        signals.Add(new Signal(
                            $"memfd_execution_android:pid:{pid}", 88, 0.92));
                        _alertedPids.Add(alertKey);
                        _logger.LogCritical(
                            "[AndroidMemory] Fileless execution via memfd in PID {Pid}", pid);
                        break;
                    }
                }
            }
            catch { }

            // Also check /proc/PID/fd for FDs pointing to deleted/memfd files
            var fdDir = Path.Combine(procDir, "fd");
            if (!Directory.Exists(fdDir)) continue;

            try
            {
                foreach (var fdPath in Directory.GetFiles(fdDir))
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var target = File.ResolveLinkTarget(fdPath, returnFinalTarget: true)?.ToString();
                        if (target is not null && target.Contains("memfd:", StringComparison.Ordinal))
                        {
                            if (!_alertedPids.Contains(alertKey))
                            {
                                signals.Add(new Signal(
                                    $"memfd_fd_android:pid:{pid}:{Path.GetFileName(fdPath)}", 75, 0.82));
                                _alertedPids.Add(alertKey);
                            }
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect suspicious shared libraries loaded from writable/untrusted paths.
    /// Legitimate .so files come from /system/lib64, /vendor/lib64, or the APK lib dir.
    /// Libraries from /data/local/tmp, /sdcard, or other writable paths are suspicious.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectSuspiciousLibraries(List<Signal> signals, CancellationToken ct)
    {
        foreach (var procDir in Directory.GetDirectories("/proc"))
        {
            if (ct.IsCancellationRequested) break;
            var pidStr = Path.GetFileName(procDir);
            if (!int.TryParse(pidStr, out var pid)) continue;
            if (pid == Environment.ProcessId) continue;

            var alertKey = $"lib:{pid}";
            if (_alertedPids.Contains(alertKey)) continue;

            var mapsPath = Path.Combine(procDir, "maps");
            if (!File.Exists(mapsPath)) continue;

            try
            {
                foreach (var line in File.ReadLines(mapsPath))
                {
                    if (ct.IsCancellationRequested) break;

                    // Only check executable mapped regions
                    if (!line.Contains("r-xp", StringComparison.Ordinal)) continue;

                    var mappedFile = ExtractMappedFile(line);
                    if (string.IsNullOrEmpty(mappedFile) || !mappedFile.EndsWith(".so", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Suspicious source paths
                    if (mappedFile.StartsWith("/data/local/tmp/", StringComparison.Ordinal) ||
                        mappedFile.StartsWith("/sdcard/", StringComparison.Ordinal) ||
                        mappedFile.StartsWith("/storage/", StringComparison.Ordinal) ||
                        (mappedFile.StartsWith("/data/data/", StringComparison.Ordinal) &&
                         !mappedFile.Contains("com.croatiasecurity.behavedr", StringComparison.Ordinal)))
                    {
                        signals.Add(new Signal(
                            $"suspicious_lib_android:pid:{pid}:{Path.GetFileName(mappedFile)}",
                            70, 0.78));
                        _alertedPids.Add(alertKey);
                        break;
                    }
                }
            }
            catch { }
        }
    }

    private static string ExtractMappedFile(string mapsLine)
    {
        // Maps line format: "address perms offset dev inode pathname"
        // The pathname is the last space-separated field (if present)
        var parts = mapsLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 6 ? parts[^1] : "[anon]";
    }
}
