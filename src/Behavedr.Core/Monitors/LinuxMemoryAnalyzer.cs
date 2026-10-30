namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux memory analyzer scanning /proc/*/maps for suspicious memory regions.
/// Detects:
/// - RWX (read-write-execute) private anonymous mappings in non-JIT processes
///   (strong indicator of shellcode, process injection, or reflective loading)
/// - Deleted executable mappings (memfd_create abuse, fileless malware)
/// - Unusually large anonymous mappings (shellcode staging areas)
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxMemoryAnalyzer : IPlatformMonitor
{
    private readonly ILogger<LinuxMemoryAnalyzer> _logger;

    public string PlatformName => "LinuxMemoryAnalyzer";
    public bool IsSupported => OperatingSystem.IsLinux();

    // Processes that legitimately use RWX memory (JIT compilers, VMs)
    private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "chromium", "brave", "opera", "electron",
        "java", "javaw", "node", "dotnet", "mono",
        "python", "python3", "ruby", "php", "luajit",
        "qemu", "qemu-system", "VBoxHeadless", "vmware-vmx",
        "code", "code-oss", "rider", "idea",
        "steam", "steamwebhelper",
    };

    // Regex to parse /proc/PID/maps lines
    // Format: addr-addr perms offset dev inode pathname
    // Example: 7f1234-7f5678 rwxp 00000000 00:00 0     [heap]
    private static readonly Regex MapsLineRegex = new(
        @"^([0-9a-f]+)-([0-9a-f]+)\s+(r|-)(w|-)(x|-)(p|s)\s+\S+\s+\S+\s+(\d+)\s*(.*)?$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public LinuxMemoryAnalyzer(ILogger<LinuxMemoryAnalyzer>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxMemoryAnalyzer>.Instance;
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (pid <= 4 || pid == Environment.ProcessId) continue;

                var commPath = Path.Combine(procDir, "comm");
                if (!File.Exists(commPath)) continue;

                string processName;
                try { processName = File.ReadAllText(commPath).Trim(); }
                catch { continue; }

                // Skip JIT processes (legitimate RWX)
                if (JitProcesses.Contains(processName)) continue;

                var mapsPath = Path.Combine(procDir, "maps");
                if (!File.Exists(mapsPath)) continue;

                try
                {
                    AnalyzeProcessMaps(pid, processName, mapsPath, signals, ct);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxMemoryAnalyzer] Error during memory scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("linux")]
    private void AnalyzeProcessMaps(int pid, string processName, string mapsPath, List<Signal> signals, CancellationToken ct)
    {
        int rwxCount = 0;
        int deletedExecCount = 0;
        long totalAnonymousRwx = 0;

        foreach (var line in File.ReadLines(mapsPath))
        {
            if (ct.IsCancellationRequested) break;

            var match = MapsLineRegex.Match(line);
            if (!match.Success) continue;

            var addrStart = match.Groups[1].Value;
            var addrEnd = match.Groups[2].Value;
            bool readable = match.Groups[3].Value == "r";
            bool writable = match.Groups[4].Value == "w";
            bool executable = match.Groups[5].Value == "x";
            bool isPrivate = match.Groups[6].Value == "p";
            var inode = match.Groups[7].Value;
            var pathname = match.Groups[8].Value.Trim();

            // RWX private anonymous mapping (inode 0, no pathname)
            if (readable && writable && executable && isPrivate && inode == "0" &&
                (string.IsNullOrEmpty(pathname) || pathname == "[heap]"))
            {
                rwxCount++;
                var size = CalculateRegionSize(addrStart, addrEnd);
                totalAnonymousRwx += size;
            }

            // Deleted executable mapping (fileless malware via memfd_create)
            if (executable && pathname.Contains("(deleted)", StringComparison.Ordinal))
            {
                deletedExecCount++;
            }

            // memfd without a filesystem path - fileless execution
            if (executable && pathname.Contains("memfd:", StringComparison.Ordinal))
            {
                deletedExecCount++;
            }
        }

        // Generate signals based on findings
        if (rwxCount > 0)
        {
            var weight = rwxCount switch
            {
                > 10 => 80.0,
                > 5 => 65.0,
                > 2 => 50.0,
                _ => 38.0,
            };
            var confidence = rwxCount switch
            {
                > 10 => 0.88,
                > 5 => 0.78,
                > 2 => 0.68,
                _ => 0.55,
            };

            signals.Add(new Signal(
                $"rwx_memory:{processName}(pid:{pid},regions:{rwxCount})", weight, confidence));
        }

        if (deletedExecCount > 0)
        {
            signals.Add(new Signal(
                $"fileless_execution:{processName}(pid:{pid},deleted_maps:{deletedExecCount})",
                85, 0.88));
        }

        // Large anonymous RWX (>1MB) without being a JIT = very suspicious
        if (totalAnonymousRwx > 1_048_576 && rwxCount > 0)
        {
            signals.Add(new Signal(
                $"large_rwx_staging:{processName}(pid:{pid},size:{totalAnonymousRwx / 1024}KB)",
                75, 0.82));
        }
    }

    private static long CalculateRegionSize(string addrStartHex, string addrEndHex)
    {
        try
        {
            var start = Convert.ToInt64(addrStartHex, 16);
            var end = Convert.ToInt64(addrEndHex, 16);
            return end - start;
        }
        catch { return 0; }
    }
}
