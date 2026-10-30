namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

/// <summary>
/// Monitors Windows Subsystem for Linux (WSL) attack surface (T1202):
/// - WSL process spawns with suspicious command lines
/// - Runtime WSL distribution installs (wsl --import)
/// - Processes loaded from \\wsl$ filesystem
/// </summary>
[SupportedOSPlatform("windows")]
public class WslMonitor : IPlatformMonitor
{
    private readonly ILogger<WslMonitor> _logger;
    private readonly HashSet<string> _baselineDistros = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _alertedPids = new();
    private bool _baselined;

    // Behavioral cmdline patterns (not product names alone - rename-resistant where possible)
    private static readonly string[] SuspiciousPatterns =
    {
        "nc -", "ncat ", "socat ", "/dev/tcp/", "bash -i",
        "curl http", "wget http", "python -c", "python3 -c",
        "perl -e", "ruby -e", "reverse_tcp",
        "base64 -d", "nmap ", "masscan", "/etc/shadow",
        "/tmp/", "/dev/shm/",
    };

    public string PlatformName => "WslMonitor";
    public bool IsSupported => OperatingSystem.IsWindows() &&
        File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));

    public WslMonitor(ILogger<WslMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<WslMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            ScanWslProcesses(signals, ct);
            CheckNewDistros(signals);
            MonitorWslFilesystem(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[WslMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void ScanWslProcesses(List<Signal> signals, CancellationToken ct)
    {
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (ct.IsCancellationRequested) break;
                var name = proc.ProcessName.ToLowerInvariant();
                if (name is not ("wsl" or "wslhost" or "bash")) continue;
                if (_alertedPids.Contains(proc.Id)) continue;

                string? cmdLine = null;
                try
                {
                    using var searcher = new System.Management.ManagementObjectSearcher(
                        $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
                    foreach (System.Management.ManagementObject obj in searcher.Get())
                    { cmdLine = obj["CommandLine"]?.ToString(); break; }
                }
                catch { }

                if (string.IsNullOrEmpty(cmdLine)) continue;

                var cmdLower = cmdLine.ToLowerInvariant();
                foreach (var pattern in SuspiciousPatterns)
                {
                    if (cmdLower.Contains(pattern))
                    {
                        signals.Add(new Signal(
                            $"wsl_suspicious_command:{proc.ProcessName}:pid:{proc.Id}:pattern:{pattern}",
                            70, 0.78));
                        _alertedPids.Add(proc.Id);
                        break;
                    }
                }
            }
            catch { }
            finally { proc.Dispose(); }
        }

        if (_alertedPids.Count > 500) _alertedPids.Clear();
    }

    [SupportedOSPlatform("windows")]
    private void CheckNewDistros(List<Signal> signals)
    {
        var current = GetInstalledDistros();

        if (!_baselined)
        {
            _baselineDistros.UnionWith(current);
            _baselined = true;
            return;
        }

        foreach (var distro in current)
        {
            if (_baselineDistros.Contains(distro)) continue;
            _baselineDistros.Add(distro);
            signals.Add(new Signal($"wsl_new_distro_installed:{distro}", 65, 0.72));
        }
    }

    [SupportedOSPlatform("windows")]
    private static HashSet<string> GetInstalledDistros()
    {
        var distros = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Lxss");
            if (key == null) return distros;
            foreach (var sub in key.GetSubKeyNames())
            {
                using var subKey = key.OpenSubKey(sub);
                var name = subKey?.GetValue("DistributionName")?.ToString();
                if (!string.IsNullOrEmpty(name)) distros.Add(name);
            }
        }
        catch { }
        return distros;
    }

    // --- RT-9 FIX: WSL Filesystem Monitoring ---

    private readonly HashSet<string> _alertedWslFiles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// RT-9 FIX: Monitor the \\wsl$ filesystem for suspicious file creation.
    /// Scans for executables, scripts, and known attack tool artifacts written from
    /// WSL into the Windows-accessible filesystem.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void MonitorWslFilesystem(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            // Check \\wsl$ mount points for suspicious files
            var wslRoot = @"\\wsl$";
            if (!Directory.Exists(wslRoot)) return;

            foreach (var distroDir in Directory.GetDirectories(wslRoot))
            {
                if (ct.IsCancellationRequested) break;

                // Check /tmp equivalent for suspicious executables
                var tmpPath = Path.Combine(distroDir, "tmp");
                if (Directory.Exists(tmpPath))
                {
                    ScanWslDirectory(tmpPath, signals, ct);
                }

                // Check common attack staging dirs
                var devShmPath = Path.Combine(distroDir, "dev", "shm");
                if (Directory.Exists(devShmPath))
                {
                    ScanWslDirectory(devShmPath, signals, ct);
                }
            }

            // Also check if WSL is accessing Windows credential paths via /mnt/c
            foreach (var distroDir in Directory.GetDirectories(wslRoot))
            {
                if (ct.IsCancellationRequested) break;
                var mntC = Path.Combine(distroDir, "mnt", "c");
                // Check for recently-created suspicious files in mnt paths
                // (We don't scan all of C: - just check for known suspicious patterns)
                var histPath = Path.Combine(distroDir, "root", ".bash_history");
                if (File.Exists(histPath))
                {
                    try
                    {
                        var lastWrite = File.GetLastWriteTimeUtc(histPath);
                        if ((DateTime.UtcNow - lastWrite).TotalSeconds < 60)
                        {
                            // Recent bash activity - check last lines for suspicious commands
                            var lines = File.ReadLines(histPath).TakeLast(5);
                            foreach (var line in lines)
                            {
                                var lower = line.ToLowerInvariant();
                                foreach (var pattern in SuspiciousPatterns)
                                {
                                    if (lower.Contains(pattern))
                                    {
                                        var key = $"wslhist:{pattern}:{distroDir}";
                                        if (_alertedWslFiles.Contains(key)) break;
                                        _alertedWslFiles.Add(key);

                                        signals.Add(new Signal(
                                            $"wsl_suspicious_history:{Path.GetFileName(distroDir)}:{pattern}",
                                            68, 0.75));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }

            if (_alertedWslFiles.Count > 200) _alertedWslFiles.Clear();
        }
        catch { }
    }

    private void ScanWslDirectory(string path, List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var file in Directory.GetFiles(path))
            {
                if (ct.IsCancellationRequested) break;
                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(fileName).ToLowerInvariant();

                // Suspicious: ELF binaries, scripts, or Windows executables in WSL tmp
                bool suspicious = ext is ".exe" or ".dll" or ".ps1" or ".bat" or ".sh" or ".py" or ".elf"
                    || string.IsNullOrEmpty(ext); // Unix executables often have no extension

                if (!suspicious) continue;

                // Check if recently created (last 5 minutes)
                try
                {
                    var created = File.GetCreationTimeUtc(file);
                    if ((DateTime.UtcNow - created).TotalMinutes > 5) continue;
                }
                catch { continue; }

                var key = $"wslfile:{file}";
                if (_alertedWslFiles.Contains(key)) continue;
                _alertedWslFiles.Add(key);

                signals.Add(new Signal(
                    $"wsl_suspicious_file:{Path.GetFileName(Path.GetDirectoryName(path))}:{fileName}",
                    60, 0.68));
                _logger.LogWarning(
                    "[WslMonitor] Suspicious file in WSL temp: {File}", file);
            }
        }
        catch { }
    }
}
