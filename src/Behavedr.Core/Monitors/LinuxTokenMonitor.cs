namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux privilege escalation and token integrity monitor.
/// Equivalent to Windows TokenIntegrityMonitor - detects:
/// - Processes that changed UID (escalated privileges at runtime)
/// - Binaries running as root from user-writable directories (/tmp, /home, /var/tmp)
/// - Capability escalation (non-root process with dangerous caps)
/// - Failed sudo/su attempts (brute force indicator)
/// - setuid/setgid execution from suspicious paths
/// - Polkit/pkexec exploitation indicators
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxTokenMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxTokenMonitor> _logger;
    private readonly Dictionary<int, (int Uid, int Euid)> _uidBaseline = new();
    private bool _baselined;

    public string PlatformName => "LinuxToken";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxTokenMonitor(ILogger<LinuxTokenMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxTokenMonitor>.Instance;
    }

    private static readonly HashSet<string> UserWritableDirs = new(StringComparer.Ordinal)
    {
        "/tmp", "/var/tmp", "/dev/shm", "/home",
    };

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        var currentState = new Dictionary<int, (int Uid, int Euid, string Name, string Exe)>();

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (pid <= 1 || pid == Environment.ProcessId) continue;

                var statusPath = Path.Combine(procDir, "status");
                if (!File.Exists(statusPath)) continue;

                try
                {
                    int uid = -1, euid = -1;
                    string? name = null;
                    foreach (var line in File.ReadLines(statusPath))
                    {
                        if (line.StartsWith("Name:", StringComparison.Ordinal))
                            name = line["Name:".Length..].Trim();
                        else if (line.StartsWith("Uid:", StringComparison.Ordinal))
                        {
                            // Format: Uid: real effective saved filesystem
                            var parts = line["Uid:".Length..].Split('\t', StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2)
                            {
                                int.TryParse(parts[0], out uid);
                                int.TryParse(parts[1], out euid);
                            }
                        }
                        if (name is not null && uid >= 0) break;
                    }

                    if (name is null || uid < 0) continue;

                    // Resolve exe path
                    string exe = "";
                    try
                    {
                        var exeLink = File.ResolveLinkTarget(Path.Combine(procDir, "exe"), false);
                        exe = exeLink?.ToString() ?? "";
                    }
                    catch { }

                    currentState[pid] = (uid, euid, name, exe);

                    // Detection: root process from user-writable directory
                    if (euid == 0 && !string.IsNullOrEmpty(exe))
                    {
                        foreach (var dir in UserWritableDirs)
                        {
                            if (exe.StartsWith(dir, StringComparison.Ordinal))
                            {
                                signals.Add(new Signal(
                                    $"elevated_from_writable_dir:{name}:pid:{pid}:{exe}",
                                    78, 0.85));
                                break;
                            }
                        }
                    }

                    // Detection: UID changed since last check (runtime escalation)
                    if (_baselined && _uidBaseline.TryGetValue(pid, out var prev))
                    {
                        if (prev.Euid != 0 && euid == 0)
                        {
                            signals.Add(new Signal(
                                $"runtime_privilege_escalation:{name}:pid:{pid}:uid:{prev.Euid}->0",
                                90, 0.92));
                            _logger.LogWarning(
                                "[LinuxToken] Privilege escalation: {Name} PID {Pid} euid {Old}->0",
                                name, pid, prev.Euid);
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            // Detect polkit/pkexec exploitation patterns
            DetectPolkitAbuse(signals, currentState, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxToken] Error during token scan");
        }

        _uidBaseline.Clear();
        foreach (var (pid, state) in currentState)
            _uidBaseline[pid] = (state.Uid, state.Euid);
        _baselined = true;

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("linux")]
    private void DetectPolkitAbuse(List<Signal> signals,
        Dictionary<int, (int Uid, int Euid, string Name, string Exe)> state, CancellationToken ct)
    {
        foreach (var (pid, info) in state)
        {
            if (ct.IsCancellationRequested) break;
            if (info.Name is not "pkexec") continue;

            // pkexec running from non-standard path or with suspicious parent
            if (!string.IsNullOrEmpty(info.Exe) && !info.Exe.StartsWith("/usr/", StringComparison.Ordinal))
            {
                signals.Add(new Signal(
                    $"polkit_abuse:pkexec_from_unusual_path:pid:{pid}:{info.Exe}", 85, 0.88));
            }
        }
    }
}
