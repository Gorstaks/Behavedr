namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux persistence mechanism detection monitor.
/// Baselines then detects changes to:
/// - Crontab entries (user and system: /var/spool/cron, /etc/cron.d, /etc/crontab)
/// - Systemd unit files (/etc/systemd/system, ~/.config/systemd/user)
/// - Init.d scripts (/etc/init.d)
/// - Profile/RC scripts (/etc/profile.d, ~/.bashrc, ~/.profile, /etc/bash.bashrc)
/// - LD_PRELOAD persistence (/etc/ld.so.preload)
/// - At jobs (/var/spool/at)
/// - Authorized SSH keys modifications
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxPersistenceMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxPersistenceMonitor> _logger;
    private Dictionary<string, DateTime> _baseline = new();
    private bool _baselined;

    public string PlatformName => "LinuxPersistence";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxPersistenceMonitor(ILogger<LinuxPersistenceMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxPersistenceMonitor>.Instance;
    }

    // Persistence locations with their threat weight and confidence
    private static readonly (string Path, string Category, double Weight, double Confidence)[] PersistenceLocations =
    [
        ("/etc/crontab", "crontab", 72, 0.8),
        ("/etc/ld.so.preload", "ld_preload_persist", 90, 0.92),
        ("/etc/bash.bashrc", "shell_rc", 60, 0.7),
        ("/etc/profile", "shell_profile", 60, 0.7),
    ];

    // Directories to scan for new files (persistence via new entries)
    private static readonly (string Dir, string Pattern, string Category, double Weight, double Confidence)[] PersistenceDirs =
    [
        ("/etc/cron.d", "*", "cron_drop", 72, 0.8),
        ("/etc/cron.daily", "*", "cron_daily", 65, 0.75),
        ("/etc/cron.hourly", "*", "cron_hourly", 70, 0.78),
        ("/var/spool/cron/crontabs", "*", "user_crontab", 72, 0.8),
        ("/etc/systemd/system", "*.service", "systemd_unit", 75, 0.82),
        ("/etc/systemd/system", "*.timer", "systemd_timer", 75, 0.82),
        ("/etc/init.d", "*", "initd_script", 70, 0.78),
        ("/etc/profile.d", "*.sh", "profile_drop", 65, 0.72),
        ("/var/spool/at", "*", "at_job", 60, 0.7),
    ];

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        var current = ScanPersistenceState(ct);

        if (!_baselined)
        {
            _baseline = current;
            _baselined = true;
            _logger.LogInformation("[LinuxPersistence] Baselined {Count} persistence entries", _baseline.Count);
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        // Detect new files (not in baseline)
        foreach (var (path, modTime) in current)
        {
            if (ct.IsCancellationRequested) break;

            if (!_baseline.ContainsKey(path))
            {
                var (weight, confidence, category) = ClassifyPersistencePath(path);
                signals.Add(new Signal(
                    $"new_persistence:{category}:{Path.GetFileName(path)}",
                    weight, confidence));
                _logger.LogWarning("[LinuxPersistence] New persistence entry detected: {Path}", path);
            }
            else if (_baseline[path] != modTime)
            {
                var (weight, confidence, category) = ClassifyPersistencePath(path);
                // Modified existing persistence file - slightly lower weight
                signals.Add(new Signal(
                    $"modified_persistence:{category}:{Path.GetFileName(path)}",
                    weight * 0.85, confidence * 0.9));
            }
        }

        // Check for ld.so.preload creation specifically (very high signal)
        if (File.Exists("/etc/ld.so.preload") && !_baseline.ContainsKey("/etc/ld.so.preload"))
        {
            signals.Add(new Signal("ld_preload_persistence_created", 92, 0.95));
        }

        // Check user-level persistence
        DetectUserPersistence(signals, ct);

        _baseline = current;
        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect user-level persistence: ~/.bashrc, ~/.profile, systemd user units,
    /// authorized_keys modifications.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DetectUserPersistence(List<Signal> signals, CancellationToken ct)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Check user shell RC files for suspicious additions
        var rcFiles = new[] { ".bashrc", ".profile", ".bash_profile", ".zshrc", ".zprofile" };
        foreach (var rcFile in rcFiles)
        {
            if (ct.IsCancellationRequested) break;
            var rcPath = Path.Combine(home, rcFile);
            if (!File.Exists(rcPath)) continue;

            try
            {
                var content = File.ReadAllText(rcPath);
                // Look for suspicious patterns in RC files
                if (content.Contains("/dev/tcp/", StringComparison.Ordinal) ||
                    content.Contains("base64 -d", StringComparison.Ordinal) ||
                    content.Contains("curl ", StringComparison.Ordinal) && content.Contains("| bash", StringComparison.Ordinal))
                {
                    signals.Add(new Signal(
                        $"malicious_rc_content:{rcFile}", 82, 0.85));
                }
            }
            catch { }
        }

        // User systemd units
        var userSystemdDir = Path.Combine(home, ".config", "systemd", "user");
        if (Directory.Exists(userSystemdDir))
        {
            try
            {
                foreach (var unit in Directory.GetFiles(userSystemdDir, "*.service"))
                {
                    if (ct.IsCancellationRequested) break;
                    var age = DateTime.UtcNow - File.GetCreationTimeUtc(unit);
                    if (age.TotalMinutes < 30)
                    {
                        signals.Add(new Signal(
                            $"new_user_systemd_unit:{Path.GetFileName(unit)}", 70, 0.78));
                    }
                }
            }
            catch { }
        }

        // authorized_keys modification
        var authKeysPath = Path.Combine(home, ".ssh", "authorized_keys");
        if (File.Exists(authKeysPath))
        {
            var key = authKeysPath;
            var modTime = File.GetLastWriteTimeUtc(authKeysPath);
            if (_baseline.TryGetValue(key, out var baselineTime) && baselineTime != modTime)
            {
                signals.Add(new Signal("authorized_keys_modified", 78, 0.83));
            }
        }
    }

    [SupportedOSPlatform("linux")]
    private Dictionary<string, DateTime> ScanPersistenceState(CancellationToken ct)
    {
        var state = new Dictionary<string, DateTime>();

        // Single files
        foreach (var (path, _, _, _) in PersistenceLocations)
        {
            if (ct.IsCancellationRequested) break;
            if (File.Exists(path))
            {
                try { state[path] = File.GetLastWriteTimeUtc(path); }
                catch { }
            }
        }

        // Directories
        foreach (var (dir, pattern, _, _, _) in PersistenceDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.GetFiles(dir, pattern))
                {
                    try { state[file] = File.GetLastWriteTimeUtc(file); }
                    catch { }
                }
            }
            catch { }
        }

        // User authorized_keys
        var authKeys = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "authorized_keys");
        if (File.Exists(authKeys))
        {
            try { state[authKeys] = File.GetLastWriteTimeUtc(authKeys); }
            catch { }
        }

        return state;
    }

    private static (double Weight, double Confidence, string Category) ClassifyPersistencePath(string path)
    {
        if (path.Contains("cron", StringComparison.OrdinalIgnoreCase))
            return (72, 0.8, "cron");
        if (path.Contains("systemd", StringComparison.OrdinalIgnoreCase))
            return (75, 0.82, "systemd");
        if (path.Contains("init.d", StringComparison.OrdinalIgnoreCase))
            return (70, 0.78, "initd");
        if (path.Contains("profile", StringComparison.OrdinalIgnoreCase))
            return (65, 0.72, "profile");
        if (path.Contains("ld.so.preload", StringComparison.OrdinalIgnoreCase))
            return (92, 0.95, "ld_preload");
        return (60, 0.7, "unknown");
    }
}
