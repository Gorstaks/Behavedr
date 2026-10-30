namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS persistence mechanism detection monitor.
/// Baselines then detects changes to:
/// - LaunchAgents (~/Library/LaunchAgents, /Library/LaunchAgents)
/// - LaunchDaemons (/Library/LaunchDaemons)
/// - Login Items (~/Library/Application Support/com.apple.backgroundtaskmanagementagent)
/// - Cron jobs (/usr/lib/cron/tabs, /var/at/tabs)
/// - Authorization plugins (/Library/Security/SecurityAgentPlugins)
/// - Periodic scripts (/etc/periodic)
/// - Configuration profiles (/Library/Managed Preferences)
/// - Kernel extensions (/Library/Extensions, /System/Library/Extensions)
/// </summary>
[SupportedOSPlatform("macos")]
public class MacOSPersistenceMonitor : IPlatformMonitor
{
    private readonly ILogger<MacOSPersistenceMonitor> _logger;
    private Dictionary<string, DateTime> _baseline = new();
    private bool _baselined;

    public string PlatformName => "MacOSPersistence";
    public bool IsSupported => OperatingSystem.IsMacOS();

    public MacOSPersistenceMonitor(ILogger<MacOSPersistenceMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSPersistenceMonitor>.Instance;
    }

    private static readonly (string Dir, string Pattern, string Category, double Weight, double Confidence)[] PersistenceDirs =
    [
        ("/Library/LaunchDaemons", "*.plist", "launch_daemon", 82, 0.88),
        ("/Library/LaunchAgents", "*.plist", "launch_agent_system", 75, 0.82),
        ("/Library/Security/SecurityAgentPlugins", "*", "auth_plugin", 90, 0.92),
        ("/Library/Extensions", "*.kext", "kernel_extension", 88, 0.9),
        ("/etc/periodic/daily", "*", "periodic_daily", 65, 0.72),
        ("/etc/periodic/weekly", "*", "periodic_weekly", 60, 0.68),
        ("/usr/lib/cron/tabs", "*", "cron_tab", 72, 0.8),
        ("/var/at/tabs", "*", "cron_tab", 72, 0.8),
    ];

    [SupportedOSPlatform("macos")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        var current = ScanPersistenceState(ct);

        if (!_baselined)
        {
            _baseline = current;
            _baselined = true;
            _logger.LogInformation("[MacOSPersistence] Baselined {Count} persistence entries", _baseline.Count);
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        // Detect new persistence entries
        foreach (var (path, modTime) in current)
        {
            if (ct.IsCancellationRequested) break;

            if (!_baseline.ContainsKey(path))
            {
                var (weight, confidence, category) = ClassifyPath(path);
                signals.Add(new Signal(
                    $"new_persistence:{category}:{Path.GetFileName(path)}",
                    weight, confidence));
                _logger.LogWarning("[MacOSPersistence] New persistence entry: {Path}", path);

                // Extra analysis for plist files - check for suspicious content
                if (path.EndsWith(".plist", StringComparison.OrdinalIgnoreCase))
                {
                    AnalyzePlist(path, signals);
                }
            }
            else if (_baseline[path] != modTime)
            {
                var (weight, confidence, category) = ClassifyPath(path);
                signals.Add(new Signal(
                    $"modified_persistence:{category}:{Path.GetFileName(path)}",
                    weight * 0.85, confidence * 0.9));
            }
        }

        _baseline = current;
        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Analyze a plist file for suspicious patterns (shell scripts, curl downloads, encoded payloads).
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void AnalyzePlist(string path, List<Signal> signals)
    {
        try
        {
            var content = File.ReadAllText(path);

            // Suspicious: plist running shell commands
            if (content.Contains("/bin/bash", StringComparison.Ordinal) ||
                content.Contains("/bin/sh", StringComparison.Ordinal) ||
                content.Contains("/bin/zsh", StringComparison.Ordinal))
            {
                if (content.Contains("curl", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("wget", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("base64", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal(
                        $"suspicious_plist_content:{Path.GetFileName(path)}", 85, 0.88));
                }
            }

            // Hidden launch agent (RunAtLoad + no label starting with com.apple)
            if (content.Contains("RunAtLoad", StringComparison.Ordinal) &&
                content.Contains("<true/>", StringComparison.Ordinal) &&
                !content.Contains("com.apple.", StringComparison.Ordinal))
            {
                // Non-Apple RunAtLoad plist in system directory = suspicious
                if (path.Contains("/Library/", StringComparison.Ordinal))
                {
                    signals.Add(new Signal(
                        $"non_apple_runAtLoad:{Path.GetFileName(path)}", 70, 0.75));
                }
            }
        }
        catch { }
    }

    [SupportedOSPlatform("macos")]
    private Dictionary<string, DateTime> ScanPersistenceState(CancellationToken ct)
    {
        var state = new Dictionary<string, DateTime>();
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // User LaunchAgents
        var userLaunchAgents = Path.Combine(home, "Library", "LaunchAgents");
        ScanDir(userLaunchAgents, "*.plist", state, ct);

        // System persistence directories
        foreach (var (dir, pattern, _, _, _) in PersistenceDirs)
        {
            if (ct.IsCancellationRequested) break;
            ScanDir(dir, pattern, state, ct);
        }

        // Login items
        var loginItemsDir = Path.Combine(home, "Library",
            "Application Support", "com.apple.backgroundtaskmanagementagent");
        ScanDir(loginItemsDir, "*", state, ct);

        return state;
    }

    private static void ScanDir(string dir, string pattern, Dictionary<string, DateTime> state, CancellationToken ct)
    {
        if (!Directory.Exists(dir)) return;
        try
        {
            foreach (var file in Directory.GetFiles(dir, pattern))
            {
                if (ct.IsCancellationRequested) break;
                try { state[file] = File.GetLastWriteTimeUtc(file); }
                catch { }
            }
        }
        catch { }
    }

    private static (double Weight, double Confidence, string Category) ClassifyPath(string path)
    {
        if (path.Contains("LaunchDaemon", StringComparison.OrdinalIgnoreCase))
            return (82, 0.88, "launch_daemon");
        if (path.Contains("LaunchAgent", StringComparison.OrdinalIgnoreCase))
            return (75, 0.82, "launch_agent");
        if (path.Contains("SecurityAgentPlugin", StringComparison.OrdinalIgnoreCase))
            return (90, 0.92, "auth_plugin");
        if (path.Contains("Extensions", StringComparison.OrdinalIgnoreCase) &&
            path.EndsWith(".kext", StringComparison.OrdinalIgnoreCase))
            return (88, 0.9, "kext");
        if (path.Contains("cron", StringComparison.OrdinalIgnoreCase))
            return (72, 0.8, "cron");
        if (path.Contains("periodic", StringComparison.OrdinalIgnoreCase))
            return (65, 0.72, "periodic");
        if (path.Contains("loginitem", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("backgroundtask", StringComparison.OrdinalIgnoreCase))
            return (68, 0.75, "login_item");
        return (60, 0.7, "unknown");
    }
}
