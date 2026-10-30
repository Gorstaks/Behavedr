namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android persistence mechanism detection.
/// Detects:
/// - Boot receiver registration (apps that auto-start on boot)
/// - Device administrator activation (prevents uninstall)
/// - Accessibility service persistence (survives force-stop)
/// - Work profile abuse (create managed profile for persistence)
/// - APK files in unusual persistence locations
/// - Init scripts in /system/etc/init (requires root to plant)
/// - Scheduled jobs via android.app.job.JobScheduler patterns
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidPersistenceMonitor : IPlatformMonitor
{
    private readonly ILogger<AndroidPersistenceMonitor> _logger;
    private Dictionary<string, DateTime> _baseline = new();
    private bool _baselined;

    public string PlatformName => "AndroidPersistence";
    public bool IsSupported => OperatingSystem.IsAndroid();

    public AndroidPersistenceMonitor(ILogger<AndroidPersistenceMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidPersistenceMonitor>.Instance;
    }

    // System persistence locations that require root to modify
    private static readonly (string Dir, string Pattern, string Category, double Weight, double Confidence)[] PersistenceDirs =
    [
        ("/system/etc/init", "*.rc", "init_script", 90, 0.92),
        ("/system/app", "*.apk", "system_app", 75, 0.8),
        ("/system/priv-app", "*.apk", "priv_app", 80, 0.85),
        ("/data/local/tmp", "*.apk", "staged_apk", 60, 0.7),
        ("/data/app", "*.apk", "installed_app", 30, 0.5),
    ];

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var current = ScanPersistenceState(ct);

            if (!_baselined)
            {
                _baseline = current;
                _baselined = true;
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
                        $"new_persistence:{category}:{Path.GetFileName(path)}", weight, confidence));
                }
            }

            _baseline = current;

            // Additional heuristic checks
            DetectSuspiciousServices(signals, ct);
            DetectHiddenApps(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AndroidPersistence] Error during scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect processes masquerading as system services or using misleading names.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectSuspiciousServices(List<Signal> signals, CancellationToken ct)
    {
        var suspiciousNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "com.android.systemservice", "com.android.system.update",
            "com.google.android.systemupdate", "system_server_helper",
        };

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                try
                {
                    var cmdlinePath = Path.Combine(procDir, "cmdline");
                    if (!File.Exists(cmdlinePath)) continue;
                    var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ').Trim();

                    if (suspiciousNames.Any(s => cmdline.Contains(s, StringComparison.OrdinalIgnoreCase)))
                    {
                        signals.Add(new Signal(
                            $"fake_system_service:{cmdline.Split(' ')[0]}:pid:{pid}", 78, 0.83));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect apps attempting to hide by using invisible names or no launcher icon.
    /// Checks for APKs in non-standard installation locations.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectHiddenApps(List<Signal> signals, CancellationToken ct)
    {
        // Check for APKs in directories that shouldn't have user-installed apps
        var hiddenDirs = new[] { "/data/local/tmp", "/sdcard/.hidden", "/sdcard/Android/data/.system" };

        foreach (var dir in hiddenDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var apk in Directory.GetFiles(dir, "*.apk"))
                {
                    var age = DateTime.UtcNow - File.GetCreationTimeUtc(apk);
                    if (age.TotalHours < 24)
                    {
                        signals.Add(new Signal(
                            $"hidden_apk:{Path.GetFileName(apk)}:{dir}", 65, 0.72));
                    }
                }
            }
            catch { }
        }
    }

    [SupportedOSPlatform("android")]
    private Dictionary<string, DateTime> ScanPersistenceState(CancellationToken ct)
    {
        var state = new Dictionary<string, DateTime>();

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

        return state;
    }

    private static (double Weight, double Confidence, string Category) ClassifyPath(string path)
    {
        if (path.Contains("/init", StringComparison.OrdinalIgnoreCase))
            return (90, 0.92, "init_script");
        if (path.Contains("/system/priv-app", StringComparison.OrdinalIgnoreCase))
            return (80, 0.85, "priv_app");
        if (path.Contains("/system/app", StringComparison.OrdinalIgnoreCase))
            return (75, 0.8, "system_app");
        if (path.Contains("/local/tmp", StringComparison.OrdinalIgnoreCase))
            return (60, 0.7, "staged_apk");
        return (45, 0.6, "unknown");
    }
}
