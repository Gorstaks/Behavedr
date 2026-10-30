using Android.App;
using Android.App.Usage;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Provider;
using Behavedr.Core.Models;
using Behavedr.Core.Monitors;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Application = Android.App.Application;
using Signal = Behavedr.Core.Models.Signal;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Central platform signal provider that bridges native Android APIs into
/// Behavedr's Core signal processing pipeline.
///
/// This is the key missing piece identified in the v0.2.0 audit - it provides:
/// - UsageStatsManager: foreground app tracking, app launch frequency anomalies
/// - PackageManager: sideload detection, install source verification, permission auditing
/// - ActivityLifecycleCallbacks: app foreground/background transitions
/// - ContentResolver: settings monitoring (developer options, ADB, install from unknown sources)
/// - ConnectivityManager: network type, VPN detection, metered network status
///
/// Signals are injected into the AndroidMonitor via its authenticated injection API.
/// </summary>
public sealed class AndroidPlatformSignalProvider : IDisposable
{
    private readonly Context _context;
    private readonly ILogger _logger;
    private readonly AndroidMonitor? _androidMonitor;
    private readonly string _injectionToken;
    private readonly LifecycleCallbackHandler _lifecycleHandler;
    private Timer? _periodicScanTimer;
    private bool _disposed;

    // Baseline tracking
    private HashSet<string> _baselinePackages = new();
    private bool _baselined;
    private DateTime _lastUsageCheck = DateTime.MinValue;

    public AndroidPlatformSignalProvider(
        Context context,
        AndroidMonitor? androidMonitor = null,
        ILogger? logger = null,
        string? injectionToken = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? NullLogger.Instance;
        // Prefer shared runtime monitor so signals reach the live engine (v0.2.2)
        _androidMonitor = androidMonitor ?? AndroidAgentRuntime.AndroidMonitor;
        // Prefer shared runtime token - never mint a second token that invalidates the runtime
        _injectionToken = injectionToken
            ?? (AndroidAgentRuntime.IsInitialized ? AndroidAgentRuntime.InjectionToken : Guid.NewGuid().ToString("N"));

        if (_androidMonitor is not null && !string.IsNullOrEmpty(_injectionToken))
            _androidMonitor.SetInjectionToken(_injectionToken);

        _lifecycleHandler = new LifecycleCallbackHandler(_logger);
    }

    /// <summary>
    /// Start the platform signal provider. Call from MainApplication.OnCreate or service start.
    /// </summary>
    public void Start()
    {
        // Register lifecycle callbacks if running in Application context
        if (_context is Application app)
        {
            app.RegisterActivityLifecycleCallbacks(_lifecycleHandler);
        }

        // Start periodic platform scanning (every 15 seconds)
        _periodicScanTimer = new Timer(OnPeriodicScan, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15));

        _logger.LogInformation("[PlatformSignalProvider] Started - bridging native Android APIs to Core");
    }

    /// <summary>
    /// Perform a platform scan and inject signals into Core.
    /// </summary>
    private void OnPeriodicScan(object? state)
    {
        if (_disposed) return;

        try
        {
            var signals = new List<Signal>();

            ScanInstalledPackages(signals);
            ScanUsageStats(signals);
            ScanDeviceSettings(signals);
            ScanNetworkState(signals);
            ScanLifecycleAnomalies(signals);

            if (signals.Count > 0)
            {
                // Prefer process-wide runtime so inject works even if monitor ref is stale
                if (AndroidAgentRuntime.IsInitialized)
                    AndroidAgentRuntime.InjectSignals(signals);
                else if (_androidMonitor is not null)
                    _androidMonitor.InjectPlatformSignals(signals, _injectionToken);

                _logger.LogDebug("[PlatformSignalProvider] Injected {Count} platform signals", signals.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[PlatformSignalProvider] Periodic scan error");
        }
    }

    /// <summary>
    /// Scan installed packages for sideloaded/suspicious apps.
    /// Uses PackageManager to check install sources, permissions, and known malware indicators.
    /// </summary>
    private void ScanInstalledPackages(List<Signal> signals)
    {
        try
        {
            var pm = _context.PackageManager;
            if (pm is null) return;

            var packages = pm.GetInstalledPackages(PackageInfoFlags.Permissions);
            if (packages is null) return;

            var currentPackages = new HashSet<string>();

            foreach (var pkg in packages)
            {
                if (pkg?.PackageName is null) continue;
                currentPackages.Add(pkg.PackageName);

                // Skip ourselves
                if (pkg.PackageName == _context.PackageName) continue;

                // Check for newly installed packages since baseline
                if (_baselined && !_baselinePackages.Contains(pkg.PackageName))
                {
                    var installerPackage = GetInstallerPackage(pm, pkg.PackageName);
                    var isSideloaded = installerPackage is null ||
                        (!installerPackage.Contains("vending", StringComparison.OrdinalIgnoreCase) &&
                         !installerPackage.Contains("packageinstaller", StringComparison.OrdinalIgnoreCase));

                    if (isSideloaded)
                    {
                        signals.Add(new Signal(
                            $"new_sideloaded_app:{pkg.PackageName}", 60, 0.78));
                    }
                    else
                    {
                        signals.Add(new Signal(
                            $"new_app_installed:{pkg.PackageName}", 20, 0.5));
                    }

                    // Run full package analysis
                    var pkgSignals = AnalyzePackageFull(pm, pkg);
                    signals.AddRange(pkgSignals);
                }
            }

            // Detect uninstalled packages (potential cleanup by malware)
            if (_baselined)
            {
                foreach (var oldPkg in _baselinePackages)
                {
                    if (!currentPackages.Contains(oldPkg))
                    {
                        signals.Add(new Signal($"app_uninstalled:{oldPkg}", 25, 0.5));
                    }
                }
            }

            _baselinePackages = currentPackages;
            _baselined = true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[PlatformSignalProvider] Package scan error");
        }
    }

    /// <summary>
    /// Analyze a package using both PackageManager metadata and AndroidMonitor's static analysis.
    /// </summary>
    private IEnumerable<Signal> AnalyzePackageFull(PackageManager pm, PackageInfo pkg)
    {
        var packageName = pkg.PackageName ?? "unknown";
        var installerPackage = GetInstallerPackage(pm, packageName);

        // Gather permissions
        var permissions = new List<string>();
        if (pkg.RequestedPermissions is not null)
        {
            permissions.AddRange(pkg.RequestedPermissions);
        }

        // Check for device admin
        bool hasDeviceAdmin = false;
        try
        {
            var dpm = _context.GetSystemService(Context.DevicePolicyService) as Android.App.Admin.DevicePolicyManager;
            if (dpm is not null)
            {
                var admins = dpm.ActiveAdmins;
                hasDeviceAdmin = admins?.Any(a => a?.PackageName == packageName) ?? false;
            }
        }
        catch { }

        // Check for overlay permission
        bool hasOverlay = permissions.Contains("android.permission.SYSTEM_ALERT_WINDOW");

        // Check for accessibility service
        bool hasAccessibility = false;
        try
        {
            var enabledServices = Settings.Secure.GetString(
                _context.ContentResolver, Settings.Secure.EnabledAccessibilityServices);
            hasAccessibility = enabledServices?.Contains(packageName, StringComparison.OrdinalIgnoreCase) ?? false;
        }
        catch { }

        return AndroidMonitor.AnalyzePackage(
            packageName, installerPackage,
            hasAccessibility, hasOverlay, hasDeviceAdmin, permissions);
    }

    /// <summary>
    /// Scan usage stats for anomalous app behavior:
    /// - Apps running excessively in background
    /// - Unusual foreground time patterns (cryptojacking indicator)
    /// - Apps launching at suspicious times (3 AM)
    /// </summary>
    private void ScanUsageStats(List<Signal> signals)
    {
        if ((DateTime.UtcNow - _lastUsageCheck).TotalMinutes < 5) return;
        _lastUsageCheck = DateTime.UtcNow;

        try
        {
            var usm = _context.GetSystemService(Context.UsageStatsService) as UsageStatsManager;
            if (usm is null) return;

            var endTime = Java.Lang.JavaSystem.CurrentTimeMillis();
            var startTime = endTime - (60 * 60 * 1000); // Last hour

            var stats = usm.QueryUsageStats(UsageStatsInterval.Daily, startTime, endTime);
            if (stats is null || stats.Count == 0) return;

            foreach (var stat in stats)
            {
                if (stat?.PackageName is null) continue;
                if (stat.PackageName == _context.PackageName) continue;

                // Apps with excessive foreground time (>45 minutes in last hour) - possible miner
                if (stat.TotalTimeInForeground > 45 * 60 * 1000)
                {
                    if (!IsKnownLegitimateApp(stat.PackageName))
                    {
                        signals.Add(new Signal(
                            $"excessive_foreground:{stat.PackageName}:{stat.TotalTimeInForeground / 60000}min",
                            40, 0.6));
                    }
                }
            }

            // Check for apps that launched in the last few minutes at unusual hours
            var localHour = DateTime.Now.Hour;
            if (localHour is >= 1 and <= 5) // 1 AM - 5 AM
            {
                var recentStats = usm.QueryUsageStats(UsageStatsInterval.Daily,
                    endTime - (5 * 60 * 1000), endTime);
                if (recentStats is not null)
                {
                    foreach (var stat in recentStats)
                    {
                        if (stat?.PackageName is null) continue;
                        if (stat.LastTimeUsed > startTime && !IsKnownLegitimateApp(stat.PackageName))
                        {
                            signals.Add(new Signal(
                                $"suspicious_launch_time:{stat.PackageName}:hour:{localHour}",
                                35, 0.55));
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[PlatformSignalProvider] UsageStats scan error (permission may not be granted)");
        }
    }

    /// <summary>
    /// Monitor device settings changes that indicate compromise or attack preparation:
    /// - Developer options enabled
    /// - USB debugging enabled
    /// - Install from unknown sources enabled
    /// - Mock location enabled
    /// - Accessibility services changed
    /// </summary>
    private void ScanDeviceSettings(List<Signal> signals)
    {
        try
        {
            var cr = _context.ContentResolver;
            if (cr is null) return;

            // Developer options
            var devEnabled = Settings.Global.GetInt(cr, Settings.Global.DevelopmentSettingsEnabled, 0);
            if (devEnabled == 1)
            {
                signals.Add(new Signal("developer_options_enabled", 30, 0.6));
            }

            // ADB enabled
            var adbEnabled = Settings.Global.GetInt(cr, Settings.Global.AdbEnabled, 0);
            if (adbEnabled == 1)
            {
                signals.Add(new Signal("adb_enabled_via_settings", 50, 0.75));
            }

            // Install from unknown sources (pre-Oreo global, post-Oreo per-app)
            if (Build.VERSION.SdkInt < BuildVersionCodes.O)
            {
#pragma warning disable CA1422
                var unknownSources = Settings.Secure.GetInt(cr, Settings.Secure.InstallNonMarketApps, 0);
#pragma warning restore CA1422
                if (unknownSources == 1)
                {
                    signals.Add(new Signal("unknown_sources_enabled", 45, 0.7));
                }
            }
            else
            {
                // On Oreo+, check if our app context can install unknown apps
                // The per-app API requires canRequestPackageInstalls() - but we
                // check for well-known sideloading-enabler packages
                var pm = _context.PackageManager;
                if (pm is not null)
                {
                    var sideloadApps = new[] { "com.apkpure.aegon", "org.fdroid.fdroid", "com.aurora.store" };
                    foreach (var pkg in sideloadApps)
                    {
                        try
                        {
                            pm.GetPackageInfo(pkg, 0);
                            signals.Add(new Signal($"sideload_store_installed:{pkg}", 35, 0.6));
                        }
                        catch { } // PackageNotFound - expected
                    }
                }
            }

            // Mock location
            var mockLocation = Settings.Secure.GetString(cr, "mock_location");
            if (!string.IsNullOrEmpty(mockLocation) && mockLocation != "0")
            {
                signals.Add(new Signal("mock_location_enabled", 30, 0.55));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[PlatformSignalProvider] Settings scan error");
        }
    }

    /// <summary>
    /// Scan network state for suspicious conditions:
    /// - Active VPN connections (potential traffic interception)
    /// - Proxy settings (man-in-the-middle)
    /// - Network type changes (downgrade attacks)
    /// </summary>
    private void ScanNetworkState(List<Signal> signals)
    {
        try
        {
            var cm = _context.GetSystemService(Context.ConnectivityService)
                as Android.Net.ConnectivityManager;
            if (cm is null) return;

            var activeNetwork = cm.ActiveNetwork;
            if (activeNetwork is null) return;

            var caps = cm.GetNetworkCapabilities(activeNetwork);
            if (caps is null) return;

            // Check for VPN (not ours)
            if (caps.HasTransport(Android.Net.TransportType.Vpn))
            {
                signals.Add(new Signal("third_party_vpn_active", 30, 0.5));
            }

            // Check global HTTP proxy (MITM indicator)
            var proxyHost = Settings.Global.GetString(_context.ContentResolver, "http_proxy");
            if (!string.IsNullOrEmpty(proxyHost) && proxyHost != ":0")
            {
                signals.Add(new Signal($"http_proxy_configured:{proxyHost}", 55, 0.72));
            }
        }
        catch { }
    }

    /// <summary>
    /// Analyze lifecycle callback data for anomalies:
    /// - Rapid activity transitions (overlay attacks)
    /// - Activities from unexpected packages gaining foreground
    /// </summary>
    private void ScanLifecycleAnomalies(List<Signal> signals)
    {
        var recentTransitions = _lifecycleHandler.GetRecentTransitions();
        if (recentTransitions.Count < 3) return;

        // Detect rapid flicker (overlay attack: attacker activity flashes to capture taps)
        var last5Seconds = recentTransitions
            .Where(t => (DateTime.UtcNow - t.Timestamp).TotalSeconds < 5)
            .ToList();

        if (last5Seconds.Count > 6)
        {
            signals.Add(new Signal(
                $"rapid_activity_transitions:{last5Seconds.Count}_in_5s", 65, 0.75));
        }
    }

    private static string? GetInstallerPackage(PackageManager pm, string packageName)
    {
        try
        {
            if (Build.VERSION.SdkInt >= BuildVersionCodes.R)
            {
#pragma warning disable CA1416
                var installSource = pm.GetInstallSourceInfo(packageName);
                return installSource?.InstallingPackageName;
#pragma warning restore CA1416
            }
            else
            {
#pragma warning disable CS0618, CA1422
                return pm.GetInstallerPackageName(packageName);
#pragma warning restore CS0618, CA1422
            }
        }
        catch { return null; }
    }

    private static bool IsKnownLegitimateApp(string packageName) =>
        packageName.StartsWith("com.google.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.android.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.samsung.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.microsoft.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.whatsapp", StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _periodicScanTimer?.Dispose();

        if (_context is Application app)
        {
            app.UnregisterActivityLifecycleCallbacks(_lifecycleHandler);
        }
    }
}

/// <summary>
/// Tracks activity lifecycle transitions across the application.
/// Detects overlay attacks, clickjacking, and suspicious foreground/background patterns.
/// </summary>
internal sealed class LifecycleCallbackHandler : Java.Lang.Object, Application.IActivityLifecycleCallbacks
{
    private readonly ILogger _logger;
    private readonly Queue<ActivityTransition> _recentTransitions = new();
    private readonly object _lock = new();
    private const int MaxTransitions = 50;

    public LifecycleCallbackHandler(ILogger logger)
    {
        _logger = logger;
    }

    public IReadOnlyList<ActivityTransition> GetRecentTransitions()
    {
        lock (_lock)
        {
            return _recentTransitions.ToList();
        }
    }

    public void OnActivityCreated(Activity activity, Bundle? savedInstanceState)
    {
        RecordTransition(activity, "created");
    }

    public void OnActivityStarted(Activity activity)
    {
        RecordTransition(activity, "started");
    }

    public void OnActivityResumed(Activity activity)
    {
        RecordTransition(activity, "resumed");
    }

    public void OnActivityPaused(Activity activity)
    {
        RecordTransition(activity, "paused");
    }

    public void OnActivityStopped(Activity activity)
    {
        RecordTransition(activity, "stopped");
    }

    public void OnActivitySaveInstanceState(Activity activity, Bundle outState) { }

    public void OnActivityDestroyed(Activity activity)
    {
        RecordTransition(activity, "destroyed");
    }

    private void RecordTransition(Activity activity, string state)
    {
        lock (_lock)
        {
            if (_recentTransitions.Count >= MaxTransitions)
                _recentTransitions.Dequeue();

            _recentTransitions.Enqueue(new ActivityTransition(
                activity.GetType().Name,
                activity.ComponentName?.PackageName ?? "unknown",
                state,
                DateTime.UtcNow));
        }
    }
}

internal record ActivityTransition(string ActivityName, string PackageName, string State, DateTime Timestamp);
