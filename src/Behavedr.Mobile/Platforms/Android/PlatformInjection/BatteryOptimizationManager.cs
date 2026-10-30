using Android.App;
using Android.Content;
using Android.Net;
using Android.OS;
using Android.Provider;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Signal = Behavedr.Core.Models.Signal;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Battery optimization bypass and Doze whitelist management.
///
/// Android's battery optimization (Doze mode) severely impacts EDR agents:
/// - Network access deferred (can't report to server)
/// - AlarmManager delays (watchdog fires late)
/// - JobScheduler/WorkManager delays (up to 15 minutes in deep Doze)
/// - WakeLock limits (partial wake locks throttled)
///
/// To maintain continuous monitoring, Behavedr must be whitelisted:
/// 1. REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: Direct whitelist request
/// 2. Foreground service (already implemented): Reduces but doesn't eliminate Doze
/// 3. Alarm whitelist: setExactAndAllowWhileIdle (already used in BehavedrForegroundService)
///
/// This class manages:
/// - Checking current optimization status
/// - Requesting whitelist inclusion (prompts user once)
/// - Monitoring if user/OEM revokes the whitelist
/// - OEM-specific battery killer detection (Huawei, Xiaomi, Samsung, OnePlus)
///
/// v0.2.0 audit fix: Ensures uninterrupted monitoring on aggressive OEMs.
/// </summary>
public sealed class BatteryOptimizationManager
{
    private readonly Context _context;
    private readonly ILogger _logger;
    private readonly PowerManager? _powerManager;
    private bool _whitelistRequested;

    public BatteryOptimizationManager(Context context, ILogger? logger = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? NullLogger.Instance;
        _powerManager = context.GetSystemService(Context.PowerService) as PowerManager;
    }

    /// <summary>
    /// Check if Behavedr is currently whitelisted from battery optimization.
    /// </summary>
    public bool IsWhitelisted
    {
        get
        {
            if (Build.VERSION.SdkInt < BuildVersionCodes.M) return true; // No Doze before M
            return _powerManager?.IsIgnoringBatteryOptimizations(_context.PackageName ?? "") ?? false;
        }
    }

    /// <summary>
    /// Request battery optimization whitelist. Shows a system dialog to the user.
    /// Can only be called once per session to avoid spamming the user.
    /// Returns true if already whitelisted or if request was launched.
    /// </summary>
    public bool RequestWhitelist(Activity? activity = null)
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.M) return true;
        if (IsWhitelisted) return true;
        if (_whitelistRequested) return false; // Don't spam

        try
        {
            var intent = new Intent(Settings.ActionRequestIgnoreBatteryOptimizations);
            intent.SetData(Android.Net.Uri.Parse($"package:{_context.PackageName}"));
            intent.AddFlags(ActivityFlags.NewTask);

            if (activity is not null)
            {
                activity.StartActivity(intent);
            }
            else
            {
                _context.StartActivity(intent);
            }

            _whitelistRequested = true;
            _logger.LogInformation("[BatteryOpt] Whitelist request shown to user");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[BatteryOpt] Failed to request whitelist");
            // Try alternative: open battery optimization settings
            TryOpenBatterySettings();
            return false;
        }
    }

    /// <summary>
    /// Generate signals related to battery optimization status and OEM killers.
    /// </summary>
    public IReadOnlyList<Signal> GetBatterySignals()
    {
        var signals = new List<Signal>();

        // Check if we've been removed from whitelist
        if (Build.VERSION.SdkInt >= BuildVersionCodes.M && !IsWhitelisted)
        {
            signals.Add(new Signal("battery_optimization_active:agent_throttled", 45, 0.7));
        }

        // Detect OEM-specific battery killers
        DetectOemBatteryKillers(signals);

        // Check if power saving mode is active (reduces monitoring effectiveness)
        if (_powerManager?.IsPowerSaveMode == true)
        {
            signals.Add(new Signal("power_save_mode_active", 25, 0.5));
        }

        // Check if device is in idle mode (Doze)
        if (Build.VERSION.SdkInt >= BuildVersionCodes.M && _powerManager?.IsDeviceIdleMode == true)
        {
            signals.Add(new Signal("device_doze_active", 30, 0.55));
        }

        return signals;
    }

    /// <summary>
    /// Detect OEM-specific aggressive battery management that can kill our service.
    /// Each OEM has their own proprietary battery killer on top of stock Android Doze.
    /// </summary>
    private void DetectOemBatteryKillers(List<Signal> signals)
    {
        var manufacturer = Build.Manufacturer?.ToLowerInvariant() ?? "";

        switch (manufacturer)
        {
            case "huawei" or "honor":
                DetectHuaweiBatteryKiller(signals);
                break;
            case "xiaomi" or "redmi" or "poco":
                DetectXiaomiBatteryKiller(signals);
                break;
            case "samsung":
                DetectSamsungBatteryKiller(signals);
                break;
            case "oneplus" or "oppo" or "realme":
                DetectOnePlusBatteryKiller(signals);
                break;
            case "vivo":
                DetectVivoBatteryKiller(signals);
                break;
        }
    }

    /// <summary>
    /// Huawei: PowerGenie and battery optimization - most aggressive OEM.
    /// Need to be in "Protected Apps" list and excluded from PowerGenie.
    /// </summary>
    private void DetectHuaweiBatteryKiller(List<Signal> signals)
    {
        // Check if PowerGenie is running (kills background apps)
        if (IsPackageInstalled("com.huawei.powergenie"))
        {
            signals.Add(new Signal("oem_battery_killer:huawei_powergenie", 35, 0.6));
        }

        // Check if we're NOT in the protected apps list
        // This can be detected by checking if our service was recently killed
        // and restarted by the watchdog
    }

    /// <summary>
    /// Xiaomi: MIUI battery saver aggressively kills background services.
    /// Need "autostart" permission and to be excluded from battery saver.
    /// </summary>
    private void DetectXiaomiBatteryKiller(List<Signal> signals)
    {
        if (IsPackageInstalled("com.miui.powerkeeper"))
        {
            signals.Add(new Signal("oem_battery_killer:xiaomi_powerkeeper", 35, 0.6));
        }

        // Check if MIUI autostart is available
        if (IsPackageInstalled("com.miui.securitycenter"))
        {
            // We should guide user to enable autostart
            signals.Add(new Signal("miui_autostart_required", 20, 0.45));
        }
    }

    /// <summary>
    /// Samsung: "Sleeping apps" and "Deep sleeping apps" lists.
    /// Apps in these lists get aggressively killed.
    /// </summary>
    private void DetectSamsungBatteryKiller(List<Signal> signals)
    {
        if (IsPackageInstalled("com.samsung.android.lool"))
        {
            signals.Add(new Signal("oem_battery_killer:samsung_device_care", 30, 0.55));
        }
    }

    /// <summary>
    /// OnePlus/Oppo/Realme: ColorOS battery management.
    /// </summary>
    private void DetectOnePlusBatteryKiller(List<Signal> signals)
    {
        if (IsPackageInstalled("com.oplus.battery") ||
            IsPackageInstalled("com.coloros.oppoguardelf"))
        {
            signals.Add(new Signal("oem_battery_killer:coloros", 30, 0.55));
        }
    }

    /// <summary>
    /// Vivo: iManager battery management.
    /// </summary>
    private void DetectVivoBatteryKiller(List<Signal> signals)
    {
        if (IsPackageInstalled("com.vivo.abe"))
        {
            signals.Add(new Signal("oem_battery_killer:vivo_imanager", 30, 0.55));
        }
    }

    /// <summary>
    /// Try to open OEM-specific battery settings for user to whitelist.
    /// Each OEM has different Settings activities.
    /// </summary>
    public void TryOpenOemBatterySettings()
    {
        var manufacturer = Build.Manufacturer?.ToLowerInvariant() ?? "";
        var intents = GetOemBatterySettingsIntents(manufacturer);

        foreach (var intent in intents)
        {
            try
            {
                intent.AddFlags(ActivityFlags.NewTask);
                _context.StartActivity(intent);
                return;
            }
            catch { }
        }

        // Fallback: open generic battery settings
        TryOpenBatterySettings();
    }

    private static IReadOnlyList<Intent> GetOemBatterySettingsIntents(string manufacturer)
    {
        var intents = new List<Intent>();

        switch (manufacturer)
        {
            case "huawei" or "honor":
                intents.Add(new Intent().SetComponent(new ComponentName(
                    "com.huawei.systemmanager",
                    "com.huawei.systemmanager.optimize.process.ProtectActivity")));
                intents.Add(new Intent().SetComponent(new ComponentName(
                    "com.huawei.systemmanager",
                    "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")));
                break;

            case "xiaomi" or "redmi" or "poco":
                intents.Add(new Intent().SetComponent(new ComponentName(
                    "com.miui.securitycenter",
                    "com.miui.permcenter.autostart.AutoStartManagementActivity")));
                break;

            case "samsung":
                intents.Add(new Intent().SetComponent(new ComponentName(
                    "com.samsung.android.lool",
                    "com.samsung.android.sm.ui.battery.BatteryActivity")));
                break;

            case "oneplus" or "oppo" or "realme":
                intents.Add(new Intent().SetComponent(new ComponentName(
                    "com.oplus.battery",
                    "com.oplus.battery.BatteryActivity")));
                intents.Add(new Intent().SetComponent(new ComponentName(
                    "com.coloros.oppoguardelf",
                    "com.coloros.powermanager.fuelgaue.PowerUsageModelActivity")));
                break;
        }

        return intents;
    }

    private void TryOpenBatterySettings()
    {
        try
        {
            var intent = new Intent(Settings.ActionIgnoreBatteryOptimizationSettings);
            intent.AddFlags(ActivityFlags.NewTask);
            _context.StartActivity(intent);
        }
        catch { }
    }

    private bool IsPackageInstalled(string packageName)
    {
        try
        {
            _context.PackageManager?.GetPackageInfo(packageName, 0);
            return true;
        }
        catch { return false; }
    }
}
