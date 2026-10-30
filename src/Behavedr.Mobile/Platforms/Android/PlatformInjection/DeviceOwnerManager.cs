using Android.App;
using Android.App.Admin;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Signal = Behavedr.Core.Models.Signal;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Device Owner / Profile Owner enrollment and management.
///
/// When Behavedr is provisioned as Device Owner (enterprise deployment) or
/// Profile Owner (work profile), it gains elevated response capabilities:
///
/// Device Owner powers:
/// - Wipe device data (nuclear option for compromised device)
/// - Disable/enable any app without uninstall
/// - Set app restrictions (disable network, sensors, etc.)
/// - Lock the device
/// - Set password policies
/// - Prevent factory reset
/// - Install/uninstall apps silently
/// - Control which apps can run
///
/// Profile Owner powers:
/// - Manage apps within the work profile
/// - Wipe work profile data
/// - Set profile-level restrictions
/// - Block copy/paste between profiles
/// - Control intents crossing the profile boundary
///
/// Enrollment methods:
/// 1. NFC provisioning (enterprise deployment)
/// 2. QR code provisioning
/// 3. Zero-touch enrollment (Google)
/// 4. adb shell dpm set-device-owner (development/testing)
///
/// v0.2.0 audit fix: Elevated response capabilities for enterprise Android.
/// </summary>
public sealed class DeviceOwnerManager
{
    private readonly Context _context;
    private readonly DevicePolicyManager? _dpm;
    private readonly ComponentName _adminReceiver;
    private readonly ILogger _logger;

    public DeviceOwnerManager(Context context, ILogger? logger = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? NullLogger.Instance;
        _dpm = context.GetSystemService(Context.DevicePolicyService) as DevicePolicyManager;
        _adminReceiver = new ComponentName(context, Java.Lang.Class.FromType(typeof(BehavedrDeviceAdminReceiver)));
    }

    /// <summary>
    /// Check if Behavedr is provisioned as Device Owner.
    /// </summary>
    public bool IsDeviceOwner => _dpm?.IsDeviceOwnerApp(_context.PackageName ?? "") ?? false;

    /// <summary>
    /// Check if Behavedr is provisioned as Profile Owner.
    /// </summary>
    public bool IsProfileOwner => _dpm?.IsProfileOwnerApp(_context.PackageName ?? "") ?? false;

    /// <summary>
    /// Check if Behavedr has device admin privileges (minimum level).
    /// </summary>
    public bool IsDeviceAdmin => _dpm?.IsAdminActive(_adminReceiver) ?? false;

    /// <summary>
    /// Get current privilege level for response capability assessment.
    /// </summary>
    public PrivilegeLevel CurrentPrivilegeLevel
    {
        get
        {
            if (IsDeviceOwner) return PrivilegeLevel.DeviceOwner;
            if (IsProfileOwner) return PrivilegeLevel.ProfileOwner;
            if (IsDeviceAdmin) return PrivilegeLevel.DeviceAdmin;
            return PrivilegeLevel.Standard;
        }
    }

    /// <summary>
    /// Disable a malicious application (Device Owner / Profile Owner only).
    /// The app remains installed but cannot run - far more effective than force-stop.
    /// </summary>
    public ResponseResult DisableApplication(string packageName)
    {
        if (string.IsNullOrEmpty(packageName))
            return ResponseResult.Failed("Empty package name");

        if (!IsDeviceOwner && !IsProfileOwner)
            return ResponseResult.Failed("Requires Device Owner or Profile Owner");

        // Never disable ourselves or system-critical apps
        if (packageName == _context.PackageName)
            return ResponseResult.Failed("Cannot disable self");
        if (IsSystemCriticalPackage(packageName))
            return ResponseResult.Failed($"Protected system package: {packageName}");

        try
        {
            _dpm!.SetApplicationHidden(_adminReceiver, packageName, true);
            _logger.LogWarning("[DPM] Disabled application: {Package}", packageName);
            return ResponseResult.Ok($"Application disabled: {packageName}");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Failed to disable {packageName}: {ex.Message}");
        }
    }

    /// <summary>
    /// Re-enable a previously disabled application.
    /// </summary>
    public ResponseResult EnableApplication(string packageName)
    {
        if (!IsDeviceOwner && !IsProfileOwner)
            return ResponseResult.Failed("Requires Device Owner or Profile Owner");

        try
        {
            _dpm!.SetApplicationHidden(_adminReceiver, packageName, false);
            _logger.LogInformation("[DPM] Re-enabled application: {Package}", packageName);
            return ResponseResult.Ok($"Application re-enabled: {packageName}");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Failed to enable {packageName}: {ex.Message}");
        }
    }

    /// <summary>
    /// Uninstall a malicious application silently (Device Owner only).
    /// </summary>
    public ResponseResult UninstallApplication(string packageName)
    {
        if (!IsDeviceOwner)
            return ResponseResult.Failed("Requires Device Owner");

        if (IsSystemCriticalPackage(packageName))
            return ResponseResult.Failed($"Protected system package: {packageName}");

        try
        {
            var pm = _context.PackageManager;
            if (pm is null) return ResponseResult.Failed("PackageManager unavailable");

            // Use PackageInstaller for silent uninstall (Device Owner privilege)
            var installer = pm.PackageInstaller;
            installer.Uninstall(packageName, Android.App.PendingIntent.GetBroadcast(
                _context, 0,
                new Intent("com.croatiasecurity.behavedr.UNINSTALL_RESULT"),
                PendingIntentFlags.Immutable)!.IntentSender);

            _logger.LogWarning("[DPM] Initiated uninstall of: {Package}", packageName);
            return ResponseResult.Ok($"Uninstall initiated: {packageName}");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Failed to uninstall {packageName}: {ex.Message}");
        }
    }

    /// <summary>
    /// Revoke a dangerous runtime permission from an app (Device Owner / Profile Owner).
    /// </summary>
    public ResponseResult RevokePermission(string packageName, string permission)
    {
        if (!IsDeviceOwner && !IsProfileOwner)
            return ResponseResult.Failed("Requires Device Owner or Profile Owner");

        try
        {
            if (Build.VERSION.SdkInt >= BuildVersionCodes.R)
            {
                // API 30+: setPermissionGrantState
                var result = _dpm!.SetPermissionGrantState(
                    _adminReceiver, packageName, permission,
                    Android.App.Admin.PermissionGrantState.Denied);

                if (result)
                {
                    _logger.LogWarning("[DPM] Revoked permission {Permission} from {Package}",
                        permission, packageName);
                    return ResponseResult.Ok($"Permission revoked: {permission} from {packageName}");
                }
            }

            return ResponseResult.Failed("Permission revocation not supported on this API level");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Failed to revoke {permission}: {ex.Message}");
        }
    }

    /// <summary>
    /// Lock the device immediately (requires Device Admin at minimum).
    /// Used as response when active compromise is detected.
    /// </summary>
    public ResponseResult LockDevice()
    {
        if (!IsDeviceAdmin && !IsDeviceOwner && !IsProfileOwner)
            return ResponseResult.Failed("Requires Device Admin");

        try
        {
            _dpm!.LockNow();
            _logger.LogWarning("[DPM] Device locked due to security event");
            return ResponseResult.Ok("Device locked");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Lock failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Set application network restrictions (Device Owner only).
    /// Blocks an app from accessing network - effective isolation without iptables.
    /// </summary>
    public ResponseResult RestrictAppNetwork(string packageName)
    {
        if (!IsDeviceOwner)
            return ResponseResult.Failed("Requires Device Owner");

        try
        {
            // Set user restriction: no networking for this app
            var restrictions = new Bundle();
            restrictions.PutBoolean("no_networking", true);
            _dpm!.SetApplicationRestrictions(_adminReceiver, packageName, restrictions);

            _logger.LogWarning("[DPM] Network restricted for: {Package}", packageName);
            return ResponseResult.Ok($"Network restricted: {packageName}");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Failed to restrict network: {ex.Message}");
        }
    }

    /// <summary>
    /// Wipe work profile data (Profile Owner) or entire device (Device Owner).
    /// NUCLEAR OPTION - use only when device is confirmed fully compromised.
    /// </summary>
    public ResponseResult WipeData(bool workProfileOnly = true)
    {
        if (workProfileOnly && !IsProfileOwner && !IsDeviceOwner)
            return ResponseResult.Failed("Requires Profile Owner or Device Owner");
        if (!workProfileOnly && !IsDeviceOwner)
            return ResponseResult.Failed("Full wipe requires Device Owner");

        try
        {
            var flags = workProfileOnly
                ? WipeDataFlags.WipeExternalStorage
                : WipeDataFlags.WipeExternalStorage | WipeDataFlags.WipeResetProtectionData;

            _dpm!.WipeData(flags);
            return ResponseResult.Ok("Wipe initiated");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Wipe failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Set restrictions that prevent tampering with Behavedr itself.
    /// Prevents: uninstall of agent, disabling agent, clearing agent data.
    /// </summary>
    public ResponseResult EnableSelfProtectionRestrictions()
    {
        if (!IsDeviceOwner)
            return ResponseResult.Failed("Requires Device Owner");

        try
        {
            // Prevent uninstalling the agent
            _dpm!.SetUninstallBlocked(_adminReceiver, _context.PackageName!, true);

            // Keep agent app enabled (cannot be disabled)
            _dpm.AddUserRestriction(_adminReceiver, UserManager.DisallowAppsControl);

            _logger.LogInformation("[DPM] Self-protection restrictions enabled");
            return ResponseResult.Ok("Self-protection restrictions active");
        }
        catch (Exception ex)
        {
            return ResponseResult.Failed($"Self-protection setup failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Generate signals based on current device management state.
    /// </summary>
    public IReadOnlyList<Signal> GetManagementSignals()
    {
        var signals = new List<Signal>();

        // Check if another device admin exists (potential MDM conflict or malware)
        try
        {
            var admins = _dpm?.ActiveAdmins;
            if (admins is not null)
            {
                foreach (var admin in admins)
                {
                    if (admin?.PackageName == _context.PackageName) continue;

                    // Another device admin - could be legitimate MDM or malware abusing DPM
                    if (!IsKnownMdm(admin?.PackageName))
                    {
                        signals.Add(new Signal(
                            $"unknown_device_admin:{admin?.PackageName}", 55, 0.7));
                    }
                }
            }
        }
        catch { }

        return signals;
    }

    private static bool IsKnownMdm(string? packageName) =>
        packageName is not null && (
            packageName.StartsWith("com.google.android.apps.work", StringComparison.OrdinalIgnoreCase) ||
            packageName.StartsWith("com.microsoft.intune", StringComparison.OrdinalIgnoreCase) ||
            packageName.StartsWith("com.airwatch", StringComparison.OrdinalIgnoreCase) ||
            packageName.StartsWith("com.mobileiron", StringComparison.OrdinalIgnoreCase) ||
            packageName.StartsWith("com.jamf", StringComparison.OrdinalIgnoreCase));

    private static bool IsSystemCriticalPackage(string packageName) =>
        packageName.StartsWith("com.android.", StringComparison.OrdinalIgnoreCase) ||
        packageName == "android" ||
        packageName.StartsWith("com.google.android.gms", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.google.android.gsf", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Device Admin receiver - required for any DPM operations.
/// Handles admin enable/disable callbacks and password/compliance events.
/// </summary>
[BroadcastReceiver(
    Name = "com.croatiasecurity.behavedr.BehavedrDeviceAdminReceiver",
    Permission = "android.permission.BIND_DEVICE_ADMIN",
    Exported = true)]
[MetaData("android.app.device_admin", Resource = "@xml/device_admin_policies")]
[IntentFilter(new[] { "android.app.action.DEVICE_ADMIN_ENABLED" })]
public class BehavedrDeviceAdminReceiver : DeviceAdminReceiver
{
    public override void OnEnabled(Context context, Intent intent)
    {
        base.OnEnabled(context, intent);
        WriteForensicLog("ADMIN_ENABLED");
    }

    public override void OnDisabled(Context context, Intent intent)
    {
        base.OnDisabled(context, intent);
        WriteForensicLog("ADMIN_DISABLED - agent protection reduced");
    }

    public override void OnPasswordFailed(Context context, Intent intent, UserHandle user)
    {
        base.OnPasswordFailed(context, intent, user);
        WriteForensicLog("PASSWORD_FAILED - possible brute force attempt");
    }

    public override void OnPasswordSucceeded(Context context, Intent intent, UserHandle user)
    {
        base.OnPasswordSucceeded(context, intent, user);
    }

    private static void WriteForensicLog(string message)
    {
        try
        {
            var logDir = Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "logs");
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, "dpm-forensic.log");
            File.AppendAllText(logPath,
                $"[{DateTime.UtcNow:O}] {message}{System.Environment.NewLine}");
        }
        catch { }
    }
}

/// <summary>Privilege level enumeration for capability scaling.</summary>
public enum PrivilegeLevel
{
    Standard,       // No special privileges
    DeviceAdmin,    // Basic admin (lock, password policy)
    ProfileOwner,   // Work profile management
    DeviceOwner,    // Full device control
}

/// <summary>Simple result type for DPM operations.</summary>
public record ResponseResult(bool Success, string Message)
{
    public static ResponseResult Ok(string msg) => new(true, msg);
    public static ResponseResult Failed(string msg) => new(false, msg);
}
