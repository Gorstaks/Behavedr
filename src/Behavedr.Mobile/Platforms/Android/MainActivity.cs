using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Behavedr.Mobile.PlatformInjection;

using Environment = System.Environment;

namespace Behavedr.Mobile;

/// <summary>
/// Launcher activity. Initializes Android platform security components, starts the
/// foreground monitoring service, and hosts the visible status screen (AgentPage).
///
/// v0.4.5: no longer self-hides. It previously used Theme.NoDisplay and called
/// MoveTaskToBack on launch, which gave the app no UI and made it look like spyware.
/// v0.2.2: All detection/response lives in <see cref="AndroidAgentRuntime"/> +
/// <see cref="BehavedrForegroundService"/>. Activity no longer creates orphan
/// signal providers that never reached the engine.
/// </summary>
[Activity(
    Theme = "@style/Maui.SplashTheme",
    MainLauncher = true,
    Exported = true,
    LaunchMode = LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.ScreenSize
        | ConfigChanges.Orientation
        | ConfigChanges.UiMode
        | ConfigChanges.ScreenLayout
        | ConfigChanges.SmallestScreenSize
        | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // 1. Keystore bridge (also done in Application.OnCreate)
        KeystoreBridgeRegistration.Register();

        // 2. Shared agent runtime (engine + response + injection token)
        AndroidAgentRuntime.EnsureInitialized();

        // 3. Supply chain verification - inject critical signals into engine
        try
        {
            var supplyChainVerifier = new SupplyChainVerifier(ApplicationContext!);
            var scSignals = supplyChainVerifier.Verify();
            if (scSignals.Count > 0)
            {
                AndroidAgentRuntime.InjectSignals(scSignals);
                if (scSignals.Any(s => s.Weight >= 90))
                {
                    WriteForensicLog("SUPPLY_CHAIN_CRITICAL: " +
                        string.Join(", ", scSignals.Where(s => s.Weight >= 90).Select(s => s.Type)));
                }
            }
        }
        catch (Exception ex)
        {
            WriteForensicLog("SUPPLY_CHAIN_ERROR: " + ex.Message);
        }

        // 4. Update rollback detection
        try
        {
            var updateSecurity = new AndroidUpdateSecurity(ApplicationContext!);
            var updateSignals = updateSecurity.DetectRollback();
            if (updateSignals.Count > 0)
            {
                AndroidAgentRuntime.InjectSignals(updateSignals);
                WriteForensicLog("UPDATE_ROLLBACK: " +
                    string.Join(", ", updateSignals.Select(s => s.Type)));
            }
        }
        catch (Exception ex)
        {
            WriteForensicLog("UPDATE_SECURITY_ERROR: " + ex.Message);
        }

        // 5. Start foreground monitoring service (owns signal provider + detection loop)
        var serviceIntent = new Intent(this, typeof(BehavedrForegroundService));
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
            StartForegroundService(serviceIntent);
        else
            StartService(serviceIntent);

        // 6. JobScheduler watchdog
        WorkManagerWatchdog.Schedule(ApplicationContext!);

        // 7. Battery optimization whitelist (best-effort UI prompt)
        try
        {
            var batteryManager = new BatteryOptimizationManager(ApplicationContext!);
            if (!batteryManager.IsWhitelisted)
                batteryManager.RequestWhitelist(this);
        }
        catch
        {
            // OEM may block the intent
        }

        // v0.4.5: do NOT MoveTaskToBack here. The activity now hosts a visible
        // status screen (AgentPage). Hiding the UI on launch is what made the app
        // behave like spyware and show nothing when tapped. The foreground service
        // keeps monitoring regardless of whether this screen is open.
    }

    private static void WriteForensicLog(string message)
    {
        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "logs");
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, "startup-forensic.log");
            File.AppendAllText(logPath,
                $"[{DateTime.UtcNow:O}] PID={Environment.ProcessId} {message}{Environment.NewLine}");
        }
        catch { }
    }
}
