using Android.App;
using Android.Runtime;
using Behavedr.Mobile.PlatformInjection;

namespace Behavedr.Mobile;

/// <summary>
/// Application entry point for Android.
/// Registers critical security components at the earliest possible lifecycle stage.
///
/// The Application.OnCreate runs before any Activity or Service, making it
/// the ideal place for:
/// - Keystore bridge registration (needed before any key access)
/// - Supply chain verification (detect compromise before doing anything else)
/// - WorkManager scheduling (persistence even if Activity never starts)
/// </summary>
[Application]
public class MainApplication : MauiApplication
{
    public MainApplication(IntPtr handle, JniHandleOwnership ownership)
        : base(handle, ownership)
    {
    }

    public override void OnCreate()
    {
        base.OnCreate();

        // Register Keystore bridge at application level (earliest possible)
        // This ensures hardware-backed keys are available for all components
        KeystoreBridgeRegistration.Register();

        // Shared detection/response runtime before any Activity/Service work
        AndroidAgentRuntime.EnsureInitialized();

        // Schedule watchdog at application level (survives if Activity is never started)
        WorkManagerWatchdog.Schedule(this);
    }

    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}
