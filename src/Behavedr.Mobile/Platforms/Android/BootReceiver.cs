using Android.App;
using Android.Content;
using Android.OS;

namespace Behavedr.Mobile;

/// <summary>
/// Boot receiver - automatically starts the Behavedr foreground service on device boot.
/// Ensures continuous protection without requiring the user to manually open the app.
///
/// Also handles MY_PACKAGE_REPLACED to restart after app update.
/// </summary>
[BroadcastReceiver(
    Enabled = true,
    Exported = true,
    DirectBootAware = true)]
[IntentFilter(new[]
{
    Intent.ActionBootCompleted,
    Intent.ActionLockedBootCompleted,
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.QUICKBOOT_POWERON",  // HTC/some OEMs
})]
public class BootReceiver : BroadcastReceiver
{
    public override void OnReceive(Context? context, Intent? intent)
    {
        if (context is null || intent is null) return;

        var action = intent.Action;
        if (action is Intent.ActionBootCompleted or
            Intent.ActionLockedBootCompleted or
            "android.intent.action.MY_PACKAGE_REPLACED" or
            "android.intent.action.QUICKBOOT_POWERON")
        {
            StartBehavedrService(context);
        }
    }

    private static void StartBehavedrService(Context context)
    {
        try
        {
            var serviceIntent = new Intent(context, typeof(BehavedrForegroundService));
            serviceIntent.SetPackage(context.PackageName);

            if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
            {
                context.StartForegroundService(serviceIntent);
            }
            else
            {
                context.StartService(serviceIntent);
            }
        }
        catch
        {
            // Best effort - some OEMs restrict background service starts
        }
    }
}
