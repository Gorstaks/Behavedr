using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Behavedr.Mobile.PlatformInjection;

namespace Behavedr.Mobile;

/// <summary>
/// Android foreground service - runs behavioral monitoring continuously.
/// Only visible artifact: a persistent notification with the Behavedr icon.
///
/// v0.2.2: Uses <see cref="AndroidAgentRuntime"/> for a full detect->score->respond
/// pipeline (previously only called GetSignalsAsync and discarded results).
/// </summary>
[Service(
    ForegroundServiceType = ForegroundService.TypeSpecialUse,
    Exported = false)]
public class BehavedrForegroundService : Service
{
    private const int NotificationId = 1;
    private const string ChannelId = "behavedr_agent";
    private const string WakeLockTag = "behavedr:monitoring";
    private CancellationTokenSource? _cts;
    private PowerManager.WakeLock? _wakeLock;
    private AndroidPlatformSignalProvider? _signalProvider;
    private PlayIntegrityAttestor? _playIntegrity;

    public override IBinder? OnBind(Intent? intent) => null;

    public override void OnCreate()
    {
        base.OnCreate();
        CreateNotificationChannel();
        AcquireWakeLock();

        // Single shared runtime for service + platform injectors
        AndroidAgentRuntime.EnsureInitialized();
        KeystoreBridgeRegistration.Register();

        // Wire platform APIs into the same AndroidMonitor the engine uses
        try
        {
            _signalProvider = new AndroidPlatformSignalProvider(
                ApplicationContext!,
                AndroidAgentRuntime.AndroidMonitor,
                injectionToken: AndroidAgentRuntime.InjectionToken);
            _signalProvider.Start();
        }
        catch
        {
            // Provider optional if context restricted
        }

        try
        {
            _playIntegrity = new PlayIntegrityAttestor(ApplicationContext!);
            _playIntegrity.Start();
            // Drain cached integrity signals into the engine periodically via timer in attestor;
            // also pull on each cycle in MonitoringLoop.
        }
        catch
        {
            // Play Integrity may be unavailable outside Play ecosystem
        }
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        var notification = BuildNotification();
        StartForeground(NotificationId, notification);

        if (_cts is null || _cts.IsCancellationRequested)
        {
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => MonitoringLoop(_cts.Token));
        }

        return StartCommandResult.Sticky;
    }

    public override void OnDestroy()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        _signalProvider?.Dispose();
        _playIntegrity?.Dispose();
        ReleaseWakeLock();
        base.OnDestroy();
    }

    public override void OnTaskRemoved(Intent? rootIntent)
    {
        base.OnTaskRemoved(rootIntent);
        ScheduleRestart();
    }

    private async Task MonitoringLoop(CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(10);

        // Stagger first cycle slightly so providers warm up
        try { await Task.Delay(TimeSpan.FromSeconds(2), ct); }
        catch (System.OperationCanceledException) { return; }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                // Pull Play Integrity cached signals into the shared monitor
                if (_playIntegrity is not null)
                {
                    var integritySignals = _playIntegrity.GetCachedSignals();
                    if (integritySignals.Count > 0)
                        AndroidAgentRuntime.InjectSignals(integritySignals);
                }

                await AndroidAgentRuntime.RunDetectionCycleAsync(ct);
            }
            catch (System.OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                // Cycle failures must not kill the service
            }

            try
            {
                await Task.Delay(interval, ct);
            }
            catch (System.OperationCanceledException)
            {
                return;
            }
        }
    }

    private void ScheduleRestart()
    {
        try
        {
            var restartIntent = new Intent(this, typeof(BehavedrForegroundService));
            restartIntent.SetPackage(PackageName);

            var pendingIntent = PendingIntent.GetService(
                this, 1, restartIntent,
                PendingIntentFlags.OneShot | PendingIntentFlags.Immutable);

            var alarmManager = GetSystemService(AlarmService) as AlarmManager;
            if (alarmManager is not null && pendingIntent is not null)
            {
                var triggerTime = SystemClock.ElapsedRealtime() + 5000;
                alarmManager.SetExactAndAllowWhileIdle(
                    AlarmType.ElapsedRealtimeWakeup, triggerTime, pendingIntent);
            }
        }
        catch
        {
            // Best effort - some OEMs restrict AlarmManager
        }
    }

    private void AcquireWakeLock()
    {
        try
        {
            var powerManager = GetSystemService(PowerService) as PowerManager;
            _wakeLock = powerManager?.NewWakeLock(WakeLockFlags.Partial, WakeLockTag);
            _wakeLock?.Acquire();
        }
        catch { }
    }

    private void ReleaseWakeLock()
    {
        try
        {
            if (_wakeLock?.IsHeld == true)
                _wakeLock.Release();
        }
        catch { }
    }

    private void CreateNotificationChannel()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.O)
            return;

        var channel = new NotificationChannel(
            ChannelId,
            "Behavedr Agent",
            NotificationImportance.Low)
        {
            Description = "Behavioral monitoring service",
            LockscreenVisibility = NotificationVisibility.Secret,
        };

        channel.SetShowBadge(false);
        channel.EnableVibration(false);
        channel.EnableLights(false);

        var manager = GetSystemService(NotificationService) as NotificationManager;
        manager?.CreateNotificationChannel(channel);
    }

    private Notification BuildNotification()
    {
        var builder = new Notification.Builder(this, ChannelId)
            .SetContentTitle("Behavedr")
            .SetContentText("Monitoring active")
            .SetSmallIcon(Resource.Mipmap.appicon)
            .SetOngoing(true)
            .SetCategory(Notification.CategoryService)
            .SetVisibility(NotificationVisibility.Secret);

        return builder.Build()!;
    }
}
