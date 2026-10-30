namespace Behavedr.Mobile;

using Behavedr.Core;

/// <summary>
/// Invisible page - MAUI requires at least one ContentPage to host.
/// This renders nothing visible; the actual work runs in the background service.
/// On Android, the Activity finishes itself and the foreground service takes over.
/// </summary>
public class AgentPage : ContentPage
{
    public AgentPage()
    {
        // No visual content - zero UI
        BackgroundColor = Colors.Black;
        Content = null;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();

        // Start the detection engine in background
        var engine = AgentBootstrap.CreateEngine();
        _ = Task.Run(() => RunMonitoringLoop(engine));

#if ANDROID
        // On Android, minimize immediately so user sees nothing
        Platform.CurrentActivity?.MoveTaskToBack(true);
#endif
    }

    private static async Task RunMonitoringLoop(DetectionEngine engine)
    {
        // Continuous monitoring loop - mirrors desktop agent behavior
        using var cts = new CancellationTokenSource();
        while (!cts.Token.IsCancellationRequested)
        {
            foreach (var monitor in engine.RegisteredMonitors)
            {
                try
                {
                    await monitor.GetSignalsAsync(cts.Token);
                }
                catch (System.OperationCanceledException)
                {
                    return;
                }
                catch
                {
                    // Swallow individual monitor failures - agent must stay alive
                }
            }

            await Task.Delay(TimeSpan.FromSeconds(30), cts.Token);
        }
    }
}
