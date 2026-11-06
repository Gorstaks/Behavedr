namespace Behavedr.Mobile;

/// <summary>
/// Status screen. Shows the user that Behavedr is installed, what it does, and
/// whether monitoring is currently active. The heavy lifting still runs in the
/// Android foreground service; this page only reflects and explains that state.
///
/// Prior to v0.4.5 this page was deliberately invisible (Content = null) and the
/// activity hid itself on launch. That made a legitimate EDR agent behave exactly
/// like spyware: no icon identity, no UI, silent background execution. This screen
/// restores a visible, honest front end.
/// </summary>
public class AgentPage : ContentPage
{
    private readonly Label _statusLabel;
    private readonly Label _detailLabel;
    private readonly BoxView _statusDot;
    private IDispatcherTimer? _refreshTimer;

    public AgentPage()
    {
        Title = "Behavedr";
        BackgroundColor = Color.FromArgb("#1B2A4A");
        Padding = new Thickness(24, 48, 24, 24);

        var heading = new Label
        {
            Text = "Behavedr",
            FontSize = 32,
            FontAttributes = FontAttributes.Bold,
            TextColor = Colors.White,
            HorizontalOptions = LayoutOptions.Center,
        };

        var subtitle = new Label
        {
            Text = "Behavioral endpoint protection",
            FontSize = 15,
            TextColor = Color.FromArgb("#9FB3D1"),
            HorizontalOptions = LayoutOptions.Center,
            Margin = new Thickness(0, 0, 0, 24),
        };

        _statusDot = new BoxView
        {
            WidthRequest = 14,
            HeightRequest = 14,
            CornerRadius = 7,
            Color = Color.FromArgb("#6B7A99"),
            VerticalOptions = LayoutOptions.Center,
        };

        _statusLabel = new Label
        {
            Text = "Starting...",
            FontSize = 18,
            FontAttributes = FontAttributes.Bold,
            TextColor = Colors.White,
            VerticalOptions = LayoutOptions.Center,
            Margin = new Thickness(10, 0, 0, 0),
        };

        var statusRow = new HorizontalStackLayout
        {
            HorizontalOptions = LayoutOptions.Center,
            Children = { _statusDot, _statusLabel },
            Margin = new Thickness(0, 0, 0, 16),
        };

        _detailLabel = new Label
        {
            Text = "",
            FontSize = 14,
            TextColor = Color.FromArgb("#C7D4E8"),
            HorizontalTextAlignment = TextAlignment.Center,
            Margin = new Thickness(0, 0, 0, 24),
        };

        var explain = new Label
        {
            Text = "Behavedr runs continuously in the background and watches for "
                 + "malicious behavior on this device. You can close this screen; "
                 + "monitoring keeps running. A persistent notification confirms it "
                 + "is active.",
            FontSize = 13,
            TextColor = Color.FromArgb("#9FB3D1"),
            HorizontalTextAlignment = TextAlignment.Center,
        };

        Content = new ScrollView
        {
            Content = new VerticalStackLayout
            {
                Children = { heading, subtitle, statusRow, _detailLabel, explain },
            },
        };
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();

        _refreshTimer = Dispatcher.CreateTimer();
        _refreshTimer.Interval = TimeSpan.FromSeconds(2);
        _refreshTimer.Tick += (_, _) => RefreshStatus();
        _refreshTimer.Start();

        RefreshStatus();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _refreshTimer?.Stop();
        _refreshTimer = null;
    }

    private void RefreshStatus()
    {
#if ANDROID
        var status = AndroidAgentRuntime.GetStatus();

        if (!status.Initialized)
        {
            SetState("#6B7A99", "Initializing", "Preparing monitoring engine...");
            return;
        }

        var active = status.CyclesRun > 0;
        if (active)
        {
            var age = status.LastCycleUtc == DateTime.MinValue
                ? "just now"
                : $"{(int)(DateTime.UtcNow - status.LastCycleUtc).TotalSeconds}s ago";

            SetState(
                "#3DDC84",
                "Protected",
                $"{status.MonitorCount} monitors active\n"
                + $"Last scan: {age}\n"
                + $"Scans completed: {status.CyclesRun}");
        }
        else
        {
            SetState(
                "#E8B04B",
                "Warming up",
                $"{status.MonitorCount} monitors loaded\nWaiting for first scan...");
        }
#else
        SetState("#6B7A99", "Unavailable", "Android runtime only.");
#endif
    }

    private void SetState(string dotColor, string status, string detail)
    {
        _statusDot.Color = Color.FromArgb(dotColor);
        _statusLabel.Text = status;
        _detailLabel.Text = detail;
    }
}
