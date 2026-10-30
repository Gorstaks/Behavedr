namespace Behavedr.Mobile;

/// <summary>
/// Zero-visuals application shell. No user-facing UI - just icon and background service.
/// </summary>
public partial class App : Application
{
    public App()
    {
        InitializeComponent();
    }

    protected override Window CreateWindow(IActivationState? activationState) =>
        new Window(new AgentPage());
}
