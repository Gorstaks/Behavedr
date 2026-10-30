using Microsoft.Extensions.Logging;

namespace Behavedr.Mobile;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>();

#if DEBUG
        builder.Logging.AddDebug();
#endif

        // Create the detection engine with all platform monitors
        builder.Services.AddSingleton(_ => Core.AgentBootstrap.CreateEngine());

#if ANDROID
        // Register Android-specific platform services
        RegisterAndroidServices(builder.Services);
#endif

        return builder.Build();
    }

#if ANDROID
    private static void RegisterAndroidServices(IServiceCollection services)
    {
        // Ensure process-wide runtime exists before any service resolution
        AndroidAgentRuntime.EnsureInitialized();

        // Factory registrations that bind to the shared AndroidMonitor / injection token
        services.AddSingleton(_ =>
        {
            var ctx = Android.App.Application.Context
                ?? throw new InvalidOperationException("Android Application.Context is null");
            return new PlatformInjection.AndroidPlatformSignalProvider(
                ctx,
                AndroidAgentRuntime.AndroidMonitor,
                injectionToken: AndroidAgentRuntime.InjectionToken);
        });

        services.AddSingleton(sp =>
        {
            var ctx = Android.App.Application.Context
                ?? throw new InvalidOperationException("Android Application.Context is null");
            return new PlatformInjection.PlayIntegrityAttestor(ctx);
        });

        services.AddSingleton(_ =>
        {
            var ctx = Android.App.Application.Context
                ?? throw new InvalidOperationException("Android Application.Context is null");
            return new PlatformInjection.BatteryOptimizationManager(ctx);
        });

        services.AddSingleton(_ =>
        {
            var ctx = Android.App.Application.Context
                ?? throw new InvalidOperationException("Android Application.Context is null");
            return new PlatformInjection.DeviceOwnerManager(ctx);
        });

        services.AddSingleton(_ =>
        {
            var ctx = Android.App.Application.Context
                ?? throw new InvalidOperationException("Android Application.Context is null");
            return new PlatformInjection.SupplyChainVerifier(ctx);
        });

        services.AddSingleton(_ =>
        {
            var ctx = Android.App.Application.Context
                ?? throw new InvalidOperationException("Android Application.Context is null");
            return new PlatformInjection.AndroidUpdateSecurity(ctx);
        });
    }
#endif
}
