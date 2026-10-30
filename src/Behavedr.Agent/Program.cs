using Behavedr.Agent;
using Behavedr.Core;
using Behavedr.Core.Communication;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Behavedr.Core.Security;
using Behavedr.Core.Update;
using Behavedr.Core.Telemetry;
// PolicyApplicator is in Communication
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Behavedr Agent v{Version} starting on {Platform}",
        typeof(DetectionEngine).Assembly.GetName().Version?.ToString(3) ?? "0.1.4",
        PlatformMonitors.CurrentPlatformSummary());

    var builder = Host.CreateApplicationBuilder(args);

    // SECURITY: Verify config file integrity before using it
    var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
    var integrityResult = ConfigIntegrity.VerifyConfigFile(configPath);
    switch (integrityResult)
    {
        case ConfigIntegrityResult.Tampered:
            Log.Fatal("SECURITY: Configuration file integrity check FAILED - agent refusing to start. " +
                      "Re-seal config with a trusted copy or reinstall the agent.");
            return 78; // EX_CONFIG
        case ConfigIntegrityResult.NotSealed:
            Log.Warning("Config file not yet sealed - validating before sealing (first run)");
            // SECURITY: Validate config values are within acceptable bounds before sealing.
            // Prevents an attacker from pre-placing a malicious config that gets sealed as trusted.
            if (!ConfigIntegrity.ValidateConfigBeforeSealing(configPath))
            {
                Log.Fatal("SECURITY: Configuration values are outside acceptable bounds - refusing to seal. " +
                          "Verify appsettings.json contains valid values and restart.");
                return 78; // EX_CONFIG
            }
            ConfigIntegrity.SealConfigFile(configPath);
            break;
        case ConfigIntegrityResult.Valid:
            Log.Information("Config file integrity verified");
            break;
    }

    // Serilog replaces the default Microsoft logger
    builder.Services.AddSerilog((services, cfg) => cfg
        .WriteTo.Console()
        .WriteTo.File("logs/behavedr-.log", rollingInterval: Serilog.RollingInterval.Day,
            retainedFileCountLimit: 14, fileSizeLimitBytes: 10_485_760, rollOnFileSizeLimit: true)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext());

    // Scoring config from appsettings
    var scoringConfig = builder.Configuration
        .GetSection("Scoring")
        .Get<ScoringConfig>() ?? ScoringConfig.Default;

    if (!scoringConfig.IsValid())
    {
        Log.Warning("Invalid scoring config detected, falling back to defaults");
        scoringConfig = ScoringConfig.Default;
    }

    builder.Services.AddSingleton(scoringConfig);
    builder.Services.AddSingleton<ScoringEngine>();
    builder.Services.AddSingleton<BehavioralCorrelationEngine>();
    builder.Services.AddSingleton<DetectionEngine>();
    builder.Services.AddSingleton<LivePolicyState>();
    builder.Services.AddSingleton<PolicyApplicator>();

    // v0.1.3: Response engine with process kill and file quarantine (C-1 fix)
    var responsePolicy = builder.Configuration
        .GetSection("Response")
        .Get<ResponsePolicy>() ?? ResponsePolicy.Default;
    if (!responsePolicy.IsValid())
    {
        Log.Warning("Invalid response policy detected, falling back to defaults");
        responsePolicy = ResponsePolicy.Default;
    }
    builder.Services.AddSingleton(responsePolicy);

    // v0.2.9: optional platform depth flags
    var platformFeatures = builder.Configuration
        .GetSection("Platform")
        .Get<PlatformFeatures>() ?? PlatformFeatures.Default;
    platformFeatures = PlatformFeatures.FromEnvironment(platformFeatures);
    builder.Services.AddSingleton(platformFeatures);
    if (platformFeatures.EnableEndpointSecurityAuth)
        Environment.SetEnvironmentVariable("BEHAVEDR_ES_AUTH", "1");
    if (platformFeatures.EnableFanotifyPerm)
        Environment.SetEnvironmentVariable("BEHAVEDR_FANOTIFY_PERM", "1");
    if (platformFeatures.RequirePlayIntegrity)
        Environment.SetEnvironmentVariable("BEHAVEDR_REQUIRE_PLAY_INTEGRITY", "1");

    builder.Services.AddSingleton<ResponseAuditWriter>();
    builder.Services.AddSingleton<BehavedrMetrics>();
    builder.Services.AddSingleton<ResponseEngine>(sp =>
        new ResponseEngine(
            sp.GetRequiredService<ResponsePolicy>(),
            sp.GetService<ILogger<ResponseEngine>>(),
            sp.GetRequiredService<ResponseAuditWriter>(),
            sp.GetRequiredService<BehavedrMetrics>()));
    builder.Services.AddSingleton<ProcessKillAction>();
    builder.Services.AddSingleton<FileQuarantineAction>();
    builder.Services.AddSingleton<IsolationResponseEngine>();

    // v0.2.6: Windows userland network isolation (advfirewall)
    if (OperatingSystem.IsWindows())
    {
        builder.Services.AddSingleton<WindowsNetworkIsolation>();
    }

    // v0.2.0: Linux nftables-based network isolation
    if (OperatingSystem.IsLinux())
    {
        builder.Services.AddSingleton<LinuxNetworkIsolation>();
    }

    // v0.2.3: macOS network isolation (route blackhole / pf table)
    if (OperatingSystem.IsMacOS())
    {
        builder.Services.AddSingleton<MacOSNetworkIsolation>();
    }

    // v0.2.0: Android response engine (kill/isolate/force-stop)
    if (OperatingSystem.IsAndroid())
    {
        builder.Services.AddSingleton<AndroidResponseEngine>();
    }

    builder.Services.AddSingleton<ChainTracer>(sp =>
        new ChainTracer(PlatformMonitors.SharedAncestryCache,
            new QuarantineServiceAdapter(sp.GetRequiredService<FileQuarantineAction>()),
            sp.GetRequiredService<ResponsePolicy>(),
            sp.GetService<ILogger<ChainTracer>>()));

    // v0.1.3: Communication layer - agent-to-server reporting (C-3 fix)
    var commConfig = builder.Configuration
        .GetSection("Communication")
        .Get<CommunicationConfig>() ?? CommunicationConfig.Default;
    builder.Services.AddSingleton(commConfig);
    builder.Services.AddSingleton<IBehavedrClient>(sp =>
        new GrpcBehavedrClient(commConfig, sp.GetService<ILogger<GrpcBehavedrClient>>()));
    builder.Services.AddSingleton<OfflineBuffer>();

    // v0.1.3: Auto-updater (H-6 fix)
    builder.Services.AddSingleton<AutoUpdater>();

    // Agent self-protection service
    builder.Services.AddHostedService<SelfProtectionService>();

    // v0.2.2: Startup self-test (Sentinel pattern)
    builder.Services.AddHostedService<StartupSelfTest>();

    // Agent watchdog service (mutual monitoring, last-gasp logging)
    builder.Services.AddHostedService<AgentWatchdog>();

    // Unix watchdog (suspension detection, forensic logging, /proc verification)
    if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
    {
        builder.Services.AddHostedService<UnixWatchdog>();
    }

    // Core monitoring background service
    builder.Services.AddHostedService<MonitoringService>();

    // v0.1.3: Communication background service
    builder.Services.AddHostedService<CommunicationService>();

    // v0.1.3: Auto-update check background service
    builder.Services.AddHostedService<UpdateCheckService>();

    // Windows Service / systemd integration
    if (OperatingSystem.IsWindows())
        builder.Services.AddWindowsService(options => options.ServiceName = "Behavedr");
    // Note: UseSystemd() requires the IHostBuilder API. With HostApplicationBuilder,
    // systemd notification is handled via Microsoft.Extensions.Hosting.Systemd automatically
    // when the NOTIFY_SOCKET env var is set by systemd.

    var host = builder.Build();

    // v0.3.0: security telemetry -> OpenTelemetry metrics
    var metrics = host.Services.GetRequiredService<BehavedrMetrics>();
    SecurityTelemetry.OnSignatureFailure = metrics.RecordSignatureFailure;
    SecurityTelemetry.OnIsolationAction = metrics.RecordIsolationAction;
    SecurityTelemetry.OnPlatformSoftFail = metrics.RecordPlatformSoftFail;

    // v0.2.2: Register platform monitors before hosted services start (was deferred to
    // MonitoringService, so StartupSelfTest / early cycles could see zero monitors).
    var detectionEngine = host.Services.GetRequiredService<DetectionEngine>();
    if (detectionEngine.RegisteredMonitors.Count == 0)
    {
        foreach (var monitor in PlatformMonitors.Supported())
        {
            detectionEngine.RegisterMonitor(monitor);
            metrics.RecordMonitorRegistered();
        }
    }

    // v0.2.9: optional Landlock write sandbox (after monitors registered; read stays open)
    var features = host.Services.GetRequiredService<PlatformFeatures>();
    if (features.EnableLandlock && OperatingSystem.IsLinux())
    {
        if (!LinuxLandlock.TryApplyDefaultProfile())
        {
            metrics.RecordPlatformSoftFail("landlock");
            Log.Warning("Landlock requested but not applied (kernel/caps)");
        }
    }

    // v0.1.3: Register response actions after build (C-1 fix)
    var responseEngine = host.Services.GetRequiredService<ResponseEngine>();
    responseEngine.RegisterAction(host.Services.GetRequiredService<ProcessKillAction>());
    responseEngine.RegisterAction(host.Services.GetRequiredService<FileQuarantineAction>());
    // v0.2.2 fix: IsolationResponseEngine was DI-registered but never wired into ResponseEngine
    responseEngine.RegisterAction(host.Services.GetRequiredService<IsolationResponseEngine>());

    // v0.2.6: Windows network isolation
    if (OperatingSystem.IsWindows())
    {
        responseEngine.RegisterAction(host.Services.GetRequiredService<WindowsNetworkIsolation>());
    }

    // v0.2.0: Register Linux network isolation response action
    if (OperatingSystem.IsLinux())
    {
        responseEngine.RegisterAction(host.Services.GetRequiredService<LinuxNetworkIsolation>());
    }

    // v0.2.3: Register macOS network isolation
    if (OperatingSystem.IsMacOS())
    {
        responseEngine.RegisterAction(host.Services.GetRequiredService<MacOSNetworkIsolation>());
    }

    // v0.2.0: Register Android response engine
    if (OperatingSystem.IsAndroid())
    {
        responseEngine.RegisterAction(host.Services.GetRequiredService<AndroidResponseEngine>());
    }

    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Behavedr Agent terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

return 0;
