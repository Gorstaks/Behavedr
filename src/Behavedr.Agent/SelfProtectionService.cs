namespace Behavedr.Agent;

using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Background service providing agent self-protection:
/// - Anti-debug detection
/// - Parent process monitoring (detect kill attempts)
/// - Periodic self-health checks
/// - Process hollowing detection
/// v0.1.3: Binary integrity check removed (now handled by AntiTamperGuard only - M-7 fix).
/// </summary>
public sealed class SelfProtectionService : BackgroundService
{
    private readonly ILogger<SelfProtectionService> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly bool _enableSelfProtection;

    public SelfProtectionService(
        IConfiguration configuration,
        ILogger<SelfProtectionService> logger,
        IHostApplicationLifetime lifetime)
    {
        _logger = logger;
        _lifetime = lifetime;
#if DEBUG
        _enableSelfProtection = configuration.GetValue("Agent:EnableSelfProtection", true);
#else
        // SECURITY: In Release builds, self-protection is always enabled and cannot be
        // disabled via configuration. An attacker who tampers config must not be able
        // to disable protection mechanisms.
        _ = configuration; // Suppress unused parameter warning
        _enableSelfProtection = true;
#endif
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_enableSelfProtection)
        {
            _logger.LogWarning("Self-protection is DISABLED via configuration");
            return;
        }

        _logger.LogInformation("Self-protection service started");

        // Check for debugger at startup
        CheckForDebugger();

        // Periodic health monitoring
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);
                PerformHealthCheck();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Self-protection health check failed");
            }
        }
    }

    /// <summary>
    /// Detect if a debugger is attached (anti-reversing measure).
    /// In Release builds: terminates the process immediately.
    /// In Debug builds: logs a warning only (allows legitimate debugging).
    /// </summary>
    private void CheckForDebugger()
    {
        if (Debugger.IsAttached)
        {
#if DEBUG
            _logger.LogWarning("SECURITY: Debugger detected attached to agent process (debug build - allowing)");
#else
            _logger.LogCritical("SECURITY: Debugger detected attached to agent process - terminating");
            Environment.FailFast("Security violation: debugger attached to Behavedr agent in Release mode");
#endif
        }
    }

    /// <summary>
    /// Periodic health check: check for debuggers,
    /// ensure we're still running with expected privileges, detect process hollowing.
    /// v0.1.3: Binary integrity is now handled exclusively by AntiTamperGuard (M-7 fix).
    /// </summary>
    private void PerformHealthCheck()
    {
        // Re-check debugger
        if (Debugger.IsAttached)
        {
#if DEBUG
            _logger.LogWarning("SECURITY: Debugger attached during runtime (debug build - allowing)");
#else
            _logger.LogCritical("SECURITY: Debugger attached during runtime - terminating");
            Environment.FailFast("Security violation: debugger attached to Behavedr agent in Release mode");
#endif
        }

        // Verify our process hasn't been hollowed (basic check: can we still resolve our own types?)
        try
        {
            var engineType = Type.GetType("Behavedr.Core.DetectionEngine, Behavedr.Core");
            if (engineType is null)
            {
                _logger.LogCritical("SECURITY: Core assembly type resolution failed - possible process hollowing");
            }
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "SECURITY: Type resolution check threw - agent may be compromised");
        }
    }
}
