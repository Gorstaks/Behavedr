namespace Behavedr.Agent;

using Behavedr.Core;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Behavedr.Core.Security;
using Behavedr.Core.Update;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Pre-flight checks before monitors are trusted (pattern from Sentinel StartupSelfTest).
/// Validates crypto, config integrity, monitor registration, quarantine path, and key protection.
/// </summary>
public sealed class StartupSelfTest : IHostedService
{
    private readonly DetectionEngine _engine;
    private readonly ResponseEngine _responseEngine;
    private readonly ILogger<StartupSelfTest> _logger;

    public StartupSelfTest(
        DetectionEngine engine,
        ResponseEngine responseEngine,
        ILogger<StartupSelfTest> logger)
    {
        _engine = engine;
        _responseEngine = responseEngine;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[StartupSelfTest] Running pre-flight checks...");
        int passed = 0, failed = 0;

        // 0. If an update was staged last run, evaluate health and auto-rollback on failure.
        // Runs before other checks so a broken update can restore .previous binaries.
        try
        {
            var rolledBack = AutoUpdater.TryHealthCheckRollback(
                () => RunCriticalCryptoHealth(),
                _logger);
            if (rolledBack)
            {
                failed++;
                _logger.LogCritical(
                    "[StartupSelfTest] Auto-rollback executed after failed post-update health check. " +
                    "Restart the agent to load restored binaries.");
            }
            else
            {
                passed++;
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Post-update rollback check FAILED");
        }

        // 1. SecureEnvelope seal/unseal round-trip
        try
        {
            var payload = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            var sealedData = SecureEnvelope.Seal(payload, "selftest");
            var opened = SecureEnvelope.Unseal(sealedData, "selftest");
            if (opened is not null && opened.AsSpan().SequenceEqual(payload))
                passed++;
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] SecureEnvelope round-trip FAILED");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] SecureEnvelope check FAILED");
        }

        // 2. Machine key available
        try
        {
            var key = KeyProtection.GetMachineKey();
            if (key is { Length: 32 }) passed++;
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] Machine key length invalid");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Machine key check FAILED");
        }

        // 3. Monitors registered for this platform
        try
        {
            var count = _engine.RegisteredMonitors.Count;
            if (count > 0)
            {
                passed++;
                _logger.LogInformation("[StartupSelfTest] {Count} monitors registered ({Platform})",
                    count, PlatformMonitors.CurrentPlatformSummary());
            }
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] No monitors registered");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Monitor count check FAILED");
        }

        // 4. At least one response action registered
        try
        {
            if (_responseEngine.RegisteredActions.Count > 0) passed++;
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] No response actions registered");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Response actions check FAILED");
        }

        // 5. Quarantine + buffer directories writable
        try
        {
            foreach (var dir in new[] { "quarantine", "buffer", "logs" })
            {
                Directory.CreateDirectory(dir);
                var probe = Path.Combine(dir, $".selftest-{Guid.NewGuid():N}");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
            }
            passed++;
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Directory writability FAILED");
        }

        // 6. Update signature verifier has a production key baked in
        try
        {
            if (UpdateSignatureVerifier.IsProductionKeyConfigured())
            {
                passed++;
            }
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] Update signing public key is PLACEHOLDER (dev mode)");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Update key check FAILED");
        }

        // 7. Policy signing path is configured (may still share update key until rotation)
        try
        {
            if (PolicySignatureVerifier.IsProductionKeyConfigured())
            {
                passed++;
                if (PolicySignatureVerifier.IsUsingSharedUpdateKey())
                {
                    _logger.LogWarning(
                        "[StartupSelfTest] Policy and update signing keys are STILL shared - " +
                        "rotate to distinct keys (see docs/SUPPLY_CHAIN.md)");
                }
                else
                {
                    _logger.LogInformation(
                        "[StartupSelfTest] Policy signing key is distinct from update key (blast-radius isolation)");
                }
            }
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] Policy signing public key is PLACEHOLDER (dev mode)");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Policy key check FAILED");
        }

        // Platform depth posture (informational - does not fail boot)
        try
        {
            ReportPlatformDepth();
            passed++;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[StartupSelfTest] Platform depth report skipped");
        }

        if (failed == 0)
            _logger.LogInformation("[StartupSelfTest] All {Passed} checks PASSED", passed);
        else
            _logger.LogWarning("[StartupSelfTest] {Passed} passed, {Failed} FAILED - agent continues with degraded confidence",
                passed, failed);

        return Task.CompletedTask;
    }

    private void ReportPlatformDepth()
    {
        var names = _engine.RegisteredMonitors.Select(m => m.PlatformName).ToHashSet(StringComparer.Ordinal);
        // Registration != field-active. Probe suite/ES active flags when present.
        var ebpfRegistered = names.Contains("LinuxEbpfExec") || names.Contains("LinuxEbpfFile") || names.Contains("LinuxEbpfNet");
        var ebpfActive = false;
        if (OperatingSystem.IsLinux() && ebpfRegistered)
        {
            try { ebpfActive = Behavedr.Core.Monitors.LinuxEbpfSuite.Shared().IsActive; }
            catch { /* ignore */ }
        }
        var esRegistered = names.Contains("MacOSEndpointSecurity");
        var esActive = false;
        if (OperatingSystem.IsMacOS() && esRegistered)
        {
            try
            {
                var es = _engine.RegisteredMonitors.OfType<Behavedr.Core.Monitors.MacOSEndpointSecurityMonitor>().FirstOrDefault();
                esActive = es?.IsActive == true;
            }
            catch { /* ignore */ }
        }

        _logger.LogInformation(
            "[StartupSelfTest] Platform depth: monitors={Count} ebpfReg={EbpfReg} ebpfActive={EbpfAct} esReg={EsReg} esActive={EsAct} hasFanotify={Fan} landlockEnv={Ll} esAuthEnv={Auth}",
            names.Count,
            ebpfRegistered,
            ebpfActive,
            esRegistered,
            esActive,
            names.Contains("LinuxFanotify"),
            Environment.GetEnvironmentVariable("BEHAVEDR_LANDLOCK") == "1",
            Environment.GetEnvironmentVariable("BEHAVEDR_ES_AUTH") == "1");
    }

    /// <summary>
    /// Minimal crypto health used for post-update rollback decisions.
    /// Does not depend on monitors (which may not be registered yet when this runs early).
    /// </summary>
    private static bool RunCriticalCryptoHealth()
    {
        try
        {
            var payload = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
            var sealedData = SecureEnvelope.Seal(payload, "post-update-health");
            var opened = SecureEnvelope.Unseal(sealedData, "post-update-health");
            if (opened is null || !opened.AsSpan().SequenceEqual(payload))
                return false;

            var key = KeyProtection.GetMachineKey();
            if (key is not { Length: 32 })
                return false;

            if (!UpdateSignatureVerifier.IsProductionKeyConfigured())
                return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
