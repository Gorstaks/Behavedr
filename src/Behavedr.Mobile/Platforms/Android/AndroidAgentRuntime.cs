#if ANDROID
using Android.Content;
using Behavedr.Core;
using Behavedr.Core.Monitors;
using Behavedr.Core.Models;
using Behavedr.Core.Response;
using Behavedr.Mobile.PlatformInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text.RegularExpressions;

namespace Behavedr.Mobile;

/// <summary>
/// Process-wide Android agent runtime. Ensures the foreground service, MainActivity,
/// platform signal providers, and response engine share one DetectionEngine and one
/// authenticated AndroidMonitor injection token.
///
/// v0.2.2 fix: previously MainActivity built an AndroidPlatformSignalProvider with
/// androidMonitor=null (signals never injected), and BehavedrForegroundService only
/// called GetSignalsAsync without scoring/response - a silent production sabotage of
/// the entire Android EDR pipeline.
/// </summary>
public static class AndroidAgentRuntime
{
    private static readonly object Gate = new();
    private static bool _initialized;
    private static DetectionEngine? _engine;
    private static ResponseEngine? _responseEngine;
    private static AndroidMonitor? _androidMonitor;
    private static string? _injectionToken;
    private static ILogger _logger = NullLogger.Instance;

    public static bool IsInitialized
    {
        get { lock (Gate) return _initialized; }
    }

    public static DetectionEngine Engine
    {
        get
        {
            EnsureInitialized();
            return _engine!;
        }
    }

    public static ResponseEngine ResponseEngine
    {
        get
        {
            EnsureInitialized();
            return _responseEngine!;
        }
    }

    public static AndroidMonitor? AndroidMonitor
    {
        get
        {
            EnsureInitialized();
            return _androidMonitor;
        }
    }

    public static string InjectionToken
    {
        get
        {
            EnsureInitialized();
            return _injectionToken!;
        }
    }

    /// <summary>
    /// Idempotent initialization. Safe to call from Application, Activity, or Service.
    /// </summary>
    public static void EnsureInitialized(ILogger? logger = null)
    {
        lock (Gate)
        {
            if (_initialized) return;

            if (logger is not null)
                _logger = logger;

            _engine = AgentBootstrap.CreateEngine();
            _androidMonitor = _engine.RegisteredMonitors.OfType<AndroidMonitor>().FirstOrDefault();

            _injectionToken = Guid.NewGuid().ToString("N");
            _androidMonitor?.SetInjectionToken(_injectionToken);

            // Production mobile default: AlertOnly unless device is Device Owner (can be upgraded later).
            // Pipeline still scores and logs; Active mode can be enabled via future config.
            var policy = new ResponsePolicy
            {
                Mode = ResponseMode.Active,
                AlertThreshold = 50.0,
                ResponseThreshold = 75.0,
                EnableQuarantine = false,
                EnableProcessKill = true,
            };

            _responseEngine = new ResponseEngine(policy);
            _responseEngine.RegisterAction(new AndroidResponseEngine());

            // v0.2.6: VPN auto-isolate + Device Owner disable on high score (non-root path)
            WirePlatformResponseHook();

            _initialized = true;
            _logger.LogInformation(
                "[AndroidAgentRuntime] Initialized: {MonitorCount} monitors, injection={HasInjection}, response=Active, platformHook=on",
                _engine.RegisteredMonitors.Count,
                _androidMonitor is not null);
        }
    }

    private static void WirePlatformResponseHook()
    {
        AndroidResponseEngine.PlatformResponseHook = async (uid, packageOrProcess, result, ct) =>
        {
            await Task.Yield();
            var parts = new List<string>();

            try
            {
                // Block domains mentioned in signals (DGA / C2 style)
                var domainRx = new Regex(
                    @"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)\b",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                var blocked = 0;
                foreach (var signal in result.Signals)
                {
                    foreach (Match m in domainRx.Matches(signal.Type))
                    {
                        var d = m.Value.ToLowerInvariant();
                        if (d is "localhost" or "localdomain") continue;
                        if (d.EndsWith(".local", StringComparison.Ordinal)) continue;
                        BehavedrVpnService.BlockDomain(d);
                        blocked++;
                        if (blocked >= 16) break;
                    }
                    if (blocked >= 16) break;
                }
                if (blocked > 0)
                    parts.Add($"VPN blocked {blocked} domain(s)");

                if (uid > 0 && uid != 0)
                {
                    BehavedrVpnService.IsolateUid(uid);
                    parts.Add($"VPN isolated UID {uid}");
                }

                // Device Owner: disable the package when enrolled
                var ctx = Android.App.Application.Context;
                if (ctx is not null)
                {
                    var dom = new DeviceOwnerManager(ctx, _logger);
                    if (dom.IsDeviceOwner || dom.IsProfileOwner)
                    {
                        var pkg = GuessPackageName(packageOrProcess);
                        if (!string.IsNullOrEmpty(pkg) &&
                            !string.Equals(pkg, ctx.PackageName, StringComparison.OrdinalIgnoreCase))
                        {
                            var disable = dom.DisableApplication(pkg);
                            if (disable.Success)
                                parts.Add($"DO disabled {pkg}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AndroidAgentRuntime] Platform response hook error");
            }

            return parts.Count > 0 ? string.Join("; ", parts) : null;
        };
    }

    private static string GuessPackageName(string processOrPackage)
    {
        // Android process names are often package or package:suffix
        if (string.IsNullOrWhiteSpace(processOrPackage))
            return "";
        var p = processOrPackage.Trim();
        var colon = p.IndexOf(':');
        if (colon > 0) p = p[..colon];
        return p;
    }

    /// <summary>
    /// Inject platform signals into the shared AndroidMonitor (authenticated).
    /// No-op if runtime not ready or monitor missing.
    /// </summary>
    public static void InjectSignals(IEnumerable<Signal> signals)
    {
        EnsureInitialized();
        if (_androidMonitor is null || _injectionToken is null) return;

        var list = signals as IList<Signal> ?? signals.ToList();
        if (list.Count == 0) return;

        try
        {
            _androidMonitor.InjectPlatformSignals(list, _injectionToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[AndroidAgentRuntime] Signal injection failed");
        }
    }

    /// <summary>
    /// Full detection cycle: collect -> score -> respond. Used by the foreground service.
    /// </summary>
    public static async Task<DetectionResult> RunDetectionCycleAsync(CancellationToken ct = default)
    {
        EnsureInitialized();

        var evt = DetectionEvent.Create(
            processId: Environment.ProcessId.ToString(),
            processName: "behavedr-android",
            behaviorType: "periodic_scan",
            source: "Android",
            isUserTargeted: false);

        var result = await _engine!.ProcessEventAsync(evt, ct);
        var responses = await _responseEngine!.RespondAsync(result, ct);

        // Attribute by PID and re-score that PID only (never copy the machine-wide cycle score).
        if (result.Signals.Count > 0)
        {
            foreach (var (pid, processName, signals) in SignalAttribution.GroupByPid(result.Signals))
            {
                if (ct.IsCancellationRequested) break;

                var targetedEvt = DetectionEvent.Create(
                    processId: pid.ToString(),
                    processName: processName,
                    behaviorType: "behavioral_detection",
                    source: "signal_attribution",
                    isUserTargeted: false);

                var targetedResult = _engine.ScoreAttributed(targetedEvt, signals);
                await _responseEngine.RespondAsync(targetedResult, ct);
            }
        }

        if (result.Signals.Count > 0)
        {
            _logger.LogInformation(
                "[AndroidAgentRuntime] Cycle: {Signals} signals, score={Score:F1}, kill={Kill}, responses={Resp}",
                result.Signals.Count, result.Score, result.PresidentKill, responses.Count);
        }

        return result;
    }
}
#endif
