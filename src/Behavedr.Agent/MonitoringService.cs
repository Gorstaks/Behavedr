namespace Behavedr.Agent;

using System.Diagnostics;
using Behavedr.Core;
using Behavedr.Core.Communication;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Behavedr.Core.Telemetry;
// LivePolicyState in Platform
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Background service that periodically collects behavioral signals and runs detection.
/// Each cycle scores every attributed PID on its own. The cycle total is never scored, reported,
/// or used for response, because it mixes unrelated processes and the agent's own activity.
/// v0.1.3: Now wires ResponseEngine and Communication (C-1, H-5 fix).
/// </summary>
public sealed class MonitoringService : BackgroundService
{
    private readonly DetectionEngine _engine;
    private readonly ResponseEngine _responseEngine;
    private readonly IBehavedrClient _client;
    private readonly OfflineBuffer _offlineBuffer;
    private readonly CommunicationConfig _commConfig;
    private readonly BehavedrMetrics _metrics;
    private readonly LivePolicyState _livePolicy;
    private readonly ILogger<MonitoringService> _logger;
    private readonly int _defaultIntervalSeconds;

    public MonitoringService(
        DetectionEngine engine,
        ResponseEngine responseEngine,
        IBehavedrClient client,
        OfflineBuffer offlineBuffer,
        CommunicationConfig commConfig,
        BehavedrMetrics metrics,
        LivePolicyState livePolicy,
        IConfiguration configuration,
        ILogger<MonitoringService> logger)
    {
        _engine = engine;
        _responseEngine = responseEngine;
        _client = client;
        _offlineBuffer = offlineBuffer;
        _commConfig = commConfig;
        _metrics = metrics;
        _livePolicy = livePolicy;
        _logger = logger;

        _defaultIntervalSeconds = Math.Clamp(
            configuration.GetValue("Agent:MonitoringIntervalSeconds", 5), 1, 60);
        if (_livePolicy.MonitoringIntervalSeconds == 5 && _defaultIntervalSeconds != 5)
            _livePolicy.MonitoringIntervalSeconds = _defaultIntervalSeconds;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Monitoring service started (interval: {Interval}s, live-policy aware)",
            _livePolicy.MonitoringIntervalSeconds);

        // Register platform monitors (only if not already registered by DI/bootstrap)
        if (_engine.RegisteredMonitors.Count == 0)
        {
            foreach (var monitor in PlatformMonitors.Supported())
            {
                _engine.RegisterMonitor(monitor);
            }
        }

        _logger.LogInformation("Registered {Count} platform monitor(s): {Names}",
            _engine.RegisteredMonitors.Count,
            string.Join(", ", _engine.RegisteredMonitors.Select(m => m.PlatformName)));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var delay = TimeSpan.FromSeconds(_livePolicy.MonitoringIntervalSeconds);
                await Task.Delay(delay, stoppingToken);
                await RunDetectionCycleAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Detection cycle failed, will retry next interval");
            }
        }

        _logger.LogInformation("Monitoring service stopping");
    }

    private async Task RunDetectionCycleAsync(CancellationToken ct)
    {
        // Update watchdog heartbeat
        AgentWatchdog.LastMonitoringHeartbeat = DateTime.UtcNow;
        var sw = Stopwatch.StartNew();

        var signals = await _engine.CollectCycleSignalsAsync(ct);
        _metrics.RecordSignalsCollected(signals.Count);
        _metrics.RecordSignalsSuppressed(_engine.LastSuppressedCount);
        foreach (var signal in signals)
            _metrics.RecordSignalFamily(SignalFamily(signal.Type));

        foreach (var (pid, processName, pidSignals) in SignalAttribution.GroupByPid(signals))
        {
            if (ct.IsCancellationRequested) break;

            // Score this process alone. Its PID and name come from its own signals.
            var targetedEvt = DetectionEvent.Create(
                processId: pid.ToString(),
                processName: processName,
                behaviorType: "behavioral_detection",
                source: "signal_attribution",
                isUserTargeted: false);

            var result = _engine.ScoreAttributed(targetedEvt, pidSignals);
            _metrics.RecordScore(result.Score);

            bool alert = result.Score > _responseEngine.Policy.AlertThreshold;
            if (alert)
            {
                _metrics.RecordDetectionTriggered();
                _logger.LogInformation(
                    "Attributed detection: {Process} (PID {Pid}) - {SignalCount} signals, score={Score:F1}",
                    processName, pid, pidSignals.Count, result.Score);
            }
            if (result.PresidentKill)
                _metrics.RecordPresidentKill();

            var responses = await _responseEngine.RespondAsync(result, ct);

            if (alert && _commConfig.Enabled)
            {
                var report = DetectionReport.FromResult(_commConfig.AgentId, result, responses);
                try
                {
                    await _client.ReportDetectionAsync(report, ct);
                }
                catch
                {
                    // Server unreachable - buffer for later replay
                    await _offlineBuffer.EnqueueAsync(report, ct);
                }
            }
        }

        _metrics.RecordCycleCompleted();
        sw.Stop();
        _metrics.RecordCycleDuration(sw.Elapsed.TotalMilliseconds);

        if (signals.Count > 0)
        {
            _logger.LogDebug("Cycle complete: {SignalCount} signals across {Pids} attributed process(es)",
                signals.Count, SignalAttribution.GroupByPid(signals).Count);
        }
    }

    /// <summary>The rule family of a signal type: the text before the first colon.</summary>
    private static string SignalFamily(string signalType)
    {
        int colon = signalType.IndexOf(':');
        return colon > 0 ? signalType[..colon] : signalType;
    }
}
