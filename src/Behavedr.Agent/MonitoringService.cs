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

        // Create a synthetic event representing the current monitoring cycle
        var evt = DetectionEvent.Create(
            processId: Environment.ProcessId.ToString(),
            processName: "behavedr-monitor",
            behaviorType: "periodic_scan",
            source: PlatformMonitors.CurrentPlatformSummary(),
            isUserTargeted: false);

        var result = await _engine.ProcessEventAsync(evt, ct);

        _metrics.RecordCycleCompleted();
        _metrics.RecordSignalsCollected(result.Signals.Count);
        _metrics.RecordScore(result.Score);
        if (result.Score > _responseEngine.Policy.AlertThreshold)
            _metrics.RecordDetectionTriggered();
        if (result.PresidentKill)
            _metrics.RecordPresidentKill();

        // v0.1.3 (C-1 fix): Execute response actions when score warrants it
        var responses = await _responseEngine.RespondAsync(result, ct);

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

                _logger.LogInformation(
                    "Attributed detection: {Process} (PID {Pid}) - {SignalCount} signals, score={Score:F1} (cycle={Cycle:F1})",
                    processName, pid, signals.Count, targetedResult.Score, result.Score);

                var targetedResponses = await _responseEngine.RespondAsync(targetedResult, ct);
                responses.AddRange(targetedResponses);
            }
        }

        // v0.1.3 (C-3 fix): Report detection to server if score warrants it
        if (result.Score > _responseEngine.Policy.AlertThreshold && _commConfig.Enabled)
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

        sw.Stop();
        _metrics.RecordCycleDuration(sw.Elapsed.TotalMilliseconds);

        if (result.Signals.Count > 0)
        {
            _logger.LogDebug("Cycle complete: {SignalCount} signals, score={Score:F1}, kill={Kill}, responses={ResponseCount}",
                result.Signals.Count, result.Score, result.PresidentKill, responses.Count);
        }
    }
}
