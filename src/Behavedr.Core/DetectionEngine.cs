namespace Behavedr.Core;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Behavedr.Core.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Main behavioral detection engine.
/// Collects signals from registered platform monitors, scores them per process, and decides on response.
/// Machine-wide signals (no PID) are collected for context but never scored as a detection.
/// The agent's own processes are removed before scoring.
/// </summary>
public class DetectionEngine
{
    private readonly ScoringEngine _scoring;
    private readonly BehavioralCorrelationEngine _correlation;
    private readonly SignalDeduplicator _deduplicator;
    private readonly SuppressionList _suppressions;
    private readonly List<IPlatformMonitor> _monitors = new();
    private readonly ILogger<DetectionEngine> _logger;

    public DetectionEngine(
        ScoringEngine? scoring = null,
        BehavioralCorrelationEngine? correlation = null,
        ILogger<DetectionEngine>? logger = null,
        SuppressionList? suppressions = null)
    {
        _scoring = scoring ?? new ScoringEngine();
        _correlation = correlation ?? new BehavioralCorrelationEngine();
        _deduplicator = new SignalDeduplicator();
        _suppressions = suppressions ?? SuppressionList.Empty;
        _logger = logger ?? NullLogger<DetectionEngine>.Instance;
    }

    public IReadOnlyList<IPlatformMonitor> RegisteredMonitors => _monitors;

    public void RegisterMonitor(IPlatformMonitor monitor)
    {
        ArgumentNullException.ThrowIfNull(monitor);
        _monitors.Add(monitor);
        _logger.LogInformation("Registered monitor: {MonitorType} ({Platform})", monitor.GetType().Name, monitor.PlatformName);
    }

    /// <summary>
    /// Collect and filter one monitoring cycle's signals without scoring them. Use this for
    /// the periodic scan. Scoring happens per PID through <see cref="ScoreAttributed"/>, so no
    /// machine-wide total is ever reported as a detection.
    /// </summary>
    public async Task<List<Signal>> CollectCycleSignalsAsync(CancellationToken ct = default)
    {
        var signals = await CollectSignalsAsync(ct);

        // Deduplicate signals within this cycle
        signals = _deduplicator.DeduplicateWithinCycle(signals);

        // Drop signals about the agent itself, its children, and processes it launched
        signals = signals.Where(s => !IsAgentSignal(s)).ToList();

        // Run behavioral correlation to produce composite signals
        var composites = _correlation.Correlate(signals);
        if (composites.Count > 0)
        {
            signals.AddRange(composites);
            _logger.LogDebug("Correlation engine produced {Count} composite signals", composites.Count);
        }

        // Operator-approved suppressions (never President's Law categories)
        signals = _suppressions.Apply(signals, out int suppressed);
        if (suppressed > 0)
            _logger.LogDebug("Suppressed {Count} signal(s) by operator rule", suppressed);
        LastSuppressedCount = suppressed;

        // Cooldown per PID, so one process cannot suppress another process's signal of the same type
        return ApplyCooldownPerPid(signals);
    }

    /// <summary>Signals removed by operator suppressions in the most recent cycle.</summary>
    public int LastSuppressedCount { get; private set; }

    /// <summary>
    /// Process a detection event: collect signals from all monitors, score, and determine response.
    /// The cycle's signals are scored as a whole, so this suits callers with a single subject
    /// process. The periodic agent scan uses <see cref="CollectCycleSignalsAsync"/> and
    /// <see cref="ScoreAttributed"/>.
    /// </summary>
    public async Task<DetectionResult> ProcessEventAsync(DetectionEvent evt, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(evt);

        _logger.LogDebug("Processing event: {ProcessName} ({BehaviorType}) from {Source}",
            evt.ProcessName, evt.BehaviorType, evt.Source);

        var signals = await CollectCycleSignalsAsync(ct);

        var score = _scoring.CalculateScore(evt, signals);
        bool presidentKill = _scoring.ShouldPresidentKill(score, evt);

        var result = new DetectionResult(evt, score, presidentKill, signals);

        if (presidentKill)
        {
            _logger.LogWarning("PRESIDENT KILL triggered for {ProcessName} (score={Score:F1})",
                evt.ProcessName, score);
        }
        else if (score > 50.0)
        {
            _logger.LogInformation("High-score detection: {ProcessName} score={Score:F1}",
                evt.ProcessName, score);
        }

        return result;
    }

    /// <summary>
    /// Score a PID-attributed subset of signals. Does not reuse a machine-wide cycle score.
    /// </summary>
    public DetectionResult ScoreAttributed(DetectionEvent evt, List<Signal> signals)
    {
        ArgumentNullException.ThrowIfNull(evt);
        ArgumentNullException.ThrowIfNull(signals);

        var score = _scoring.CalculateScore(evt, signals);
        var presidentKill = _scoring.ShouldPresidentKill(score, evt);
        return new DetectionResult(evt, score, presidentKill, signals);
    }

    private static bool IsAgentSignal(Signal signal) =>
        SignalAttribution.TryGetPid(signal.Type, out var pid) && AgentProcessIdentity.IsAgentOwned(pid);

    private List<Signal> ApplyCooldownPerPid(List<Signal> signals)
    {
        var result = new List<Signal>(signals.Count);
        foreach (var group in signals.GroupBy(s =>
                     SignalAttribution.TryGetPid(s.Type, out var pid) ? pid.ToString() : null))
        {
            result.AddRange(_deduplicator.ApplyCooldown(group.ToList(), group.Key));
        }
        return result;
    }

    /// <summary>
    /// Collect signals from all registered monitors that are supported on this platform.
    /// Runs monitors concurrently with per-monitor timeout to prevent slow monitors
    /// from blocking the detection cycle.
    /// </summary>
    private async Task<List<Signal>> CollectSignalsAsync(CancellationToken ct)
    {
        var allSignals = new List<Signal>();
        // Keep short: most monitors are sync and ignore CancellationToken until they return.
        var monitorTimeout = TimeSpan.FromSeconds(5);

        // Run all supported monitors concurrently on the thread pool so a blocking
        // GetSignalsAsync (macOS FSW / ps / kqueue) cannot stall the whole cycle forever.
        var tasks = _monitors
            .Where(m => m.IsSupported)
            .Select(async monitor =>
            {
                try
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(monitorTimeout);

                    // Do not pass timeoutCts into Task.Run. Cancelling a still-queued
                    // run (thread-pool delay on Windows CI) dropped FakeMonitor/real
                    // signals and failed president-kill with empty results.
                    var work = Task.Run(async () =>
                        (await monitor.GetSignalsAsync(timeoutCts.Token).ConfigureAwait(false)).ToList());
                    var signals = await work.WaitAsync(monitorTimeout, ct).ConfigureAwait(false);

                    return (monitor, signals, error: (Exception?)null);
                }
                catch (TimeoutException)
                {
                    _logger.LogWarning("Monitor {Monitor} timed out after {Timeout}s (abandoned)",
                        monitor.PlatformName, monitorTimeout.TotalSeconds);
                    return (monitor, signals: new List<Signal>(), error: (Exception?)null);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    _logger.LogWarning("Monitor {Monitor} timed out after {Timeout}s",
                        monitor.PlatformName, monitorTimeout.TotalSeconds);
                    return (monitor, signals: new List<Signal>(), error: (Exception?)null);
                }
                catch (OperationCanceledException)
                {
                    throw; // Propagate real cancellation
                }
                catch (Exception ex)
                {
                    return (monitor, signals: new List<Signal>(), error: ex);
                }
            })
            .ToList();

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        foreach (var (monitor, signals, error) in results)
        {
            if (error is not null)
            {
                _logger.LogError(error, "Failed to collect signals from {Monitor}", monitor.PlatformName);
                continue;
            }

            allSignals.AddRange(signals);
            _logger.LogDebug("Collected {Count} signals from {Monitor}",
                signals.Count, monitor.PlatformName);
        }

        return allSignals;
    }
}

public record DetectionResult(DetectionEvent Event, double Score, bool PresidentKill, List<Signal> Signals);
