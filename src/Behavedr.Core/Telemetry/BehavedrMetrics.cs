namespace Behavedr.Core.Telemetry;

using System.Diagnostics.Metrics;

/// <summary>
/// OpenTelemetry-compatible metrics for the Behavedr agent.
/// Uses System.Diagnostics.Metrics (built into .NET) for zero-dependency metric collection.
/// Can be exported to Prometheus, OTLP, or any OTel-compatible backend.
/// </summary>
public sealed class BehavedrMetrics
{
    public static readonly string MeterName = "Behavedr.Agent";

    private readonly Meter _meter;
    private readonly Counter<long> _detectionCycles;
    private readonly Counter<long> _signalsCollected;
    private readonly Counter<long> _detectionsTriggered;
    private readonly Counter<long> _presidentKills;
    private readonly Counter<long> _responsesExecuted;
    private readonly Counter<long> _responsesFailed;
    private readonly Counter<long> _reportsBuffered;
    private readonly Counter<long> _reportsSent;
    private readonly Histogram<double> _detectionScore;
    private readonly Histogram<double> _cycleDurationMs;
    private readonly UpDownCounter<int> _activeMonitors;

    public BehavedrMetrics()
    {
        _meter = new Meter(MeterName, "0.3.9");

        _detectionCycles = _meter.CreateCounter<long>(
            "behavedr.detection.cycles",
            description: "Total detection cycles completed");

        _signalsCollected = _meter.CreateCounter<long>(
            "behavedr.signals.collected",
            description: "Total signals collected from monitors");

        _detectionsTriggered = _meter.CreateCounter<long>(
            "behavedr.detections.triggered",
            description: "Detection events that exceeded alert threshold");

        _presidentKills = _meter.CreateCounter<long>(
            "behavedr.detections.president_kills",
            description: "Events that triggered president-kill authority");

        _responsesExecuted = _meter.CreateCounter<long>(
            "behavedr.responses.executed",
            description: "Response actions successfully executed");

        _responsesFailed = _meter.CreateCounter<long>(
            "behavedr.responses.failed",
            description: "Response actions that failed");

        _reportsBuffered = _meter.CreateCounter<long>(
            "behavedr.comms.buffered",
            description: "Detection reports buffered offline");

        _reportsSent = _meter.CreateCounter<long>(
            "behavedr.comms.sent",
            description: "Detection reports sent to server");

        _detectionScore = _meter.CreateHistogram<double>(
            "behavedr.detection.score",
            unit: "score",
            description: "Distribution of detection scores");

        _cycleDurationMs = _meter.CreateHistogram<double>(
            "behavedr.detection.cycle_duration",
            unit: "ms",
            description: "Duration of detection cycles");

        _activeMonitors = _meter.CreateUpDownCounter<int>(
            "behavedr.monitors.active",
            description: "Number of active platform monitors");

        _isolationActions = _meter.CreateCounter<long>(
            "behavedr.isolation.actions",
            description: "Network isolation actions attempted");

        _signatureFailures = _meter.CreateCounter<long>(
            "behavedr.security.signature_failures",
            description: "Update/policy signature verification failures");

        _platformFeatureSoftFail = _meter.CreateCounter<long>(
            "behavedr.platform.soft_fail",
            description: "Optional platform depth features that soft-failed (eBPF/ES/Landlock)");
    }

    private readonly Counter<long> _isolationActions;
    private readonly Counter<long> _signatureFailures;
    private readonly Counter<long> _platformFeatureSoftFail;

    public void RecordCycleCompleted() => _detectionCycles.Add(1);

    public void RecordSignalsCollected(int count) => _signalsCollected.Add(count);

    public void RecordDetectionTriggered() => _detectionsTriggered.Add(1);

    public void RecordPresidentKill() => _presidentKills.Add(1);

    public void RecordResponseExecuted(bool success)
    {
        if (success)
            _responsesExecuted.Add(1);
        else
            _responsesFailed.Add(1);
    }

    public void RecordReportBuffered() => _reportsBuffered.Add(1);

    public void RecordReportSent() => _reportsSent.Add(1);

    public void RecordScore(double score) => _detectionScore.Record(score);

    public void RecordCycleDuration(double milliseconds) =>
        _cycleDurationMs.Record(milliseconds);

    public void RecordMonitorRegistered() => _activeMonitors.Add(1);

    public void RecordMonitorUnregistered() => _activeMonitors.Add(-1);

    public void RecordIsolationAction() => _isolationActions.Add(1);

    public void RecordSignatureFailure() => _signatureFailures.Add(1);

    public void RecordPlatformSoftFail(string feature) =>
        _platformFeatureSoftFail.Add(1, new KeyValuePair<string, object?>("feature", feature));
}
