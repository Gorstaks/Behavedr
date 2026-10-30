namespace Behavedr.Core.Response;

using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Orchestrates response actions based on detection results and configured policy.
/// Supports alert-only mode (default) and active response mode.
/// </summary>
public class ResponseEngine
{
    private readonly List<IResponseAction> _actions = new();
    private readonly ILogger<ResponseEngine> _logger;
    private ResponsePolicy _policy;
    private readonly ResponseAuditWriter _audit;
    private readonly Telemetry.BehavedrMetrics? _metrics;
    private readonly object _policyLock = new();

    // Rate limiting: track recent response targets to prevent re-executing on same PID/path
    private readonly Dictionary<string, DateTime> _recentTargets = new();
    private readonly TimeSpan _cooldownPeriod = TimeSpan.FromSeconds(60);
    private readonly object _rateLimitLock = new();

    // v0.2.2 (from Sentinel): global kill budget per rolling minute to stop kill-storms / FP weaponization
    private readonly Queue<DateTime> _recentKills = new();

    public ResponseEngine(
        ResponsePolicy? policy = null,
        ILogger<ResponseEngine>? logger = null,
        ResponseAuditWriter? audit = null,
        Telemetry.BehavedrMetrics? metrics = null)
    {
        _policy = policy ?? ResponsePolicy.Default;
        _logger = logger ?? NullLogger<ResponseEngine>.Instance;
        _audit = audit ?? new ResponseAuditWriter(logger: _logger);
        _metrics = metrics;
    }

    public IReadOnlyList<IResponseAction> RegisteredActions => _actions;
    public ResponsePolicy Policy
    {
        get { lock (_policyLock) return _policy; }
    }

    /// <summary>
    /// Hot-apply a signed policy update (v0.3.1). Rejects invalid thresholds.
    /// </summary>
    public bool TryUpdatePolicy(ResponsePolicy policy, out string error)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!policy.IsValid())
        {
            error = "ResponsePolicy failed IsValid()";
            return false;
        }
        lock (_policyLock)
        {
            _policy = policy;
        }
        _logger.LogWarning(
            "Response policy updated live: Mode={Mode}, Alert={Alert}, Respond={Respond}, MaxKills={Max}",
            policy.Mode, policy.AlertThreshold, policy.ResponseThreshold, policy.MaxKillsPerMinute);
        error = "";
        return true;
    }

    /// <summary>Register a response action.</summary>
    public void RegisterAction(IResponseAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        _actions.Add(action);
        _logger.LogInformation("Registered response action: {Action} (supported: {Supported})",
            action.Name, action.IsSupported);
    }

    /// <summary>
    /// Evaluate a detection result and execute appropriate response actions.
    /// </summary>
    public async Task<List<ResponseOutcome>> RespondAsync(DetectionResult result, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        var outcomes = new List<ResponseOutcome>();

        ResponsePolicy policySnapshot;
        lock (_policyLock) policySnapshot = _policy;

        // Determine response level based on score and policy
        var level = DetermineResponseLevel(result, policySnapshot);

        _logger.LogDebug("Detection score={Score:F1}, level={Level}, policy={PolicyMode}",
            result.Score, level, policySnapshot.Mode);

        // Alert-only mode: log but don't act
        if (policySnapshot.Mode == ResponseMode.AlertOnly)
        {
            if (level >= ResponseLevel.Respond)
            {
                _logger.LogWarning("ALERT (alert-only mode): {ProcessName} scored {Score:F1} - would trigger {Level}",
                    result.Event.ProcessName, result.Score, level);
                outcomes.Add(ResponseOutcome.Skipped("policy", $"Alert-only mode active. Score={result.Score:F1}, level={level}"));
                _audit.Append(result, outcomes, policySnapshot.Mode.ToString());
            }
            return outcomes;
        }

        // Active mode: execute response actions based on level
        if (level < ResponseLevel.Respond)
            return outcomes;

        // Rate limiting: don't re-execute actions against the same target within cooldown
        var targetKey = $"{result.Event.ProcessId}:{result.Event.ProcessName}";
        lock (_rateLimitLock)
        {
            // Prune expired entries
            var expired = _recentTargets.Where(kv => DateTime.UtcNow - kv.Value > _cooldownPeriod).Select(kv => kv.Key).ToList();
            foreach (var key in expired) _recentTargets.Remove(key);

            if (_recentTargets.ContainsKey(targetKey))
            {
                _logger.LogDebug("Rate-limited: already responded to {Target} within cooldown", targetKey);
                outcomes.Add(ResponseOutcome.Skipped("rate-limit", $"Cooldown active for {targetKey}"));
                return outcomes;
            }

            _recentTargets[targetKey] = DateTime.UtcNow;
        }

        foreach (var action in _actions)
        {
            if (ct.IsCancellationRequested) break;
            if (!action.IsSupported) continue;

            // President Kill: ProcessKillAction only at president threshold.
            // AndroidResponseEngine runs at Respond+ (mobile has no separate quarantine action).
            if (level < ResponseLevel.PresidentKill && action is ProcessKillAction)
            {
                outcomes.Add(ResponseOutcome.Skipped(action.Name, "Score below president-kill threshold"));
                continue;
            }

            // Kill budget (Sentinel MaxKillsPerMinute pattern)
            if (IsKillClassAction(action) && !TryConsumeKillBudget(policySnapshot.MaxKillsPerMinute))
            {
                _logger.LogWarning(
                    "Kill budget exhausted ({Max}/min) - demoting {Action} for {Process}",
                    policySnapshot.MaxKillsPerMinute, action.Name, result.Event.ProcessName);
                outcomes.Add(ResponseOutcome.Skipped(action.Name,
                    $"Kill budget exhausted (max {policySnapshot.MaxKillsPerMinute}/min)"));
                continue;
            }

            try
            {
                _logger.LogInformation("Executing response action: {Action} against {Process}",
                    action.Name, result.Event.ProcessName);

                var outcome = await action.ExecuteAsync(result, ct);
                outcomes.Add(outcome);
                _metrics?.RecordResponseExecuted(
                    outcome.Success && !outcome.Message.StartsWith("Skipped:", StringComparison.Ordinal));

                _logger.LogInformation("Response action {Action}: {Success} - {Message}",
                    action.Name, outcome.Success ? "SUCCESS" : "FAILED", outcome.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Response action {Action} threw exception", action.Name);
                outcomes.Add(ResponseOutcome.Failed(action.Name, ex.Message));
                _metrics?.RecordResponseExecuted(false);
            }
        }

        _audit.Append(result, outcomes, policySnapshot.Mode.ToString());
        return outcomes;
    }

    private static bool IsKillClassAction(IResponseAction action) =>
        action is ProcessKillAction or AndroidResponseEngine;

    private bool TryConsumeKillBudget(int maxKillsPerMinute)
    {
        if (maxKillsPerMinute <= 0) return false;

        lock (_rateLimitLock)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-1);
            while (_recentKills.Count > 0 && _recentKills.Peek() < cutoff)
                _recentKills.Dequeue();

            if (_recentKills.Count >= maxKillsPerMinute)
                return false;

            _recentKills.Enqueue(DateTime.UtcNow);
            return true;
        }
    }

    private static ResponseLevel DetermineResponseLevel(DetectionResult result, ResponsePolicy policy)
    {
        if (result.PresidentKill)
            return ResponseLevel.PresidentKill;
        if (result.Score >= policy.ResponseThreshold)
            return ResponseLevel.Respond;
        if (result.Score >= policy.AlertThreshold)
            return ResponseLevel.Alert;
        return ResponseLevel.None;
    }
}

/// <summary>
/// Response policy configuration.
/// </summary>
public record ResponsePolicy
{
    /// <summary>Operating mode: AlertOnly (log only) or Active (take actions).</summary>
    public ResponseMode Mode { get; init; } = ResponseMode.AlertOnly;

    /// <summary>Minimum score to trigger an alert.</summary>
    public double AlertThreshold { get; init; } = 50.0;

    /// <summary>Minimum score to trigger active response.</summary>
    public double ResponseThreshold { get; init; } = 75.0;

    /// <summary>Whether to quarantine files found in suspicious locations.</summary>
    public bool EnableQuarantine { get; init; } = true;

    /// <summary>Whether to kill processes flagged by president-kill.</summary>
    public bool EnableProcessKill { get; init; } = true;

    /// <summary>Path for quarantined files.</summary>
    public string QuarantinePath { get; init; } = "quarantine";

    /// <summary>
    /// Max kill-class actions per rolling minute (0 = unlimited).
    /// From Sentinel 1.6.0 kill-storm mitigation.
    /// </summary>
    public int MaxKillsPerMinute { get; init; } = 15;

    public static ResponsePolicy Default => new();

    /// <summary>
    /// Reject policies that would disable safety budgets or set absurd kill rates
    /// (signed-policy still cannot ask for unlimited kill-storms).
    /// </summary>
    public bool IsValid() =>
        AlertThreshold > 0.0 && AlertThreshold <= 100.0 &&
        ResponseThreshold > AlertThreshold && ResponseThreshold <= 100.0 &&
        MaxKillsPerMinute >= 1 && MaxKillsPerMinute <= 60 &&
        // Active mode must not set response so low that any noise kills
        (Mode != ResponseMode.Active || ResponseThreshold >= 40.0);
}

public enum ResponseMode
{
    /// <summary>Log detections but take no automated action.</summary>
    AlertOnly,

    /// <summary>Take automated response actions based on thresholds.</summary>
    Active,
}

public enum ResponseLevel
{
    None,
    Alert,
    Respond,
    PresidentKill,
}
