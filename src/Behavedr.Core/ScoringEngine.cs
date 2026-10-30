namespace Behavedr.Core;

using System.Collections.Concurrent;
using Behavedr.Core.Models;

/// <summary>
/// Multi-signal scoring engine - upgraded from Sentinel's proven patterns.
///
/// Aggregates per-process detection events into composite threat scores.
/// Score increases with:
///   - Base confidence of signals
///   - Number of corroborating detection sources (+15 per distinct category on same PID)
///   - Multiple distinct threat categories on the same process
///   - President's Law rule hits (always boosted)
///   - User-targeted attacks (2x confidence multiplier)
/// Score decreases with:
///   - Behavioral baseline (established process with no prior detections)
///   - Capped at -20 total baseline reduction (prevents baseline poisoning)
///
/// Preserves raw score fidelity and maps to severity tiers for response decisions.
/// </summary>
public class ScoringEngine
{
    private ScoringConfig _config;
    private readonly object _configLock = new();

    // Per-process state tracking: PID -> detection history
    private readonly ConcurrentDictionary<string, ProcessScoreState> _processStates = new();
    private readonly BehavioralBaseline _baseline = new();
    private static readonly TimeSpan StateRetention = TimeSpan.FromMinutes(30);
    private DateTime _lastPrune = DateTime.UtcNow;

    public ScoringEngine(ScoringConfig? config = null)
    {
        _config = config ?? ScoringConfig.Default;
    }

    public double PresidentKillThreshold
    {
        get { lock (_configLock) return _config.PresidentKillThreshold; }
    }

    public double UserTargetedMultiplier
    {
        get { lock (_configLock) return _config.UserTargetedMultiplier; }
    }

    public ScoringConfig Config
    {
        get { lock (_configLock) return _config; }
    }

    /// <summary>Hot-apply scoring config from a signed policy update.</summary>
    public bool TryUpdateConfig(ScoringConfig config, out string error)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!config.IsValid())
        {
            error = "ScoringConfig failed IsValid()";
            return false;
        }
        lock (_configLock)
            _config = config;
        error = "";
        return true;
    }

    /// <summary>
    /// Score a detection event with full contextual enrichment.
    /// Returns a ThreatScore with breakdown of adjustments for explainability.
    /// </summary>
    public ThreatScore ScoreDetection(DetectionEvent evt, List<Signal> signals, FusedTelemetryContext? fusedContext = null)
    {
        ArgumentNullException.ThrowIfNull(evt);
        ArgumentNullException.ThrowIfNull(signals);

        PruneStaleStates();

        if (signals.Count == 0)
            return new ThreatScore { RawScore = 0, Verdict = ThreatVerdict.Clean };

        // 1. Base score: sum(weight x confidence)
        double baseScore = 0.0;
        foreach (var signal in signals)
        {
            var confidence = Math.Clamp(signal.Confidence, 0.0, 1.0);
            var weight = Math.Clamp(signal.Weight, 0.0, 100.0);
            baseScore += weight * confidence;
        }

        var adjustments = new List<ScoreAdjustment>();

        // 2. User-targeted boost (2x base)
        double mult;
        lock (_configLock)
            mult = _config.UserTargetedMultiplier;

        if (evt.IsUserTargeted)
        {
            var boost = baseScore * (mult - 1.0);
            adjustments.Add(new ScoreAdjustment("User-targeted attack multiplier", boost,
                $"{mult:F1}x confidence boost for user-targeting"));
            baseScore *= mult;
        }

        // 3. Categorize signals and update process state
        var categories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var signal in signals)
        {
            var cat = WeightedCorrelationEngine.MapWeightCategory(signal);
            categories.Add(cat);
        }

        var state = _processStates.GetOrAdd(evt.ProcessId, _ => new ProcessScoreState());
        state.LastSeen = DateTime.UtcNow;
        foreach (var cat in categories)
            state.DetectedCategories.Add(cat);
        state.DetectionCount++;

        // 4. Category corroboration boost: +15 per additional distinct category on this PID
        int priorCategories = state.DetectedCategories.Count - categories.Count;
        if (priorCategories > 0)
        {
            var boost = priorCategories * 15.0;
            adjustments.Add(new ScoreAdjustment("Multi-category corroboration", boost,
                $"{priorCategories} prior threat categories on this process"));
            baseScore += boost;
        }

        // 5. President's Law boost: high-severity categories always receive extra weight
        bool isPresidentsLaw = signals.Any(s => IsPresidentsLawSignal(s));
        if (isPresidentsLaw)
        {
            var boost = 10.0;
            adjustments.Add(new ScoreAdjustment("President's Law (terminal category)", boost,
                "High-severity behavioral detection"));
            baseScore += boost;
        }

        // 6. Graph diversity context boost (from fusion engine)
        if (fusedContext != null && fusedContext.GraphDiversityBoost > 0)
        {
            adjustments.Add(new ScoreAdjustment("Graph diversity boost", fusedContext.GraphDiversityBoost,
                $"Process touches {fusedContext.DistinctEndpoints} endpoints, {fusedContext.DistinctFiles} files"));
            baseScore += fusedContext.GraphDiversityBoost;
        }

        // 7. Behavioral baseline reduction (capped at -20)
        const double MaxBaselineReduction = 20.0;
        double totalReduction = 0.0;

        if (_baseline.IsEstablishedProcess(evt.ProcessName) && !isPresidentsLaw)
        {
            var reduction = Math.Min(10.0, MaxBaselineReduction - totalReduction);
            if (reduction > 0)
            {
                adjustments.Add(new ScoreAdjustment("Established process baseline", -reduction,
                    $"Process '{evt.ProcessName}' has no prior detections"));
                baseScore -= reduction;
                totalReduction += reduction;
            }
        }

        // Record that this process fired a detection (prevents future baseline trust)
        _baseline.RecordDetection(evt.ProcessName);

        // Floor at 0
        baseScore = Math.Max(0.0, baseScore);

        // Determine verdict
        var verdict = DetermineVerdict(baseScore);
        bool presidentKill = ShouldPresidentKill(baseScore, evt);

        return new ThreatScore
        {
            RawScore = baseScore,
            Verdict = verdict,
            PresidentKill = presidentKill,
            Categories = categories.ToList(),
            CorroboratingCategories = priorCategories,
            Adjustments = adjustments,
            IsPresidentsLaw = isPresidentsLaw,
        };
    }

    /// <summary>
    /// Legacy scoring method for backward compatibility.
    /// Delegates to ScoreDetection and returns just the raw score.
    /// </summary>
    public double CalculateScore(DetectionEvent evt, List<Signal> signals)
    {
        var result = ScoreDetection(evt, signals);
        return result.RawScore;
    }

    /// <summary>Get the normalized display score (clamped to 0-100 for UI).</summary>
    public static double NormalizeForDisplay(double rawScore) =>
        Math.Clamp(rawScore, 0.0, 100.0);

    public SeverityTier GetSeverityTier(double score) => score switch
    {
        > 200.0 => SeverityTier.Extreme,
        > 95.0 => SeverityTier.Critical,
        > 75.0 => SeverityTier.High,
        > 50.0 => SeverityTier.Medium,
        > 25.0 => SeverityTier.Low,
        _ => SeverityTier.Info,
    };

    public bool ShouldPresidentKill(double score, DetectionEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        double thr;
        lock (_configLock)
            thr = _config.PresidentKillThreshold;
        return score > thr && evt.IsUserTargeted;
    }

    /// <summary>
    /// President's Law signals: high-severity categories that always get boosted.
    /// These represent the most dangerous behaviors where immediate response is critical.
    /// </summary>
    public static bool IsPresidentsLawSignal(Signal signal)
    {
        var cat = WeightedCorrelationEngine.MapWeightCategory(signal);
        return cat is "Credential" or "Evasion" or "Ransomware" or "Injection"
            or "ReverseShell" or "PrivilegeEscalation" or "C2" or "BYOVD"
            or "TokenTheft";
    }

    private static ThreatVerdict DetermineVerdict(double score) => score switch
    {
        >= 80.0 => ThreatVerdict.Critical,
        >= 60.0 => ThreatVerdict.Malicious,
        >= 40.0 => ThreatVerdict.Suspicious,
        >= 20.0 => ThreatVerdict.Low,
        _ => ThreatVerdict.Clean,
    };

    private void PruneStaleStates()
    {
        if (DateTime.UtcNow - _lastPrune < TimeSpan.FromMinutes(5)) return;
        _lastPrune = DateTime.UtcNow;

        var cutoff = DateTime.UtcNow - StateRetention;
        var staleKeys = _processStates
            .Where(kv => kv.Value.LastSeen < cutoff)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var key in staleKeys)
            _processStates.TryRemove(key, out _);
    }

    /// <summary>Get corroborating category count for a process.</summary>
    public int GetCorroboratingCategoryCount(string processId)
    {
        return _processStates.TryGetValue(processId, out var state)
            ? state.DetectedCategories.Count
            : 0;
    }
}

/// <summary>Per-process scoring state for category tracking and corroboration.</summary>
internal sealed class ProcessScoreState
{
    public HashSet<string> DetectedCategories { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int DetectionCount { get; set; }
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Behavioral baseline - tracks process execution history to identify established
/// (non-threatening) processes. A process that has previously fired a detection
/// can NEVER become "established" (prevents baseline poisoning).
/// </summary>
internal sealed class BehavioralBaseline
{
    private readonly ConcurrentDictionary<string, int> _executionCount = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, bool> _detectionHistory = new(StringComparer.OrdinalIgnoreCase);

    private const int EstablishedThreshold = 10;

    public void RecordExecution(string processName)
    {
        _executionCount.AddOrUpdate(processName, 1, (_, c) => c + 1);
    }

    public void RecordDetection(string processName)
    {
        _detectionHistory[processName] = true;
    }

    /// <summary>
    /// A process is "established" if it has run 10+ times with NO prior detections.
    /// Once a detection fires for a process name, it can never be established again.
    /// </summary>
    public bool IsEstablishedProcess(string processName)
    {
        if (_detectionHistory.ContainsKey(processName))
            return false; // Had prior detections - never trusted
        return _executionCount.TryGetValue(processName, out var count) && count >= EstablishedThreshold;
    }
}

/// <summary>Structured threat score with explainability.</summary>
public sealed class ThreatScore
{
    public double RawScore { get; set; }
    public ThreatVerdict Verdict { get; set; }
    public bool PresidentKill { get; set; }
    public bool IsPresidentsLaw { get; set; }
    public List<string> Categories { get; set; } = [];
    public int CorroboratingCategories { get; set; }
    public List<ScoreAdjustment> Adjustments { get; set; } = [];
}

/// <summary>Score adjustment for audit/explainability trail.</summary>
public sealed record ScoreAdjustment(string Name, double Value, string Reason);

/// <summary>5-level verdict system.</summary>
public enum ThreatVerdict
{
    Clean,
    Low,
    Suspicious,
    Malicious,
    Critical,
}

/// <summary>Severity classification preserving raw score fidelity.</summary>
public enum SeverityTier
{
    Info,
    Low,
    Medium,
    High,
    Critical,
    Extreme,
}

/// <summary>Externalized scoring configuration.</summary>
public record ScoringConfig
{
    public double UserTargetedMultiplier { get; init; } = 2.0;
    public double PresidentKillThreshold { get; init; } = 95.0;
    public double HighScoreAlertThreshold { get; init; } = 50.0;

    public static ScoringConfig Default => new();

    public bool IsValid() =>
        UserTargetedMultiplier is > 0.0 and <= 10.0 &&
        PresidentKillThreshold is > 0.0 and <= 100.0 &&
        HighScoreAlertThreshold > 0.0 && HighScoreAlertThreshold < PresidentKillThreshold;
}
