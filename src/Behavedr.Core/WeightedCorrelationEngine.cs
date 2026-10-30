namespace Behavedr.Core;

using System.Collections.Concurrent;
using System.Text;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Explainable weighted multi-signal correlation engine - ported from Sentinel v2.0.
///
/// Complements BehavioralCorrelationEngine (hand-authored composites) with a
/// transparent score card:
///
///   Network=18, Injection=44, Persistence=31, Credential=50, ...
///   Total >= Threshold (default 100) + >=2 distinct weight categories
///   + at least one terminal-family contribution -> emit composite.
///
/// Score cards are always attached to detection results for ops/explainability
/// even when the threshold is not met.
/// </summary>
public sealed class WeightedCorrelationEngine
{
    private readonly ConcurrentDictionary<string, List<TimestampedSignal>> _buffers = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastEmit = new();
    private readonly WeightedCorrelationConfig _config;
    private readonly EventGraph? _eventGraph;
    private readonly ILogger<WeightedCorrelationEngine> _logger;
    private DateTime _lastPrune = DateTime.UtcNow;

    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromSeconds(60);

    /// <summary>Category -> weight (0-100 scale contribution, not confidence).</summary>
    public static readonly IReadOnlyDictionary<string, int> DefaultWeights =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["Credential"] = 50,
            ["TokenTheft"] = 48,
            ["Injection"] = 44,
            ["Memory"] = 40,
            ["Ransomware"] = 55,
            ["C2"] = 42,
            ["ReverseShell"] = 48,
            ["Exfil"] = 38,
            ["Persistence"] = 31,
            ["PrivilegeEscalation"] = 35,
            ["Evasion"] = 33,
            ["BYOVD"] = 60,
            ["Network"] = 18,
            ["Dns"] = 20,
            ["Lateral"] = 36,
            ["Surveillance"] = 28,
            ["Unsigned"] = 22,
            ["Generic"] = 10,
        };

    /// <summary>Terminal categories - emit requires at least one unless score is very high.</summary>
    private static readonly HashSet<string> TerminalCategories = new(StringComparer.OrdinalIgnoreCase)
    {
        "Credential", "TokenTheft", "ReverseShell", "C2", "Ransomware", "BYOVD", "Exfil", "Injection"
    };

    public WeightedCorrelationEngine(
        WeightedCorrelationConfig? config = null,
        EventGraph? eventGraph = null,
        ILogger<WeightedCorrelationEngine>? logger = null)
    {
        _config = config ?? new WeightedCorrelationConfig();
        _eventGraph = eventGraph;
        _logger = logger ?? NullLogger<WeightedCorrelationEngine>.Instance;
    }

    /// <summary>
    /// Register a signal for weighted correlation. Always produces a score card.
    /// Returns a composite signal if the threshold is met, otherwise null.
    /// </summary>
    public Signal? RegisterSignal(Signal signal, string processId, string processName)
    {
        if (signal == null || string.IsNullOrEmpty(processId)) return null;
        if (!_config.Enabled) return null;

        PruneStale();

        var buffer = _buffers.GetOrAdd(processId, _ => new List<TimestampedSignal>());
        lock (buffer)
        {
            buffer.Add(new TimestampedSignal(signal, DateTime.UtcNow));
            if (buffer.Count > 80)
                buffer.RemoveAt(0);
            var cutoff = DateTime.UtcNow - CorrelationWindow;
            buffer.RemoveAll(s => s.Timestamp < cutoff);
        }

        List<TimestampedSignal> snapshot;
        lock (buffer)
            snapshot = new List<TimestampedSignal>(buffer);

        var card = BuildScoreCard(processId, processName, snapshot);

        if (!ShouldEmit(card, snapshot))
            return null;

        if (_lastEmit.TryGetValue(processId, out var last) && DateTime.UtcNow - last < EmitCooldown)
            return null;

        _lastEmit[processId] = DateTime.UtcNow;

        var composite = BuildComposite(card, processId, processName);
        _logger.LogWarning("[WeightedCorrelation] EMIT: {Explanation}", card.Explanation);
        return composite;
    }

    /// <summary>Build an explainable score card for a process (test/ops helper).</summary>
    public CorrelationScoreCard GetScoreCard(string processId, string processName)
    {
        if (!_buffers.TryGetValue(processId, out var buffer))
            return new CorrelationScoreCard { ProcessId = processId, ProcessName = processName };

        List<TimestampedSignal> snapshot;
        lock (buffer)
            snapshot = new List<TimestampedSignal>(buffer);

        return BuildScoreCard(processId, processName, snapshot);
    }

    private bool ShouldEmit(CorrelationScoreCard card, List<TimestampedSignal> signals)
    {
        if (card.TotalScore < _config.Threshold)
            return false;
        if (card.DistinctCategories < _config.MinDistinctCategories)
            return false;

        // Require a terminal-family leg OR very high score
        bool hasTerminal = signals.Any(s => TerminalCategories.Contains(MapWeightCategory(s.Signal)));

        if (!hasTerminal && card.TotalScore < _config.Threshold + 40)
            return false;

        return true;
    }

    private CorrelationScoreCard BuildScoreCard(string pid, string processName, List<TimestampedSignal> signals)
    {
        var card = new CorrelationScoreCard
        {
            ProcessId = pid,
            ProcessName = processName ?? "",
            Threshold = _config.Threshold,
            WindowSeconds = (int)CorrelationWindow.TotalSeconds,
        };

        var weights = _config.Weights ?? DefaultWeights;
        var bestByCategory = new Dictionary<string, (int Weight, string SignalType, double Conf)>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var ts in signals)
        {
            var cat = MapWeightCategory(ts.Signal);
            if (!weights.TryGetValue(cat, out var w))
                w = weights.TryGetValue("Generic", out var g) ? g : 10;

            // Scale weight by confidence (0.5-1.0 floor)
            double conf = ts.Signal.Confidence > 0 ? Math.Min(1.0, ts.Signal.Confidence) : 0.55;
            int scaled = (int)Math.Round(w * (0.5 + 0.5 * conf));

            if (!bestByCategory.TryGetValue(cat, out var existing) || scaled > existing.Weight)
                bestByCategory[cat] = (scaled, ts.Signal.Type, conf);
        }

        foreach (var kv in bestByCategory.OrderByDescending(k => k.Value.Weight))
        {
            card.CategoryContributions[kv.Key] = kv.Value.Weight;
            card.ContributingRules.Add($"{kv.Key}={kv.Value.Weight} ({kv.Value.SignalType})");
        }

        card.TotalScore = card.CategoryContributions.Values.Sum();

        // EventGraph diversity boost
        if (_eventGraph != null && _config.EnableGraphBoost)
        {
            var diversity = _eventGraph.GetProcessDiversity(pid, processName);
            if (diversity.WeightBoost > 0)
            {
                card.GraphBoost = diversity.WeightBoost;
                card.TotalScore += diversity.WeightBoost;
                card.CategoryContributions["GraphDiversity"] = diversity.WeightBoost;
                card.ContributingRules.Add(
                    $"GraphDiversity={diversity.WeightBoost} (edges={diversity.EdgeCount}, " +
                    $"endpoints={diversity.DistinctEndpoints}, files={diversity.DistinctFiles})");
            }
        }

        card.DistinctCategories = card.CategoryContributions.Count(kv =>
            !string.Equals(kv.Key, "GraphDiversity", StringComparison.OrdinalIgnoreCase));
        card.SignalCount = signals.Count;
        card.MeetsThreshold = card.TotalScore >= _config.Threshold &&
                              card.DistinctCategories >= _config.MinDistinctCategories;
        card.Explanation = BuildExplanation(card);
        return card;
    }

    private static string BuildExplanation(CorrelationScoreCard card)
    {
        var sb = new StringBuilder();
        sb.Append("Weighted correlation: ");
        sb.Append(string.Join(" + ", card.CategoryContributions.Select(kv => $"{kv.Key}={kv.Value}")));
        sb.Append($" = {card.TotalScore}");
        sb.Append(card.MeetsThreshold
            ? $" >= threshold {card.Threshold} (emit)"
            : $" < threshold {card.Threshold} (observe)");
        return sb.ToString();
    }

    private Signal BuildComposite(CorrelationScoreCard card, string processId, string processName)
    {
        double confidence = Math.Min(0.97, 0.82 + (card.TotalScore / 500.0));
        var type = $"composite:weighted_correlation:pid:{processId}:score:{card.TotalScore}";
        return new Signal(type, 100, confidence);
    }

    /// <summary>Map a signal to a weight-bucket category based on its type string.</summary>
    public static string MapWeightCategory(Signal signal)
    {
        var lower = signal.Type.ToLowerInvariant();

        if (lower.Contains("credential") || lower.Contains("lsass") || lower.Contains("browser_cred"))
            return "Credential";
        if (lower.Contains("token") && lower.Contains("theft"))
            return "TokenTheft";
        if (lower.Contains("injection") || lower.Contains("hollowing") || lower.Contains("rwx_memory"))
            return "Injection";
        if (lower.Contains("ransom"))
            return "Ransomware";
        if (lower.Contains("beacon") || lower.Contains("c2"))
            return "C2";
        if (lower.Contains("reverse_shell") || lower.Contains("bind_shell"))
            return "ReverseShell";
        if (lower.Contains("exfil") || lower.Contains("data_staging"))
            return "Exfil";
        if (lower.Contains("persist") || lower.Contains("run_key") || lower.Contains("scheduled_task") || lower.Contains("service_registration"))
            return "Persistence";
        if (lower.Contains("privilege") || lower.Contains("escalat") || lower.Contains("uac"))
            return "PrivilegeEscalation";
        if (lower.Contains("evasion") || lower.Contains("amsi") || lower.Contains("etw") || lower.Contains("anti_tamper"))
            return "Evasion";
        if (lower.Contains("driver") || lower.Contains("byovd") || lower.Contains(".sys"))
            return "BYOVD";
        if (lower.Contains("network") || lower.Contains("connection") || lower.Contains("port"))
            return "Network";
        if (lower.Contains("dns") || lower.Contains("dga"))
            return "Dns";
        if (lower.Contains("lateral") || lower.Contains("psexec") || lower.Contains("wmi_exec"))
            return "Lateral";
        if (lower.Contains("surveillance") || lower.Contains("camera") || lower.Contains("screen") || lower.Contains("keylog"))
            return "Surveillance";
        if (lower.Contains("unsigned"))
            return "Unsigned";

        return "Generic";
    }

    private void PruneStale()
    {
        if (DateTime.UtcNow - _lastPrune < PruneInterval) return;
        _lastPrune = DateTime.UtcNow;

        var cutoff = DateTime.UtcNow - CorrelationWindow - TimeSpan.FromSeconds(30);
        foreach (var kvp in _buffers)
        {
            lock (kvp.Value)
            {
                kvp.Value.RemoveAll(s => s.Timestamp < cutoff);
            }
        }

        var emptyKeys = _buffers.Where(kv =>
        {
            lock (kv.Value) return kv.Value.Count == 0;
        }).Select(kv => kv.Key).ToList();
        foreach (var key in emptyKeys)
            _buffers.TryRemove(key, out _);
    }

    private record TimestampedSignal(Signal Signal, DateTime Timestamp);
}

/// <summary>Configuration for the weighted correlation engine.</summary>
public sealed class WeightedCorrelationConfig
{
    public bool Enabled { get; set; } = true;
    public int Threshold { get; set; } = 100;
    public int MinDistinctCategories { get; set; } = 2;
    public bool EnableGraphBoost { get; set; } = true;
    public IReadOnlyDictionary<string, int>? Weights { get; set; }
}

/// <summary>Explainable score card produced by the weighted engine.</summary>
public sealed class CorrelationScoreCard
{
    public string ProcessId { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int TotalScore { get; set; }
    public int Threshold { get; set; }
    public int WindowSeconds { get; set; }
    public int GraphBoost { get; set; }
    public int DistinctCategories { get; set; }
    public int SignalCount { get; set; }
    public bool MeetsThreshold { get; set; }
    public string Explanation { get; set; } = string.Empty;
    public Dictionary<string, int> CategoryContributions { get; set; } = new();
    public List<string> ContributingRules { get; set; } = new();
}
