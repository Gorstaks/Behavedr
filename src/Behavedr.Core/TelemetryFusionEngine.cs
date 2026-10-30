namespace Behavedr.Core;

using System.Collections.Concurrent;
using Behavedr.Core.Models;

/// <summary>
/// Telemetry fusion layer - ported from Sentinel v2.0.
///
/// Every signal feeds through the fusion engine before scoring/correlation. The fusion layer:
/// 1. Maintains per-process signal chains (up to 500 events, 10-minute retention)
/// 2. Feeds every signal into the EventGraph (adding PROCESS->ENDPOINT, PROCESS->FILE edges)
/// 3. Produces a FusedTelemetryContext with behavioral velocity and multi-vector flags
///
/// The fusion layer is PASSIVE - it never blocks, kills, or modifies signals.
/// It enriches context for downstream engines (WeightedCorrelationEngine, ScoringEngine).
/// </summary>
public sealed class TelemetryFusionEngine : IAsyncDisposable
{
    private readonly EventGraph _eventGraph;
    private readonly ConcurrentDictionary<string, List<TimestampedSignal>> _processChains = new();
    private readonly Timer _cleanupTimer;

    // 500 events per chain makes evidence-erasure flooding expensive
    private const int MaxEventsPerChain = 500;
    private static readonly TimeSpan ChainRetention = TimeSpan.FromMinutes(10);

    public TelemetryFusionEngine(EventGraph eventGraph)
    {
        _eventGraph = eventGraph;
        _cleanupTimer = new Timer(CleanupStaleChains, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
    }

    /// <summary>
    /// Feed a signal from a detection cycle into the fusion engine.
    /// Updates the EventGraph and returns enriched context for scoring.
    /// </summary>
    public FusedTelemetryContext FeedSignal(Signal signal, string processId, string processName)
    {
        var ts = new TimestampedSignal(signal, DateTime.UtcNow);
        var chain = _processChains.GetOrAdd(processId, _ => new List<TimestampedSignal>());

        lock (chain)
        {
            chain.Add(ts);
            if (chain.Count > MaxEventsPerChain)
                chain.RemoveAt(0);
        }

        // Update EventGraph
        var procKey = $"PID_{processId}_{processName}";
        _eventGraph.AddNode(procKey, "PROCESS", new Dictionary<string, string>
        {
            { "PID", processId },
            { "Name", processName }
        });

        // Classify signal type for graph edges
        var signalLower = signal.Type.ToLowerInvariant();
        if (IsNetworkSignal(signalLower))
        {
            var endpointKey = $"ENDPOINT_{ExtractEndpoint(signal.Type)}";
            _eventGraph.AddEdge(procKey, endpointKey, "CONNECTED");
        }
        else if (IsFileSignal(signalLower))
        {
            var fileKey = $"FILE_{ExtractFilePath(signal.Type)}";
            _eventGraph.AddEdge(procKey, fileKey, "WROTE");
        }
        else if (IsProcessSignal(signalLower))
        {
            var childKey = $"PROCESS_{ExtractChildPid(signal.Type)}";
            _eventGraph.AddEdge(procKey, childKey, "SPAWNED");
        }

        return BuildContext(processId, processName, signal);
    }

    /// <summary>
    /// Feed a batch of signals from a detection cycle.
    /// Returns the last fused context (most enriched - has full chain awareness).
    /// </summary>
    public FusedTelemetryContext FeedBatch(IEnumerable<Signal> signals, string processId, string processName)
    {
        FusedTelemetryContext? lastContext = null;
        foreach (var signal in signals)
            lastContext = FeedSignal(signal, processId, processName);
        return lastContext ?? new FusedTelemetryContext { ProcessId = processId, ProcessName = processName };
    }

    private FusedTelemetryContext BuildContext(string processId, string processName, Signal triggeringSignal)
    {
        var context = new FusedTelemetryContext
        {
            TriggeringSignal = triggeringSignal,
            ProcessId = processId,
            ProcessName = processName,
        };

        if (_processChains.TryGetValue(processId, out var chain))
        {
            lock (chain)
            {
                int count = 0;
                bool hasNet = false;
                bool hasFile = false;
                bool hasCredential = false;
                var cutoff = DateTime.UtcNow - TimeSpan.FromSeconds(60);

                foreach (var e in chain)
                {
                    if (e.Timestamp >= cutoff)
                    {
                        count++;
                        var lower = e.Signal.Type.ToLowerInvariant();
                        if (IsNetworkSignal(lower)) hasNet = true;
                        else if (IsFileSignal(lower)) hasFile = true;
                        else if (IsCredentialSignal(lower)) hasCredential = true;
                    }
                }

                context.EventCount60s = count;
                context.HasNetworkActivity = hasNet;
                context.HasFileWrites = hasFile;
                context.HasCredentialAccess = hasCredential;
            }
        }

        // Graph diversity for this process
        var diversity = _eventGraph.GetProcessDiversity(processId, processName);
        context.GraphDiversityBoost = diversity.WeightBoost;
        context.DistinctEndpoints = diversity.DistinctEndpoints;
        context.DistinctFiles = diversity.DistinctFiles;

        return context;
    }

    private void CleanupStaleChains(object? state)
    {
        var cutoff = DateTime.UtcNow - ChainRetention;
        foreach (var key in _processChains.Keys)
        {
            if (_processChains.TryGetValue(key, out var chain))
            {
                lock (chain)
                {
                    chain.RemoveAll(e => e.Timestamp < cutoff);
                    if (chain.Count == 0)
                        _processChains.TryRemove(key, out _);
                }
            }
        }
        _eventGraph.Prune(ChainRetention);
    }

    #region Signal Classification

    private static bool IsNetworkSignal(string lower) =>
        lower.Contains("connection") || lower.Contains("beaconing") ||
        lower.Contains("network") || lower.Contains("port") ||
        lower.Contains("dns") || lower.Contains("exfil");

    private static bool IsFileSignal(string lower) =>
        lower.Contains("file_") || lower.Contains("write") ||
        lower.Contains("ransom") || lower.Contains("drop");

    private static bool IsProcessSignal(string lower) =>
        lower.Contains("spawn") || lower.Contains("parent_child") ||
        lower.Contains("process_burst") || lower.Contains("child");

    private static bool IsCredentialSignal(string lower) =>
        lower.Contains("credential") || lower.Contains("lsass") ||
        lower.Contains("browser_cred") || lower.Contains("token");

    private static string ExtractEndpoint(string signalType)
    {
        // Best-effort extraction from signal type strings like "connection_burst:1.2.3.4:443"
        var parts = signalType.Split(':');
        return parts.Length > 1 ? parts[1] : "unknown";
    }

    private static string ExtractFilePath(string signalType)
    {
        var parts = signalType.Split(':');
        return parts.Length > 1 ? parts[1] : "unknown_file";
    }

    private static string ExtractChildPid(string signalType)
    {
        // Look for pid:NNNN pattern
        var idx = signalType.IndexOf("pid:", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var start = idx + 4;
            var end = start;
            while (end < signalType.Length && char.IsDigit(signalType[end])) end++;
            if (end > start) return signalType[start..end];
        }
        return "unknown";
    }

    #endregion

    public ValueTask DisposeAsync()
    {
        _cleanupTimer.Dispose();
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    private record TimestampedSignal(Signal Signal, DateTime Timestamp);
}

/// <summary>
/// Enriched telemetry context produced by the fusion engine.
/// Consumed by ScoringEngine and WeightedCorrelationEngine for contextual decisions.
/// </summary>
public sealed class FusedTelemetryContext
{
    public Signal? TriggeringSignal { get; set; }
    public string ProcessId { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int EventCount60s { get; set; }
    public bool HasNetworkActivity { get; set; }
    public bool HasFileWrites { get; set; }
    public bool HasCredentialAccess { get; set; }
    public int GraphDiversityBoost { get; set; }
    public int DistinctEndpoints { get; set; }
    public int DistinctFiles { get; set; }
}
