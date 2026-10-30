namespace Behavedr.Core;

using System.Collections.Concurrent;

/// <summary>
/// Queryable in-memory graph database tracking process-file-endpoint relationships.
/// Ported from Sentinel v2.0 - adapted for Behavedr's cross-platform type system.
///
/// Node types: PROCESS, FILE, ENDPOINT
/// Edge types: SPAWNED (process->process), CONNECTED (process->endpoint), WROTE (process->file)
///
/// Used by WeightedCorrelationEngine for graph diversity boost - processes touching
/// many distinct endpoints/files get higher correlation scores (behavioral fan-out
/// indicates more sophisticated attack tooling).
/// </summary>
public sealed class EventGraph
{
    private readonly ConcurrentDictionary<string, GraphNode> _nodes = new();
    private readonly ConcurrentDictionary<string, List<GraphEdge>> _processEdges = new();
    private readonly object _pruneLock = new();

    private const int MaxEdgesPerProcess = 300;
    private const int TrimEdgesTarget = 150;
    private const int HardCapProcesses = 5000;
    private const int HardCapFiles = 10000;
    private const int HardCapEndpoints = 3000;

    public void AddNode(string key, string type, Dictionary<string, string>? properties = null)
    {
        var node = _nodes.GetOrAdd(key, k => new GraphNode { Key = k, Type = type });
        node.LastSeen = DateTime.UtcNow;
        if (properties != null)
        {
            foreach (var (pKey, pVal) in properties)
                node.Properties[pKey] = pVal;
        }
    }

    public void AddEdge(string sourceKey, string targetKey, string relation)
    {
        var edge = new GraphEdge
        {
            SourceKey = sourceKey,
            TargetKey = targetKey,
            Relation = relation,
            Timestamp = DateTime.UtcNow,
        };

        AddNode(sourceKey, "PROCESS");
        AddNode(targetKey, relation == "WROTE" ? "FILE" : relation == "CONNECTED" ? "ENDPOINT" : "PROCESS");

        var edges = _processEdges.GetOrAdd(sourceKey, _ => new List<GraphEdge>());
        lock (edges)
        {
            edges.Add(edge);
            if (edges.Count > MaxEdgesPerProcess)
                edges.RemoveRange(0, edges.Count - TrimEdgesTarget);
        }
    }

    public List<GraphEdge> GetProcessEdges(string processKey)
    {
        if (_processEdges.TryGetValue(processKey, out var edges))
        {
            lock (edges)
                return new List<GraphEdge>(edges);
        }
        return [];
    }

    /// <summary>
    /// Diversity score for weighted correlation.
    /// Counts distinct relation types and endpoint/file fan-out for a process.
    /// Returns a bounded 0-25 weight boost.
    /// </summary>
    public GraphDiversityScore GetProcessDiversity(string processId, string? processName = null)
    {
        var score = new GraphDiversityScore { ProcessId = processId };
        var prefix = $"PID_{processId}_";
        var relations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int edgeCount = 0;

        foreach (var kvp in _processEdges)
        {
            if (!kvp.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                !(processName != null && kvp.Key.Equals($"PID_{processId}_{processName}", StringComparison.OrdinalIgnoreCase)))
                continue;

            List<GraphEdge> edges;
            lock (kvp.Value)
                edges = new List<GraphEdge>(kvp.Value);

            foreach (var e in edges)
            {
                edgeCount++;
                relations.Add(e.Relation ?? "");
                if (string.Equals(e.Relation, "CONNECTED", StringComparison.OrdinalIgnoreCase))
                    endpoints.Add(e.TargetKey);
                else if (string.Equals(e.Relation, "WROTE", StringComparison.OrdinalIgnoreCase))
                    files.Add(e.TargetKey);
            }
        }

        score.EdgeCount = edgeCount;
        score.DistinctRelations = relations.Count;
        score.DistinctEndpoints = endpoints.Count;
        score.DistinctFiles = files.Count;
        // Bounded boost 0-25
        score.WeightBoost =
            Math.Min(8, score.DistinctRelations * 3) +
            Math.Min(10, score.DistinctEndpoints) +
            Math.Min(7, score.DistinctFiles / 2);
        return score;
    }

    public void Prune(TimeSpan retentionWindow)
    {
        lock (_pruneLock)
        {
            var cutoff = DateTime.UtcNow - retentionWindow;

            var staleKeys = _nodes.Where(n => n.Value.LastSeen < cutoff).Select(n => n.Key).ToList();
            foreach (var key in staleKeys)
            {
                _nodes.TryRemove(key, out _);
                _processEdges.TryRemove(key, out _);
            }

            EnforceHardCaps("PROCESS", HardCapProcesses);
            EnforceHardCaps("FILE", HardCapFiles);
            EnforceHardCaps("ENDPOINT", HardCapEndpoints);
        }
    }

    private void EnforceHardCaps(string type, int capLimit)
    {
        var typeNodes = _nodes.Where(n => n.Value.Type == type).ToList();
        if (typeNodes.Count > capLimit)
        {
            var keysToRemove = typeNodes
                .OrderBy(n => n.Value.LastSeen)
                .Take(typeNodes.Count - capLimit)
                .Select(n => n.Key)
                .ToList();

            foreach (var key in keysToRemove)
            {
                _nodes.TryRemove(key, out _);
                _processEdges.TryRemove(key, out _);
            }
        }
    }

    public int NodeCount => _nodes.Count;
    public int EdgeBucketCount => _processEdges.Count;
}

public sealed class GraphNode
{
    public string Key { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    public Dictionary<string, string> Properties { get; set; } = new();
}

public sealed class GraphEdge
{
    public string SourceKey { get; set; } = string.Empty;
    public string TargetKey { get; set; } = string.Empty;
    public string Relation { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

public sealed class GraphDiversityScore
{
    public string ProcessId { get; set; } = string.Empty;
    public int EdgeCount { get; set; }
    public int DistinctRelations { get; set; }
    public int DistinctEndpoints { get; set; }
    public int DistinctFiles { get; set; }
    public int WeightBoost { get; set; }
}
