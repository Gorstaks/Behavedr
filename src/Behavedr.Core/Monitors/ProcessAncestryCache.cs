namespace Behavedr.Core.Monitors;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// In-memory process ancestry cache for parent-child relationship resolution.
/// Populated from EtwSession/NativeEtwSession process start events.
/// Maintains parent-child mappings for 120 seconds (matches correlation window).
///
/// Enables:
/// - "Grandparent" analysis (e.g., Word -> cmd -> PowerShell -> encoded command)
/// - Parent resolution even after parent process exits
/// - Ancestry chain enrichment for all monitors
///
/// Thread-safe. Bounded to prevent unbounded memory growth.
/// </summary>
public class ProcessAncestryCache
{
    private readonly Dictionary<int, ProcessRecord> _cache = new();
    private readonly object _lock = new();
    private readonly ILogger<ProcessAncestryCache> _logger;
    private readonly TimeSpan _maxAge = TimeSpan.FromSeconds(120);
    private const int MaxCacheSize = 5000;

    public ProcessAncestryCache(ILogger<ProcessAncestryCache>? logger = null)
    {
        _logger = logger ?? NullLogger<ProcessAncestryCache>.Instance;
    }

    /// <summary>
    /// Record a process start event.
    /// </summary>
    public void RecordProcessStart(int pid, int parentPid, string processName, string? commandLine = null)
    {
        lock (_lock)
        {
            if (_cache.Count >= MaxCacheSize)
                EvictOldest();

            _cache[pid] = new ProcessRecord
            {
                Pid = pid,
                ParentPid = parentPid,
                ProcessName = processName,
                CommandLine = commandLine ?? "",
                StartTime = DateTime.UtcNow,
            };
        }
    }

    /// <summary>
    /// Record a process stop event (mark as exited but keep in cache for ancestry resolution).
    /// </summary>
    public void RecordProcessStop(int pid)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(pid, out var record))
            {
                record.ExitTime = DateTime.UtcNow;
            }
        }
    }

    /// <summary>
    /// Get the parent PID for a given process. Returns null if unknown.
    /// </summary>
    public int? GetParentPid(int pid)
    {
        lock (_lock)
        {
            return _cache.TryGetValue(pid, out var record) ? record.ParentPid : null;
        }
    }

    /// <summary>
    /// Get the process name for a given PID. Returns null if unknown.
    /// Resolves even for exited processes (within cache window).
    /// </summary>
    public string? GetProcessName(int pid)
    {
        lock (_lock)
        {
            return _cache.TryGetValue(pid, out var record) ? record.ProcessName : null;
        }
    }

    /// <summary>
    /// Get the full ancestry chain for a process (child -> parent -> grandparent -> ...).
    /// Returns up to maxDepth ancestors. Stops at unknown PIDs.
    /// </summary>
    public List<AncestryEntry> GetAncestryChain(int pid, int maxDepth = 5)
    {
        var chain = new List<AncestryEntry>();
        var visited = new HashSet<int>();

        lock (_lock)
        {
            var currentPid = pid;
            for (int i = 0; i < maxDepth; i++)
            {
                if (!_cache.TryGetValue(currentPid, out var record))
                    break;

                if (!visited.Add(currentPid))
                    break; // Cycle detection

                chain.Add(new AncestryEntry(record.Pid, record.ParentPid, record.ProcessName));
                currentPid = record.ParentPid;
            }
        }

        return chain;
    }

    /// <summary>
    /// Check if a process has a specific ancestor in its chain.
    /// Useful for detecting multi-hop attack chains.
    /// </summary>
    public bool HasAncestor(int pid, string ancestorName, int maxDepth = 5)
    {
        var chain = GetAncestryChain(pid, maxDepth);
        return chain.Any(a => a.ProcessName.Equals(ancestorName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Get the ancestry chain as a readable string (e.g., "powershell <- cmd <- winword").
    /// </summary>
    public string GetAncestryString(int pid, int maxDepth = 4)
    {
        var chain = GetAncestryChain(pid, maxDepth);
        if (chain.Count == 0) return "unknown";
        return string.Join(" <- ", chain.Select(a => a.ProcessName));
    }

    /// <summary>
    /// Ingest process events from the ETW session.
    /// Call this periodically from the monitoring loop.
    /// </summary>
    public void IngestEtwEvents(List<EtwProcessEvent> events)
    {
        foreach (var evt in events)
        {
            if (evt.EventType == ProcessEventType.Start)
            {
                RecordProcessStart(evt.ProcessId, evt.ParentProcessId, evt.ProcessName, evt.CommandLine);
            }
            else if (evt.EventType == ProcessEventType.Stop)
            {
                RecordProcessStop(evt.ProcessId);
            }
        }
    }

    /// <summary>
    /// Prune expired entries. Call periodically.
    /// </summary>
    public void Prune()
    {
        lock (_lock)
        {
            var cutoff = DateTime.UtcNow - _maxAge;
            var expired = _cache
                .Where(kv => kv.Value.ExitTime.HasValue && kv.Value.ExitTime.Value < cutoff)
                .Select(kv => kv.Key).ToList();

            foreach (var key in expired)
                _cache.Remove(key);

            // Also remove very old entries (running but stale)
            var stale = _cache
                .Where(kv => kv.Value.StartTime < cutoff && !kv.Value.ExitTime.HasValue)
                .Select(kv => kv.Key).ToList();

            foreach (var key in stale)
                _cache.Remove(key);
        }
    }

    /// <summary>Current number of cached process records.</summary>
    public int Count
    {
        get { lock (_lock) { return _cache.Count; } }
    }

    private void EvictOldest()
    {
        var oldest = _cache
            .OrderBy(kv => kv.Value.StartTime)
            .Take(1000)
            .Select(kv => kv.Key).ToList();
        foreach (var key in oldest)
            _cache.Remove(key);
    }

    private class ProcessRecord
    {
        public int Pid { get; init; }
        public int ParentPid { get; init; }
        public string ProcessName { get; init; } = "";
        public string CommandLine { get; init; } = "";
        public DateTime StartTime { get; init; }
        public DateTime? ExitTime { get; set; }
    }
}

public record AncestryEntry(int Pid, int ParentPid, string ProcessName);
