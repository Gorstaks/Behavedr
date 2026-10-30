namespace Behavedr.Core;

using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Groups related detections into incidents by process tree and time window.
/// An incident represents a correlated set of detection events that likely belong
/// to the same attack campaign.
///
/// Grouping criteria:
/// - Same PID within 120s -> same incident
/// - Same parent PID within 120s -> same incident
/// - Composite signal referencing same PID -> same incident
///
/// Lifecycle: Open -> Active -> Closed (after 5 min inactivity)
/// </summary>
public class IncidentManager
{
    private readonly Dictionary<string, Incident> _activeIncidents = new();
    private readonly List<Incident> _closedIncidents = new();
    private readonly object _lock = new();
    private readonly ILogger<IncidentManager> _logger;
    private readonly TimeSpan _incidentTimeout = TimeSpan.FromMinutes(5);
    private readonly TimeSpan _correlationWindow = TimeSpan.FromSeconds(120);
    private long _incidentCounter;

    public IncidentManager(ILogger<IncidentManager>? logger = null)
    {
        _logger = logger ?? NullLogger<IncidentManager>.Instance;
    }

    /// <summary>
    /// Process a detection result and assign it to an incident.
    /// Returns the incident ID it was assigned to.
    /// </summary>
    public string ProcessDetection(DetectionResult result)
    {
        lock (_lock)
        {
            // Try to find an existing incident for this process
            var incident = FindMatchingIncident(result);

            if (incident is null)
            {
                // Create a new incident
                incident = CreateIncident(result);
                _activeIncidents[incident.Id] = incident;
                _logger.LogInformation("[Incident] New incident {Id} created for {Process} (score={Score:F1})",
                    incident.Id, result.Event.ProcessName, result.Score);
            }
            else
            {
                // Add to existing incident
                incident.AddDetection(result);
                _logger.LogDebug("[Incident] Detection added to incident {Id} ({Count} events, score={Score:F1})",
                    incident.Id, incident.DetectionCount, incident.MaxScore);
            }

            // Prune closed incidents
            PruneInactive();

            return incident.Id;
        }
    }

    /// <summary>
    /// Get all active incidents.
    /// </summary>
    public List<Incident> GetActiveIncidents()
    {
        lock (_lock)
        {
            PruneInactive();
            return _activeIncidents.Values.ToList();
        }
    }

    /// <summary>
    /// Get a specific incident by ID.
    /// </summary>
    public Incident? GetIncident(string incidentId)
    {
        lock (_lock)
        {
            return _activeIncidents.GetValueOrDefault(incidentId)
                ?? _closedIncidents.FirstOrDefault(i => i.Id == incidentId);
        }
    }

    /// <summary>
    /// Get count of active incidents.
    /// </summary>
    public int ActiveCount
    {
        get { lock (_lock) { return _activeIncidents.Count; } }
    }

    private Incident? FindMatchingIncident(DetectionResult result)
    {
        var now = DateTime.UtcNow;

        foreach (var incident in _activeIncidents.Values)
        {
            // Check if within correlation window
            if (now - incident.LastActivity > _correlationWindow)
                continue;

            // Same PID
            if (incident.InvolvedPids.Contains(result.Event.ProcessId))
                return incident;

            // Same process name (likely related even with different PIDs)
            if (incident.InvolvedProcessNames.Contains(result.Event.ProcessName) &&
                now - incident.LastActivity < TimeSpan.FromSeconds(30))
                return incident;
        }

        return null;
    }

    private Incident CreateIncident(DetectionResult result)
    {
        var id = $"INC-{Interlocked.Increment(ref _incidentCounter):D6}";
        var incident = new Incident(id, result);
        return incident;
    }

    private void PruneInactive()
    {
        var now = DateTime.UtcNow;
        var toClose = _activeIncidents
            .Where(kv => now - kv.Value.LastActivity > _incidentTimeout)
            .Select(kv => kv.Key).ToList();

        foreach (var id in toClose)
        {
            if (_activeIncidents.Remove(id, out var incident))
            {
                incident.Close();
                _closedIncidents.Add(incident);
                _logger.LogInformation("[Incident] Incident {Id} closed - {Count} detections, max score {Score:F1}, duration {Duration}s",
                    id, incident.DetectionCount, incident.MaxScore, incident.Duration.TotalSeconds);
            }
        }

        // Cap closed incident history
        if (_closedIncidents.Count > 100)
            _closedIncidents.RemoveRange(0, _closedIncidents.Count - 100);
    }
}

/// <summary>
/// Represents a correlated group of detection events (an incident/attack campaign).
/// </summary>
public class Incident
{
    private readonly List<DetectionSummary> _detections = new();

    public string Id { get; }
    public DateTime CreatedAt { get; }
    public DateTime LastActivity { get; private set; }
    public DateTime? ClosedAt { get; private set; }
    public IncidentStatus Status { get; private set; } = IncidentStatus.Open;
    public HashSet<string> InvolvedPids { get; } = new();
    public HashSet<string> InvolvedProcessNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public double MaxScore { get; private set; }
    public bool HasPresidentKill { get; private set; }
    public int DetectionCount => _detections.Count;
    public IReadOnlyList<DetectionSummary> Detections => _detections;
    public TimeSpan Duration => (ClosedAt ?? DateTime.UtcNow) - CreatedAt;

    public Incident(string id, DetectionResult initialResult)
    {
        Id = id;
        CreatedAt = DateTime.UtcNow;
        AddDetection(initialResult);
    }

    public void AddDetection(DetectionResult result)
    {
        _detections.Add(new DetectionSummary(
            result.Event.ProcessId,
            result.Event.ProcessName,
            result.Score,
            result.PresidentKill,
            result.Signals.Select(s => s.Type).ToList(),
            DateTime.UtcNow));

        InvolvedPids.Add(result.Event.ProcessId);
        InvolvedProcessNames.Add(result.Event.ProcessName);
        LastActivity = DateTime.UtcNow;

        if (result.Score > MaxScore)
            MaxScore = result.Score;
        if (result.PresidentKill)
            HasPresidentKill = true;

        Status = IncidentStatus.Active;
    }

    public void Close()
    {
        Status = IncidentStatus.Closed;
        ClosedAt = DateTime.UtcNow;
    }
}

public record DetectionSummary(
    string ProcessId,
    string ProcessName,
    double Score,
    bool PresidentKill,
    List<string> SignalTypes,
    DateTime Timestamp);

public enum IncidentStatus
{
    Open,
    Active,
    Closed,
}
