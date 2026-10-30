namespace Behavedr.Core.Models;

/// <summary>
/// Represents a behavioral event to be analyzed by the detection engine.
/// v0.1.3: Removed dead Score field that was always 0.0 and never used (L-1 fix).
/// </summary>
public record DetectionEvent(
    string ProcessId,
    string ProcessName,
    string BehaviorType,
    DateTime Timestamp,
    bool IsUserTargeted,
    string Source
)
{
    /// <summary>Create a detection event with current timestamp.</summary>
    public static DetectionEvent Create(string processId, string processName, string behaviorType, string source, bool isUserTargeted = false) =>
        new(processId, processName, behaviorType, DateTime.UtcNow, isUserTargeted, source);
}
