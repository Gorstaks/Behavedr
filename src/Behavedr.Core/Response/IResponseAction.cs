namespace Behavedr.Core.Response;

using Behavedr.Core.Models;

/// <summary>
/// Defines a response action that can be taken when a detection event exceeds a threshold.
/// </summary>
public interface IResponseAction
{
    /// <summary>Human-readable name of this response action.</summary>
    string Name { get; }

    /// <summary>Whether this action type is supported on the current platform.</summary>
    bool IsSupported { get; }

    /// <summary>
    /// Execute the response action against a detection result.
    /// </summary>
    /// <param name="result">The detection result that triggered this response.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Outcome of the response action.</returns>
    Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default);
}

/// <summary>
/// Result of executing a response action.
/// </summary>
public record ResponseOutcome(
    string ActionName,
    bool Success,
    string Message,
    DateTime Timestamp)
{
    public static ResponseOutcome Ok(string actionName, string message) =>
        new(actionName, true, message, DateTime.UtcNow);

    public static ResponseOutcome Failed(string actionName, string message) =>
        new(actionName, false, message, DateTime.UtcNow);

    public static ResponseOutcome Skipped(string actionName, string reason) =>
        new(actionName, true, $"Skipped: {reason}", DateTime.UtcNow);
}
