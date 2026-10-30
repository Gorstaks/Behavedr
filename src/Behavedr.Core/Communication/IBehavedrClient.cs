namespace Behavedr.Core.Communication;

using Behavedr.Core.Models;
using Behavedr.Core.Response;

/// <summary>
/// Abstraction for the agent-to-server communication channel.
/// </summary>
public interface IBehavedrClient : IAsyncDisposable
{
    /// <summary>Whether the client is currently connected to the server.</summary>
    bool IsConnected { get; }

    /// <summary>Connect to the server.</summary>
    Task ConnectAsync(CancellationToken ct = default);

    /// <summary>Report a detection event to the server.</summary>
    Task ReportDetectionAsync(DetectionReport report, CancellationToken ct = default);

    /// <summary>Send an agent heartbeat with status information.</summary>
    Task SendHeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken ct = default);

    /// <summary>Fetch updated policy from the server (if available).</summary>
    Task<PolicyUpdate?> FetchPolicyAsync(CancellationToken ct = default);
}

/// <summary>
/// A detection report to send to the server.
/// Includes replay prevention fields: Nonce (unique per report), SequenceNumber (monotonic),
/// and BootNonce (unique per agent boot, prevents cross-session replay).
/// Server MUST validate: sequence is monotonically increasing per agent, nonce is unique,
/// boot nonce matches current session.
/// </summary>
public record DetectionReport(
    string AgentId,
    DetectionEvent Event,
    double Score,
    bool PresidentKill,
    List<SignalReport> Signals,
    List<ResponseOutcome> ResponsesTaken,
    DateTime ReportedAt,
    string Nonce,
    long SequenceNumber,
    string BootNonce)
{
    /// <summary>Monotonically increasing sequence counter for replay prevention.</summary>
    private static long _sequenceCounter = DateTime.UtcNow.Ticks;

    /// <summary>
    /// Per-boot unique nonce - changes every time the agent starts.
    /// Server uses this to detect if an attacker is replaying reports from a previous session.
    /// </summary>
    public static readonly string CurrentBootNonce = Guid.NewGuid().ToString("N");

    public static DetectionReport FromResult(string agentId, DetectionResult result, List<ResponseOutcome> responses) =>
        new(
            agentId,
            result.Event,
            result.Score,
            result.PresidentKill,
            result.Signals.Select(s => new SignalReport(s.Type, s.Weight, s.Confidence)).ToList(),
            responses,
            DateTime.UtcNow,
            Guid.NewGuid().ToString("N"),
            Interlocked.Increment(ref _sequenceCounter),
            CurrentBootNonce);
}

public record SignalReport(string Type, double Weight, double Confidence);

/// <summary>
/// Periodic heartbeat from agent to server.
/// </summary>
public record AgentHeartbeat(
    string AgentId,
    string Platform,
    string Version,
    int MonitorCount,
    long UptimeSeconds,
    DateTime SentAt);

/// <summary>
/// Policy update received from server. Must include a signature for authenticity verification.
/// </summary>
public record PolicyUpdate(
    ResponsePolicy? ResponsePolicy,
    ScoringConfig? ScoringConfig,
    int? MonitoringIntervalSeconds,
    DateTime IssuedAt,
    string? Signature = null)
{
    /// <summary>
    /// Verify that this policy update was signed by the server.
    /// Uses RSA-PSS SHA-256 via <see cref="Security.PolicySignatureVerifier"/>
    /// (separate key material path from package updates as of v0.2.4).
    /// </summary>
    public bool VerifySignature()
    {
        if (string.IsNullOrEmpty(Signature))
            return false;

        try
        {
            // Canonical payload = JSON of everything except signature
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                ResponsePolicy,
                ScoringConfig,
                MonitoringIntervalSeconds,
                IssuedAt,
            });

            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
            var sigBytes = Convert.FromBase64String(Signature);
            return Security.PolicySignatureVerifier.VerifyPayload(payloadBytes, sigBytes);
        }
        catch
        {
            return false;
        }
    }
}
