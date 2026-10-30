namespace Behavedr.Core.Platform;

/// <summary>
/// Hot-updatable operational knobs from signed server policy (v0.3.1).
/// Monitoring interval is read each cycle so CommunicationService can adjust without restart.
/// </summary>
public sealed class LivePolicyState
{
    private int _monitoringIntervalSeconds = 5;
    private readonly object _lock = new();

    public int MonitoringIntervalSeconds
    {
        get { lock (_lock) return _monitoringIntervalSeconds; }
        set
        {
            var v = Math.Clamp(value, 1, 60);
            lock (_lock) _monitoringIntervalSeconds = v;
        }
    }

    public DateTime? LastPolicyAppliedUtc { get; private set; }

    public void MarkApplied() => LastPolicyAppliedUtc = DateTime.UtcNow;
}
