namespace Behavedr.Core;

using Behavedr.Core.Models;

/// <summary>
/// Signal deduplication and decay engine.
/// Prevents the same signal type from flooding the scoring engine within a cooldown period.
/// Provides exponential decay of signal weight over time within the correlation window.
///
/// Rules:
/// - Same signal type within a single cycle: deduplicated (keep highest confidence)
/// - Same (signal_type, PID) within cooldown (30s): suppressed
/// - Composite correlation rules: fire once per correlation window (120s)
/// - Signal weight decays exponentially over time: weight * e^(-t) where  = ln(2)/halflife
/// </summary>
public class SignalDeduplicator
{
    private readonly Dictionary<string, DateTime> _signalCooldowns = new();
    private readonly Dictionary<string, DateTime> _compositeCooldowns = new();
    private readonly object _lock = new();
    private readonly TimeSpan _signalCooldown = TimeSpan.FromSeconds(30);
    private readonly TimeSpan _compositeCooldown = TimeSpan.FromSeconds(120);
    private readonly double _decayHalfLifeSeconds = 60.0;

    /// <summary>
    /// Deduplicate signals within a single detection cycle.
    /// Keeps the highest-confidence instance of each signal type.
    /// </summary>
    public List<Signal> DeduplicateWithinCycle(List<Signal> signals)
    {
        if (signals.Count <= 1)
            return signals;

        var bestByType = new Dictionary<string, Signal>();

        foreach (var signal in signals)
        {
            // Extract base type (strip PID/details suffix for grouping)
            var baseType = GetBaseSignalType(signal.Type);

            if (!bestByType.TryGetValue(baseType, out var existing) ||
                signal.Confidence > existing.Confidence)
            {
                bestByType[baseType] = signal;
            }
        }

        return bestByType.Values.ToList();
    }

    /// <summary>
    /// Apply cross-cycle cooldown suppression.
    /// Returns only signals that haven't been seen within their cooldown period.
    /// </summary>
    public List<Signal> ApplyCooldown(List<Signal> signals, string? pidContext = null)
    {
        var now = DateTime.UtcNow;
        var result = new List<Signal>();

        lock (_lock)
        {
            // Prune expired cooldowns
            PruneExpired(now);

            foreach (var signal in signals)
            {
                var cooldownKey = pidContext is not null
                    ? $"{GetBaseSignalType(signal.Type)}:{pidContext}"
                    : GetBaseSignalType(signal.Type);

                // Check if composite signal
                if (signal.Type.StartsWith("composite:", StringComparison.Ordinal))
                {
                    if (_compositeCooldowns.TryGetValue(signal.Type, out var lastComposite) &&
                        now - lastComposite < _compositeCooldown)
                    {
                        continue; // Suppress - already fired within window
                    }
                    _compositeCooldowns[signal.Type] = now;
                    result.Add(signal);
                }
                else
                {
                    if (_signalCooldowns.TryGetValue(cooldownKey, out var lastSeen) &&
                        now - lastSeen < _signalCooldown)
                    {
                        continue; // Suppress - within cooldown
                    }
                    _signalCooldowns[cooldownKey] = now;
                    result.Add(signal);
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Apply exponential decay to signal weight based on age.
    /// Newer signals have full weight; older signals fade toward zero.
    /// </summary>
    public Signal ApplyDecay(Signal signal, TimeSpan age)
    {
        if (age.TotalSeconds <= 0)
            return signal;

        // Exponential decay: weight * e^(-t),  = ln(2) / halflife
        var lambda = Math.Log(2) / _decayHalfLifeSeconds;
        var decayFactor = Math.Exp(-lambda * age.TotalSeconds);
        var decayedWeight = signal.Weight * decayFactor;

        return new Signal(signal.Type, decayedWeight, signal.Confidence);
    }

    /// <summary>
    /// Reset all cooldowns (for testing or config changes).
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _signalCooldowns.Clear();
            _compositeCooldowns.Clear();
        }
    }

    private void PruneExpired(DateTime now)
    {
        var maxAge = TimeSpan.FromSeconds(Math.Max(
            _signalCooldown.TotalSeconds, _compositeCooldown.TotalSeconds) * 2);

        var expiredSignals = _signalCooldowns
            .Where(kv => now - kv.Value > maxAge)
            .Select(kv => kv.Key).ToList();
        foreach (var key in expiredSignals)
            _signalCooldowns.Remove(key);

        var expiredComposites = _compositeCooldowns
            .Where(kv => now - kv.Value > maxAge)
            .Select(kv => kv.Key).ToList();
        foreach (var key in expiredComposites)
            _compositeCooldowns.Remove(key);
    }

    /// <summary>
    /// Extract the base signal type by stripping dynamic suffixes (PID, counts, etc.)
    /// For deduplication grouping.
    /// </summary>
    private static string GetBaseSignalType(string signalType)
    {
        // Patterns like "suspicious_process:mimikatz" -> keep full type
        // Patterns like "rwx_memory:notepad(pid:1234,regions:3)" -> strip to "rwx_memory:notepad"
        // Patterns like "process_burst:25_in_10s" -> strip to "process_burst"
        // Patterns like "beaconing_detected:1234:10.0.0.1:443(cv:0.150,obs:7)" -> strip to "beaconing_detected"

        var pidIdx = signalType.IndexOf("(pid:", StringComparison.Ordinal);
        if (pidIdx > 0) return signalType[..pidIdx];

        var cvIdx = signalType.IndexOf("(cv:", StringComparison.Ordinal);
        if (cvIdx > 0) return signalType[..cvIdx];

        // For burst patterns with numbers, keep the base prefix
        var colonIdx = signalType.IndexOf(':');
        if (colonIdx > 0)
        {
            var afterColon = signalType[(colonIdx + 1)..];
            if (afterColon.Length > 0 && char.IsDigit(afterColon[0]))
                return signalType[..colonIdx];
        }

        return signalType;
    }
}
