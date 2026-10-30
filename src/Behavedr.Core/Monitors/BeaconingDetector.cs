namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Statistical C2 beacon detection via connection interval analysis.
/// Tracks connection timestamps per (PID, RemoteAddress, Port) tuple.
/// Fires when coefficient of variation (CV) of intervals is below 0.40
/// with 5+ observations - indicating periodic automated check-ins.
///
/// CV = stddev / mean. Regular beacons have low CV (high regularity).
/// Human browsing has high CV (irregular timing).
///
/// Cross-platform: works on Windows, Linux, and macOS.
/// </summary>
public class BeaconingDetector : IPlatformMonitor
{
    private readonly ILogger<BeaconingDetector> _logger;
    private readonly Dictionary<string, List<long>> _connectionTimestamps = new();
    private readonly object _lock = new();
    private const int MinObservations = 5;
    private const double CvThreshold = 0.40;
    private const int MaxTrackedConnections = 5000;

    public string PlatformName => "BeaconingDetector";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public BeaconingDetector(ILogger<BeaconingDetector>? logger = null)
    {
        _logger = logger ?? NullLogger<BeaconingDetector>.Instance;
    }

    /// <summary>
    /// Record a connection observation for beaconing analysis.
    /// Call from NetworkMonitor when established connections are seen.
    /// Uses monotonic clock (Environment.TickCount64) to prevent evasion via
    /// system clock manipulation. An attacker adjusting wall clock cannot disrupt
    /// interval regularity detection.
    /// </summary>
    public void RecordConnection(int pid, string remoteAddr, int remotePort)
    {
        var key = $"{pid}:{remoteAddr}:{remotePort}";
        lock (_lock)
        {
            if (!_connectionTimestamps.TryGetValue(key, out var timestamps))
            {
                if (_connectionTimestamps.Count >= MaxTrackedConnections)
                {
                    // Evict oldest entries
                    var oldest = _connectionTimestamps.OrderBy(kv => kv.Value.LastOrDefault()).Take(1000).Select(kv => kv.Key).ToList();
                    foreach (var k in oldest) _connectionTimestamps.Remove(k);
                }
                timestamps = new List<long>();
                _connectionTimestamps[key] = timestamps;
            }
            timestamps.Add(Environment.TickCount64);

            // Keep only last 60 observations
            if (timestamps.Count > 60)
                timestamps.RemoveRange(0, timestamps.Count - 60);
        }
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        lock (_lock)
        {
            foreach (var (key, timestamps) in _connectionTimestamps)
            {
                if (ct.IsCancellationRequested) break;
                if (timestamps.Count < MinObservations) continue;

                var cv = CalculateCv(timestamps);
                if (cv < CvThreshold && cv >= 0)
                {
                    var confidence = cv switch
                    {
                        < 0.10 => 0.95,
                        < 0.20 => 0.85,
                        < 0.30 => 0.75,
                        _ => 0.65
                    };

                    signals.Add(new Signal(
                        $"beaconing_detected:{key}(cv:{cv:F3},obs:{timestamps.Count})",
                        70, confidence));
                }
            }

            // Prune entries older than 10 minutes (600,000 ms monotonic)
            var cutoffMs = Environment.TickCount64 - 600_000;
            var toRemove = _connectionTimestamps
                .Where(kv => kv.Value.All(t => t < cutoffMs))
                .Select(kv => kv.Key).ToList();
            foreach (var k in toRemove) _connectionTimestamps.Remove(k);
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private static double CalculateCv(List<long> timestamps)
    {
        if (timestamps.Count < 2) return -1;

        var intervals = new List<double>();
        for (int i = 1; i < timestamps.Count; i++)
        {
            intervals.Add((timestamps[i] - timestamps[i - 1]) / 1000.0); // Convert ms to seconds
        }

        if (intervals.Count == 0) return -1;

        var mean = intervals.Average();
        if (mean < 1.0) return -1; // Sub-second intervals are noise

        var variance = intervals.Sum(x => Math.Pow(x - mean, 2)) / intervals.Count;
        var stddev = Math.Sqrt(variance);

        return stddev / mean; // Coefficient of Variation
    }
}
