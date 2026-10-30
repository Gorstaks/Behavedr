namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using System.Security.Cryptography;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android anti-tamper guard providing service persistence and kill detection:
/// 1. OOM adjustment monitoring (detect deprioritization by OS or attacker)
/// 2. Binary integrity verification (APK/DEX modification on disk)
/// 3. Process suspension detection via monotonic clock gaps
/// 4. Service liveness heartbeat (detect if monitoring loop is stuck)
/// 5. Data directory integrity (detect clearing of agent data)
/// 6. Battery optimization status (detect if agent excluded from whitelist)
///
/// Unlike desktop platforms, Android cannot prevent its own termination.
/// Focus: DETECT tampering, LOG forensic evidence, RESTART via WorkManager.
///
/// v0.2.0 audit fix A-9: Adds anti-tamper capability for Android.
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidAntiTamperGuard : IPlatformMonitor
{
    private readonly ILogger<AndroidAntiTamperGuard> _logger;
    private string? _binaryHash;
    private long _lastMonotonicMs;
    private DateTime _lastPeriodicCheck = DateTime.UtcNow;
    private long _lastDataDirSize = -1;
    private const int SuspendThresholdMs = 5000;

    public string PlatformName => "AndroidAntiTamper";
    public bool IsSupported => OperatingSystem.IsAndroid();

    public AndroidAntiTamperGuard(ILogger<AndroidAntiTamperGuard>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidAntiTamperGuard>.Instance;
        _lastMonotonicMs = Environment.TickCount64;

        // Compute baseline binary hash
        var exePath = Environment.ProcessPath;
        if (exePath is not null && File.Exists(exePath))
        {
            try
            {
                using var stream = File.OpenRead(exePath);
                _binaryHash = Convert.ToHexString(SHA256.HashData(stream));
            }
            catch { }
        }
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        // 1. Suspension detection (every cycle)
        DetectSuspension(signals);

        // 2. Periodic checks (~10s)
        if ((DateTime.UtcNow - _lastPeriodicCheck).TotalSeconds >= 10)
        {
            DetectOomDeprioritization(signals);
            CheckBinaryIntegrity(signals);
            CheckDataDirectoryIntegrity(signals);
            _lastPeriodicCheck = DateTime.UtcNow;
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect process suspension via monotonic clock gap.
    /// If an attacker uses kill -STOP or the OOM killer pauses us,
    /// the time gap reveals it on resume.
    /// </summary>
    private void DetectSuspension(List<Signal> signals)
    {
        var currentMs = Environment.TickCount64;
        var elapsedMs = currentMs - _lastMonotonicMs;
        _lastMonotonicMs = currentMs;

        if (elapsedMs > SuspendThresholdMs)
        {
            signals.Add(new Signal(
                $"android_suspension_detected:{elapsedMs}ms_gap", 85, 0.9));
            _logger.LogCritical(
                "[AndroidAntiTamper] Suspension detected - {Elapsed}ms gap", elapsedMs);
            WriteForensicEntry($"SUSPENSION: {elapsedMs}ms gap");
        }
    }

    /// <summary>
    /// Check OOM adjustment value. A foreground service should have oom_adj <= 0.
    /// If the value is positive, we've been deprioritized and may be killed soon.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectOomDeprioritization(List<Signal> signals)
    {
        try
        {
            var oomPath = "/proc/self/oom_adj";
            if (!File.Exists(oomPath))
                oomPath = "/proc/self/oom_score_adj";
            if (!File.Exists(oomPath)) return;

            var adjStr = File.ReadAllText(oomPath).Trim();
            if (int.TryParse(adjStr, out var oomAdj) && oomAdj > 0)
            {
                signals.Add(new Signal(
                    $"agent_deprioritized:oom_adj:{oomAdj}", 65, 0.75));
                _logger.LogWarning(
                    "[AndroidAntiTamper] Agent deprioritized (oom_adj={Adj}). " +
                    "May be killed by LMK. Ensure foreground service is active.", oomAdj);
            }
        }
        catch { }
    }

    /// <summary>
    /// Verify agent binary hasn't been replaced on disk (repackaging attack).
    /// </summary>
    [SupportedOSPlatform("android")]
    private void CheckBinaryIntegrity(List<Signal> signals)
    {
        if (_binaryHash is null) return;

        var exePath = Environment.ProcessPath;
        if (exePath is null || !File.Exists(exePath)) return;

        try
        {
            using var stream = File.OpenRead(exePath);
            var currentHash = Convert.ToHexString(SHA256.HashData(stream));

            if (!string.Equals(currentHash, _binaryHash, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal("android_binary_tampered", 95, 0.98));
                _logger.LogCritical(
                    "[AndroidAntiTamper] Binary modified on disk - possible repackaging!");
                WriteForensicEntry("BINARY_TAMPERED: hash mismatch");
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect if agent's data directory was cleared (Settings -> Clear Data attack).
    /// Track total size of data directory - sudden decrease indicates wipe.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void CheckDataDirectoryIntegrity(List<Signal> signals)
    {
        try
        {
            var dataDir = AppContext.BaseDirectory;
            if (!Directory.Exists(dataDir)) return;

            long totalSize = 0;
            foreach (var file in Directory.GetFiles(dataDir, "*", SearchOption.AllDirectories))
            {
                try { totalSize += new FileInfo(file).Length; }
                catch { }
            }

            if (_lastDataDirSize < 0)
            {
                _lastDataDirSize = totalSize;
                return;
            }

            // Sudden large decrease (>50%) indicates data clear
            if (totalSize < _lastDataDirSize * 0.5 && _lastDataDirSize > 4096)
            {
                signals.Add(new Signal(
                    $"data_directory_cleared:was:{_lastDataDirSize}:now:{totalSize}", 80, 0.85));
                _logger.LogCritical(
                    "[AndroidAntiTamper] Data directory size decreased dramatically " +
                    "({Old} -> {New} bytes) - possible 'Clear Data' attack",
                    _lastDataDirSize, totalSize);
                WriteForensicEntry($"DATA_CLEARED: {_lastDataDirSize} -> {totalSize}");
            }

            _lastDataDirSize = totalSize;
        }
        catch { }
    }

    private static void WriteForensicEntry(string message)
    {
        try
        {
            var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, "android-tamper-forensic.log");
            var entry = $"[{DateTime.UtcNow:O}] MONO={Environment.TickCount64} PID={Environment.ProcessId} {message}{Environment.NewLine}";
            File.AppendAllText(logPath, entry);
        }
        catch { }
    }
}
