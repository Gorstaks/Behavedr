namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux authentication / privilege-escalation telemetry from auth logs.
/// Watches auth.log / secure for failed sudo/sshd bursts and root sessions.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxAuthMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxAuthMonitor> _logger;
    private readonly Dictionary<string, long> _offsets = new(StringComparer.Ordinal);
    private int _recentFailures;
    private DateTime _failureWindowStart = DateTime.UtcNow;

    private static readonly string[] AuthLogCandidates =
    [
        "/var/log/auth.log",
        "/var/log/secure",
    ];

    public string PlatformName => "LinuxAuth";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxAuthMonitor(ILogger<LinuxAuthMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxAuthMonitor>.Instance;
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            foreach (var path in AuthLogCandidates)
            {
                if (ct.IsCancellationRequested) break;
                if (!File.Exists(path)) continue;
                ScanLog(path, signals, ct);
            }

            if ((DateTime.UtcNow - _failureWindowStart).TotalSeconds > 60)
            {
                _recentFailures = 0;
                _failureWindowStart = DateTime.UtcNow;
            }

            if (_recentFailures >= 8)
            {
                signals.Add(new Signal($"auth_bruteforce:failures:{_recentFailures}", 75, 0.82));
                _recentFailures = 0;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxAuth] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("linux")]
    private void ScanLog(string path, List<Signal> signals, CancellationToken ct)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!_offsets.TryGetValue(path, out var offset))
            {
                _offsets[path] = fi.Length; // baseline: skip history
                return;
            }

            if (fi.Length < offset)
                offset = 0; // rotated

            if (fi.Length == offset)
                return;

            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            fs.Seek(offset, SeekOrigin.Begin);
            using var reader = new StreamReader(fs);

            while (!reader.EndOfStream && !ct.IsCancellationRequested)
            {
                var line = reader.ReadLine();
                if (string.IsNullOrEmpty(line)) continue;
                AnalyzeLine(line, signals);
            }

            _offsets[path] = fs.Position;
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException ex)
        {
            _logger.LogDebug(ex, "[LinuxAuth] IO error reading {Path}", path);
        }
    }

    private void AnalyzeLine(string line, List<Signal> signals)
    {
        var lower = line.ToLowerInvariant();

        if (lower.Contains("failed password") ||
            lower.Contains("authentication failure") ||
            lower.Contains("invalid user"))
        {
            _recentFailures++;
            return;
        }

        if (lower.Contains("session opened for user root") ||
            (lower.Contains("sudo:") && lower.Contains(" root ") && lower.Contains("command=")))
        {
            signals.Add(new Signal("auth_root_session", 55, 0.7));
            return;
        }

        if (lower.Contains("accepted publickey for root") ||
            lower.Contains("accepted password for root"))
        {
            signals.Add(new Signal("auth_root_ssh_login", 80, 0.88));
        }
    }
}
