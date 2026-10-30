namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux sensitive-file open monitor (production, 0.3.3).
/// Primary: suite EV_OPEN events from eBPF openat.tracepoint.
/// Secondary: /proc/*/fd sampling when the suite is inactive (still real coverage).
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfFileMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxEbpfFileMonitor> _logger;
    private bool _initialized;
    private bool _suiteActive;
    private DateTime _lastProcScan = DateTime.MinValue;
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly TimeSpan _procInterval = TimeSpan.FromSeconds(3);

    private static readonly string[] SensitivePaths =
    [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
        "/etc/crontab", "/var/spool/cron",
        "/etc/ld.so.preload", "/var/run/secrets",
        "/etc/kubernetes",
    ];

    public string PlatformName => "LinuxEbpfFile";
    public bool IsSupported => OperatingSystem.IsLinux();
    public bool IsActive => _suiteActive;
    public string ActiveMode => _suiteActive ? "suite-openat" : "proc-fd-sample";

    public LinuxEbpfFileMonitor(ILogger<LinuxEbpfFileMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxEbpfFileMonitor>.Instance;
    }

    public bool TryInitialize()
    {
        if (_initialized) return _suiteActive;
        _initialized = true;
        if (!OperatingSystem.IsLinux()) return false;
        _suiteActive = LinuxEbpfSuite.Shared(_logger).TryStart();
        _logger.LogInformation("[eBPF-file] Mode={Mode}", ActiveMode);
        return _suiteActive;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        if (!_initialized)
            TryInitialize();

        var signals = new List<Signal>();

        if (_suiteActive)
            DrainSuiteOpen(signals);
        else
            SampleProcFds(signals);

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void DrainSuiteOpen(List<Signal> signals)
    {
        var batch = LinuxEbpfSuite.Shared().DrainOpen();
        foreach (var e in batch)
        {
            if (e.Pid <= 1) continue;
            var comm = string.IsNullOrEmpty(e.Comm) ? "unknown" : e.Comm;
            var path = e.Path ?? "";

            // Suite already filters to sensitive paths; emit high-confidence signals only
            signals.Add(new Signal(
                $"ebpf_sensitive_open:{comm}:pid:{e.Pid}:{Truncate(path, 48)}",
                88, 0.92));
        }
    }

    private void SampleProcFds(List<Signal> signals)
    {
        if ((DateTime.UtcNow - _lastProcScan) < _procInterval)
            return;
        _lastProcScan = DateTime.UtcNow;

        try
        {
            int scanned = 0;
            foreach (var procDir in Directory.EnumerateDirectories("/proc"))
            {
                if (scanned > 80) break;
                var name = Path.GetFileName(procDir);
                if (!int.TryParse(name, out var pid) || pid <= 1) continue;
                scanned++;

                var fdDir = Path.Combine(procDir, "fd");
                if (!Directory.Exists(fdDir)) continue;

                try
                {
                    foreach (var fd in Directory.EnumerateFileSystemEntries(fdDir).Take(32))
                    {
                        string? target = null;
                        try { target = File.ResolveLinkTarget(fd, returnFinalTarget: true)?.FullName; }
                        catch { continue; }
                        if (string.IsNullOrEmpty(target) || !IsSensitive(target))
                            continue;

                        var key = $"{pid}:{target}";
                        if (!_seen.Add(key)) continue;
                        if (_seen.Count > 5000) _seen.Clear();

                        signals.Add(new Signal(
                            $"ebpf_file_sensitive_open:pid:{pid}:{Path.GetFileName(target)}",
                            85, 0.9));
                    }
                }
                catch { /* permission */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[eBPF-file] proc sample error");
        }
    }

    private static bool IsSensitive(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        foreach (var sens in SensitivePaths)
        {
            if (path.StartsWith(sens, StringComparison.Ordinal) ||
                string.Equals(path, sens, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= n ? s : s[..n];
}
