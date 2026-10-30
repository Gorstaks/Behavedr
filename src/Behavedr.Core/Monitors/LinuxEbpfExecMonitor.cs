namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux eBPF process-exec monitor (production path, 0.3.3).
/// Consumes <see cref="LinuxEbpfSuite"/> EV_EXEC events (pinned maps + CO-RE object).
/// Soft-fails cleanly so <see cref="LinuxProcessConnector"/> remains primary coverage.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfExecMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<LinuxEbpfExecMonitor> _logger;
    private bool _initialized;
    private bool _active;

    public string PlatformName => "LinuxEbpfExec";
    public bool IsSupported => OperatingSystem.IsLinux();
    public bool IsActive => _active;
    public string ActiveMode => _active
        ? LinuxEbpfSuite.Shared().ActiveMode
        : "inactive";

    public LinuxEbpfExecMonitor(ILogger<LinuxEbpfExecMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxEbpfExecMonitor>.Instance;
    }

    public bool TryInitialize()
    {
        if (_initialized) return _active;
        _initialized = true;
        if (!OperatingSystem.IsLinux()) return false;

        _active = LinuxEbpfSuite.Shared(_logger).TryStart();
        if (_active)
            _logger.LogInformation("[eBPF-exec] Subscribed to suite EV_EXEC");
        return _active;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        if (!_initialized)
            TryInitialize();

        var signals = new List<Signal>();
        if (!_active)
            return Task.FromResult<IEnumerable<Signal>>(signals); // cn_proc is primary; no per-cycle noise

        var batch = LinuxEbpfSuite.Shared().DrainExec();
        foreach (var e in batch)
        {
            if (e.Pid <= 1) continue;
            var comm = string.IsNullOrEmpty(e.Comm) ? "unknown" : e.Comm;
            var pathPart = string.IsNullOrEmpty(e.Path) ? "" : $":{Truncate(e.Path, 64)}";

            // Low-weight exec telemetry (renames don't erase path heuristics)
            signals.Add(new Signal($"ebpf_exec:{comm}:pid:{e.Pid}{pathPart}", 18, 0.55));

            var off = ThreatHeuristics.Evaluate(comm, e.Path);
            if (off is { } o)
            {
                signals.Add(new Signal(
                    $"ebpf_offensive:{o.Tag}:{o.Detail}:pid:{e.Pid}",
                    o.Weight, o.Confidence));
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    public void Dispose()
    {
        // Suite is process-shared; do not dispose it here.
        _active = false;
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= n ? s : s[..n];
}
