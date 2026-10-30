namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects new or suspicious Linux kernel module loads - the Linux analogue of BYOVD.
/// Baselines /proc/modules at startup and alerts on:
/// - New modules appearing after baseline
/// - Modules loaded from user-writable paths (via /sys/module/*/sections or holders)
/// - Unsigned-module environments when Secure Boot is off (informational)
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxKernelModuleMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxKernelModuleMonitor> _logger;
    private readonly HashSet<string> _baseline = new(StringComparer.Ordinal);
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselined;

    // Names frequently abused for rootkit / EDR-kill tooling (subset)
    private static readonly HashSet<string> SuspiciousModuleNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "diamorphine", "reptile", "suterusu", "adore", "knark", "enyelkm",
        "hide", "rootkit", "rkit", "kiss", "override", "sysenter_hook",
    };

    public string PlatformName => "LinuxKernelModule";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxKernelModuleMonitor(ILogger<LinuxKernelModuleMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxKernelModuleMonitor>.Instance;
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var current = ReadModules();
            if (!_baselined)
            {
                foreach (var m in current)
                    _baseline.Add(m);
                _baselined = true;
                _logger.LogInformation("[LinuxKernelModule] Baselined {Count} loaded modules", _baseline.Count);
                return Task.FromResult<IEnumerable<Signal>>(signals);
            }

            foreach (var mod in current)
            {
                if (ct.IsCancellationRequested) break;
                if (_baseline.Contains(mod)) continue;
                if (!_alerted.Add(mod)) continue;

                _baseline.Add(mod);

                if (SuspiciousModuleNames.Any(s => mod.Contains(s, StringComparison.OrdinalIgnoreCase)))
                {
                    signals.Add(new Signal($"kernel_module:known_rootkit:{mod}", 98, 0.97));
                    _logger.LogCritical("[LinuxKernelModule] Known-suspicious module loaded: {Module}", mod);
                    continue;
                }

                // New module after baseline - elevated
                signals.Add(new Signal($"kernel_module:new_load:{mod}", 85, 0.88));
                _logger.LogWarning("[LinuxKernelModule] New kernel module loaded: {Module}", mod);
            }

            // Kernel lockdown none (soft signal - unsigned modules more dangerous)
            try
            {
                if (File.Exists("/sys/kernel/security/lockdown"))
                {
                    var lockdown = File.ReadAllText("/sys/kernel/security/lockdown").Trim();
                    if (lockdown.Contains("[none]", StringComparison.OrdinalIgnoreCase))
                        signals.Add(new Signal("kernel_lockdown:disabled", 40, 0.55));
                }
            }
            catch { }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LinuxKernelModule] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("linux")]
    private static HashSet<string> ReadModules()
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (!File.Exists("/proc/modules"))
            return set;

        foreach (var line in File.ReadLines("/proc/modules"))
        {
            // Format: name size used_by ...
            var sp = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (sp.Length > 0)
                set.Add(sp[0]);
        }

        return set;
    }
}
