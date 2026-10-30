namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects short-lived "flash" processes via Windows Prefetch directory monitoring.
/// New .pf files indicate process executions that may have exited before ETW delivery.
/// Catches sub-second stagers, fast credential dumpers, and exec-and-delete payloads.
/// </summary>
[SupportedOSPlatform("windows")]
public class EphemeralProcessMonitor : IPlatformMonitor
{
    private readonly ILogger<EphemeralProcessMonitor> _logger;
    private readonly HashSet<string> _baselinePrefetch = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alertedFiles = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselined;

    private static readonly string PrefetchPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

    private static readonly HashSet<string> AllowedEphemeral = new(StringComparer.OrdinalIgnoreCase)
    {
        "CONHOST", "CONSENT", "CTFMON", "BACKGROUNDTASKHOST",
        "RUNTIMEBROKER", "APPLICATIONFRAMEHOST", "SEARCHPROTOCOLHOST",
        "SEARCHFILTERHOST", "AUDIODG", "FONTDRVHOST", "DWM",
        "WMIPRVSE", "TASKHOSTW", "SIHOST", "COMPATTELRUNNER",
        "MICROSOFTEDGEUPDATE", "GOOGLEUPDATE", "MSMPENG", "NISSRV",
    };

    public string PlatformName => "EphemeralProcessMonitor";
    public bool IsSupported => OperatingSystem.IsWindows() && Directory.Exists(PrefetchPath);

    public EphemeralProcessMonitor(ILogger<EphemeralProcessMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<EphemeralProcessMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            if (!Directory.Exists(PrefetchPath))
                return Task.FromResult<IEnumerable<Signal>>(signals);

            var currentFiles = Directory.GetFiles(PrefetchPath, "*.pf")
                .Select(Path.GetFileName)
                .Where(f => f != null)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (!_baselined)
            {
                _baselinePrefetch.UnionWith(currentFiles!);
                _baselined = true;
                return Task.FromResult<IEnumerable<Signal>>(signals);
            }

            foreach (var file in currentFiles)
            {
                if (ct.IsCancellationRequested) break;
                if (file == null) continue;
                if (_baselinePrefetch.Contains(file)) continue;
                if (_alertedFiles.Contains(file)) continue;

                _baselinePrefetch.Add(file);

                // Extract executable name from prefetch filename (FORMAT: EXENAME-HASH.pf)
                var exeName = ExtractExeName(file);
                if (string.IsNullOrEmpty(exeName)) continue;
                if (AllowedEphemeral.Contains(exeName)) continue;

                signals.Add(new Signal(
                    $"ephemeral_process:{exeName}:prefetch:{file}",
                    55, 0.65));
                _alertedFiles.Add(file);
            }

            if (_alertedFiles.Count > 500) _alertedFiles.Clear();
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[EphemeralProcessMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private static string? ExtractExeName(string prefetchFileName)
    {
        // Format: EXECUTABLENAME-HASH.pf
        var dashIdx = prefetchFileName.LastIndexOf('-');
        if (dashIdx <= 0) return null;
        return prefetchFileName[..dashIdx];
    }
}
