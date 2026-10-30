namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Plants hidden canary files; any delete/modify is a high-confidence ransomware signal.
/// Cross-platform (Desktop/Documents/home).
/// </summary>
public sealed class CanaryFileMonitor : IPlatformMonitor
{
    private readonly ILogger<CanaryFileMonitor> _logger;
    private readonly List<string> _canaries = new();
    private readonly Dictionary<string, DateTime> _writeTimes = new(StringComparer.OrdinalIgnoreCase);
    private bool _planted;

    public string PlatformName => "CanaryFile";
    public bool IsSupported => true;

    public CanaryFileMonitor(ILogger<CanaryFileMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<CanaryFileMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        try
        {
            if (!_planted)
            {
                Plant();
                _planted = true;
            }

            foreach (var path in _canaries.ToArray())
            {
                if (ct.IsCancellationRequested) break;
                if (!File.Exists(path))
                {
                    signals.Add(new Signal($"canary_deleted:{path}", 95, 0.95));
                    _canaries.Remove(path);
                    _writeTimes.Remove(path);
                    continue;
                }

                try
                {
                    var wt = File.GetLastWriteTimeUtc(path);
                    if (_writeTimes.TryGetValue(path, out var baseline) && wt > baseline.AddSeconds(1))
                    {
                        signals.Add(new Signal($"canary_modified:{path}", 92, 0.93));
                        _writeTimes[path] = wt;
                    }
                }
                catch { /* ignore */ }
            }

            // Replant if all consumed
            if (_canaries.Count == 0)
            {
                Plant();
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[CanaryFileMonitor] error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void Plant()
    {
        var dirs = new List<string?>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        };

        foreach (var dir in dirs)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            try
            {
                var name = OperatingSystem.IsWindows() ? ".~behavedr_canary.tmp" : ".behavedr_canary";
                var path = Path.Combine(dir, name);
                if (!File.Exists(path))
                {
                    File.WriteAllText(path, "BEHAVEDR_CANARY_DO_NOT_DELETE");
                    if (OperatingSystem.IsWindows())
                    {
                        try { File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System); }
                        catch { /* best effort */ }
                    }
                    else
                    {
                        // Unix: leading-dot already hidden
                    }
                }
                _canaries.Add(path);
                _writeTimes[path] = File.GetLastWriteTimeUtc(path);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CanaryFileMonitor] plant failed in {Dir}", dir);
            }
        }
    }
}
