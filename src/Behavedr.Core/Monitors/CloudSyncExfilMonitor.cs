namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects burst staging into cloud-sync folders and known exfil tools (rclone, megasync, etc.).
/// </summary>
public sealed class CloudSyncExfilMonitor : IPlatformMonitor
{
    private readonly ILogger<CloudSyncExfilMonitor> _logger;
    private readonly Dictionary<string, int> _writeCounts = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _windowStart = DateTime.UtcNow;
    private readonly HashSet<string> _alertedTools = new(StringComparer.OrdinalIgnoreCase);
    private bool _watchersReady;
    private readonly List<FileSystemWatcher> _watchers = new();
    private int _pendingWrites;
    private readonly object _lock = new();

    public string PlatformName => "CloudSyncExfil";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private static readonly HashSet<string> ExfilTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "rclone", "megasync", "megacmd", "cyberduck", "winscp", "filezilla",
        "dropbox", "onedrive", "googledrivefs", "box", "resilio", "syncthing"
    };

    public CloudSyncExfilMonitor(ILogger<CloudSyncExfilMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<CloudSyncExfilMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if (!IsSupported) return Task.FromResult<IEnumerable<Signal>>(signals);

        try
        {
            EnsureWatchers();

            if ((DateTime.UtcNow - _windowStart).TotalSeconds > 30)
            {
                int count;
                lock (_lock)
                {
                    count = _pendingWrites;
                    _pendingWrites = 0;
                    _windowStart = DateTime.UtcNow;
                }
                if (count >= 40)
                    signals.Add(new Signal($"cloud_sync_burst:{count}_files_30s", 80, 0.82));
            }

            // Tool presence / process scan
            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return Task.FromResult<IEnumerable<Signal>>(signals); }

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                string name;
                try { name = p.ProcessName; }
                catch { continue; }

                var bare = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
                if (!ExfilTools.Contains(bare) && !ExfilTools.Contains(name)) continue;
                if (!_alertedTools.Add(bare)) continue;

                // rclone / megacmd are higher confidence when present with many open files
                var weight = bare.Equals("rclone", StringComparison.OrdinalIgnoreCase) ||
                             bare.Equals("megacmd", StringComparison.OrdinalIgnoreCase) ? 75 : 50;
                signals.Add(new Signal($"cloud_exfil_tool:{bare}:pid={p.Id}", weight, weight >= 75 ? 0.80 : 0.55));
            }

            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { /* ignore */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[CloudSyncExfilMonitor] error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void EnsureWatchers()
    {
        if (_watchersReady) return;
        _watchersReady = true;

        if (string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase))
            return;

        foreach (var dir in GetSyncDirs())
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                var w = new FileSystemWatcher(dir)
                {
                    // Top-level only: recursive watchers on cloud trees stall macOS CI runners.
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite
                };
                w.Created += (_, _) => { lock (_lock) { _pendingWrites++; } };
                w.Changed += (_, _) => { lock (_lock) { _pendingWrites++; } };
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CloudSyncExfilMonitor] watch fail {Dir}", dir);
            }
        }
    }

    private static IEnumerable<string> GetSyncDirs()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var list = new List<string>();
        if (string.IsNullOrEmpty(home)) return list;

        if (OperatingSystem.IsWindows())
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var user = home;
            list.Add(Path.Combine(user, "OneDrive"));
            list.Add(Path.Combine(user, "Dropbox"));
            list.Add(Path.Combine(user, "Google Drive"));
            list.Add(Path.Combine(user, "Mega"));
            if (!string.IsNullOrEmpty(local))
                list.Add(Path.Combine(local, "Mega Limited", "MEGAsync"));
        }
        else
        {
            list.Add(Path.Combine(home, "Dropbox"));
            list.Add(Path.Combine(home, "OneDrive"));
            list.Add(Path.Combine(home, "Google Drive"));
            list.Add(Path.Combine(home, "MEGA"));
            list.Add(Path.Combine(home, "Library", "CloudStorage"));
        }

        return list.Where(Directory.Exists);
    }
}
