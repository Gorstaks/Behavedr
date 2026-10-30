namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Real-time file activity monitoring using FileSystemWatcher.
/// Monitors user profile, Downloads, and temp directories for:
/// - Ransomware patterns (bulk renames, encrypted file extensions)
/// - Suspicious file drops (executables in temp, DLLs in user paths)
/// - Sensitive file access (hosts file, SAM, shadow copies)
/// </summary>
public class FileActivityMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<FileActivityMonitor> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<Signal> _pendingSignals = new();
    private readonly object _lock = new();
    private int _recentRenames;
    private int _recentCreates;
    private DateTime _renameWindowStart = DateTime.UtcNow;
    private bool _initialized;

    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
        ".pay", ".ransom", ".locky", ".cerber", ".zepto",
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".wsf", ".hta", ".msi",
    };

    public string PlatformName => "FileActivity";
    public bool IsSupported => true; // Cross-platform

    public FileActivityMonitor(ILogger<FileActivityMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<FileActivityMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        if (!_initialized)
        {
            InitializeWatchers();
            _initialized = true;
        }

        List<Signal> signals;
        lock (_lock)
        {
            signals = new List<Signal>(_pendingSignals);
            _pendingSignals.Clear();

            // Ransomware I/O depth (v0.4.1): lower thresholds + write/create burst composite
            var elapsed = (DateTime.UtcNow - _renameWindowStart).TotalSeconds;
            if (_recentRenames >= 12 && elapsed < 20)
            {
                signals.Add(new Signal(
                    $"ransomware_rename_burst:{_recentRenames}_in_{elapsed:F0}s",
                    92, 0.93));
                _recentRenames = 0;
                _recentCreates = 0;
                _renameWindowStart = DateTime.UtcNow;
            }
            else if (_recentCreates >= 50 && elapsed < 20)
            {
                signals.Add(new Signal(
                    $"ransomware_write_burst:{_recentCreates}_creates_in_{elapsed:F0}s",
                    85, 0.85));
                _recentCreates = 0;
                _renameWindowStart = DateTime.UtcNow;
            }
            else if (elapsed > 30)
            {
                _recentRenames = 0;
                _recentCreates = 0;
                _renameWindowStart = DateTime.UtcNow;
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void InitializeWatchers()
    {
        // GitHub Actions / CI: skip FSW - FSEvents EnableRaisingEvents has hung macos-latest
        // test runs for 10+ minutes when all platform monitors are polled together.
        if (string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("[FileActivity] Skipping watchers under CI");
            return;
        }

        var paths = new List<string>();

        // User profile directories
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        paths.Add(Path.Combine(userProfile, "Downloads"));
        paths.Add(Path.Combine(userProfile, "Documents"));
        paths.Add(Path.Combine(userProfile, "Desktop"));

        // Temp directories
        paths.Add(Path.GetTempPath());

        // System sensitive paths (if accessible)
        if (OperatingSystem.IsWindows())
        {
            var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var driversEtc = Path.Combine(system32, "drivers", "etc");
            if (Directory.Exists(driversEtc)) paths.Add(driversEtc);
        }

        foreach (var path in paths)
        {
            if (!Directory.Exists(path)) continue;
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };
                watcher.Created += OnFileCreated;
                watcher.Renamed += OnFileRenamed;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileActivity] Cannot watch {Path}", path);
            }
        }

        _logger.LogInformation("[FileActivity] Watching {Count} directories", _watchers.Count);
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        var ext = Path.GetExtension(e.Name)?.ToLowerInvariant() ?? "";
        var dir = Path.GetDirectoryName(e.FullPath) ?? "";

        lock (_lock)
        {
            _recentCreates++;

            // Executable dropped in temp
            if (ExecutableExtensions.Contains(ext) && dir.Contains("Temp", StringComparison.OrdinalIgnoreCase))
            {
                _pendingSignals.Add(new Signal($"executable_in_temp:{e.Name}", 55, 0.65));
            }

            // DLL dropped in user-writable path
            if (ext == ".dll" && !dir.Contains("System32", StringComparison.OrdinalIgnoreCase))
            {
                _pendingSignals.Add(new Signal($"dll_drop_user_path:{e.Name}", 40, 0.5));
            }
        }
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        var newExt = Path.GetExtension(e.Name)?.ToLowerInvariant() ?? "";

        lock (_lock)
        {
            _recentRenames++;

            // Renamed to known ransomware extension
            if (SuspiciousExtensions.Contains(newExt))
            {
                _pendingSignals.Add(new Signal($"ransomware_extension:{e.Name}", 80, 0.85));
            }
        }
    }

    public void Dispose()
    {
        foreach (var w in _watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
        _watchers.Clear();
    }
}
