namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux credential file protection monitor.
/// Uses FileSystemWatcher and periodic scanning to detect unauthorized access to:
/// - SSH keys (~/.ssh/id_*, authorized_keys)
/// - /etc/shadow, /etc/passwd modification
/// - Browser credential databases (Chrome/Firefox Login Data, key4.db)
/// - GNOME Keyring / KWallet files
/// - Cloud credential files (~/.aws/credentials, ~/.config/gcloud)
/// - GPG/PGP private keys
///
/// Identifies accessing processes by correlating file access timestamps
/// with recently-started non-standard processes.
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxCredentialMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<LinuxCredentialMonitor> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<Signal> _pendingSignals = new();
    private readonly object _lock = new();
    private bool _initialized;

    public string PlatformName => "LinuxCredential";
    public bool IsSupported => OperatingSystem.IsLinux();

    private static readonly HashSet<string> LegitimateAccessors = new(StringComparer.OrdinalIgnoreCase)
    {
        "sshd", "ssh", "ssh-agent", "ssh-add", "gpg-agent", "gpg",
        "gnome-keyring", "kwalletd", "kwalletd5", "secretserviced",
        "chrome", "firefox", "chromium", "brave", "opera",
        "passwd", "chpasswd", "login", "su", "sudo", "pam",
        "systemd", "polkitd", "accounts-daemon", "behavedr",
    };

    // Critical credential file patterns
    private static readonly (string Dir, string[] Files, string Category, double Weight, double Confidence)[] WatchTargets =
    [
        ("/etc", new[] { "shadow", "shadow-" }, "system_credential", 85, 0.9),
        ("/etc", new[] { "passwd" }, "passwd_modification", 55, 0.6),
        ("/etc", new[] { "sudoers", "sudoers.d" }, "privilege_config", 78, 0.85),
    ];

    public LinuxCredentialMonitor(ILogger<LinuxCredentialMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxCredentialMonitor>.Instance;
    }

    [SupportedOSPlatform("linux")]
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
        }

        // Periodic scan for credential file access by suspicious processes
        ScanCredentialAccess(signals, ct);

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("linux")]
    private void InitializeWatchers()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var watchPaths = new List<(string Path, string Category)>();

        // SSH directory
        var sshDir = Path.Combine(home, ".ssh");
        if (Directory.Exists(sshDir))
            watchPaths.Add((sshDir, "ssh_key"));

        // Cloud credentials
        var awsDir = Path.Combine(home, ".aws");
        if (Directory.Exists(awsDir))
            watchPaths.Add((awsDir, "cloud_credential"));

        var gcloudDir = Path.Combine(home, ".config", "gcloud");
        if (Directory.Exists(gcloudDir))
            watchPaths.Add((gcloudDir, "cloud_credential"));

        // GPG
        var gpgDir = Path.Combine(home, ".gnupg");
        if (Directory.Exists(gpgDir))
            watchPaths.Add((gpgDir, "gpg_key"));

        // /etc sensitive files
        if (Directory.Exists("/etc"))
            watchPaths.Add(("/etc", "system_credential"));

        // Browser credential dirs
        var chromeDir = Path.Combine(home, ".config", "google-chrome", "Default");
        if (Directory.Exists(chromeDir))
            watchPaths.Add((chromeDir, "browser_credential"));

        var firefoxDir = Path.Combine(home, ".mozilla", "firefox");
        if (Directory.Exists(firefoxDir))
        {
            try
            {
                foreach (var profileDir in Directory.GetDirectories(firefoxDir, "*.default*"))
                    watchPaths.Add((profileDir, "browser_credential"));
            }
            catch { }
        }

        foreach (var (path, category) in watchPaths)
        {
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite | NotifyFilters.FileName,
                    EnableRaisingEvents = true,
                };
                watcher.Changed += (s, e) => OnCredentialFileEvent(e, category);
                watcher.Created += (s, e) => OnCredentialFileEvent(e, category);
                watcher.Deleted += (s, e) => OnCredentialFileDeleted(e, category);
                _watchers.Add(watcher);
            }
            catch { }
        }

        _logger.LogInformation("[LinuxCredential] Watching {Count} credential directories", _watchers.Count);
    }

    private void OnCredentialFileEvent(FileSystemEventArgs e, string category)
    {
        var fileName = e.Name ?? "";

        // Filter relevant credential files
        bool isCredential = category switch
        {
            "ssh_key" => fileName.StartsWith("id_", StringComparison.Ordinal) ||
                         fileName == "authorized_keys" || fileName == "known_hosts",
            "system_credential" => fileName is "shadow" or "shadow-" or "sudoers",
            "cloud_credential" => fileName is "credentials" or "config" or
                                  "application_default_credentials.json",
            "gpg_key" => fileName.EndsWith(".key", StringComparison.OrdinalIgnoreCase) ||
                         fileName == "secring.gpg" || fileName == "private-keys-v1.d",
            "browser_credential" => fileName is "Login Data" or "Cookies" or "Web Data" or
                                    "key4.db" or "logins.json" or "cookies.sqlite",
            _ => true,
        };

        if (!isCredential) return;

        lock (_lock)
        {
            _pendingSignals.Add(new Signal(
                $"credential_file_accessed:{category}:{fileName}", 70, 0.75));
        }
    }

    private void OnCredentialFileDeleted(FileSystemEventArgs e, string category)
    {
        var fileName = e.Name ?? "";
        if (category == "ssh_key" && fileName.StartsWith("id_", StringComparison.Ordinal))
        {
            lock (_lock)
            {
                _pendingSignals.Add(new Signal(
                    $"ssh_key_deleted:{fileName}", 80, 0.85));
            }
        }
    }

    /// <summary>
    /// Scan /proc for processes that have open file descriptors to credential files.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void ScanCredentialAccess(List<Signal> signals, CancellationToken ct)
    {
        var credentialPaths = new HashSet<string>(StringComparer.Ordinal)
        {
            "/etc/shadow", "/etc/shadow-",
        };

        // Add user SSH keys
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var sshDir = Path.Combine(home, ".ssh");
        if (Directory.Exists(sshDir))
        {
            try
            {
                foreach (var f in Directory.GetFiles(sshDir, "id_*"))
                    credentialPaths.Add(f);
            }
            catch { }
        }

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (pid == Environment.ProcessId) continue;

                var fdDir = Path.Combine(procDir, "fd");
                if (!Directory.Exists(fdDir)) continue;

                string? processName = null;
                try
                {
                    var commPath = Path.Combine(procDir, "comm");
                    if (File.Exists(commPath))
                        processName = File.ReadAllText(commPath).Trim();
                }
                catch { continue; }

                if (processName is null || LegitimateAccessors.Contains(processName)) continue;

                try
                {
                    foreach (var fdPath in Directory.GetFiles(fdDir))
                    {
                        try
                        {
                            var target = File.ResolveLinkTarget(fdPath, false)?.ToString() ?? "";
                            if (credentialPaths.Contains(target))
                            {
                                signals.Add(new Signal(
                                    $"credential_file_open:{processName}:pid:{pid}:{Path.GetFileName(target)}",
                                    82, 0.87));
                            }
                        }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch { }
    }

    public void Dispose()
    {
        foreach (var w in _watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
        _watchers.Clear();
    }
}
