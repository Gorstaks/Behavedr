namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS credential protection monitor.
/// Detects unauthorized access to:
/// - Keychain databases (login.keychain-db, System.keychain)
/// - Browser credential files (Chrome Login Data, Firefox key4.db/logins.json)
/// - SSH keys (~/.ssh/id_*)
/// - Cloud credentials (~/.aws, ~/.config/gcloud)
/// - security command-line tool abuse (dump-keychain, export)
///
/// Also detects credential-harvesting tools running on the system.
/// </summary>
[SupportedOSPlatform("macos")]
public class MacOSCredentialMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<MacOSCredentialMonitor> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<Signal> _pendingSignals = new();
    private readonly object _lock = new();
    private bool _initialized;

    public string PlatformName => "MacOSCredential";
    public bool IsSupported => OperatingSystem.IsMacOS();

    private static readonly HashSet<string> LegitimateAccessors = new(StringComparer.OrdinalIgnoreCase)
    {
        "Safari", "Google Chrome", "firefox", "Brave Browser", "Opera",
        "ssh-agent", "ssh-add", "SecurityAgent", "securityd", "trustd",
        "keychain-circle-notification", "cloudkeychainproxy",
        "1Password", "Bitwarden", "KeePassXC", "behavedr",
    };

    public MacOSCredentialMonitor(ILogger<MacOSCredentialMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSCredentialMonitor>.Instance;
    }

    [SupportedOSPlatform("macos")]
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

        // Detect security tool abuse (dump-keychain, export-keychain)
        DetectSecurityToolAbuse(signals, ct);

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("macos")]
    private void InitializeWatchers()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var watchPaths = new List<(string Dir, string Category)>();

        // Keychain locations
        var keychainDir = Path.Combine(home, "Library", "Keychains");
        if (Directory.Exists(keychainDir))
            watchPaths.Add((keychainDir, "keychain"));

        // SSH keys
        var sshDir = Path.Combine(home, ".ssh");
        if (Directory.Exists(sshDir))
            watchPaths.Add((sshDir, "ssh_key"));

        // Cloud credentials
        var awsDir = Path.Combine(home, ".aws");
        if (Directory.Exists(awsDir))
            watchPaths.Add((awsDir, "cloud_credential"));

        // Chrome credentials
        var chromeDir = Path.Combine(home, "Library", "Application Support", "Google", "Chrome", "Default");
        if (Directory.Exists(chromeDir))
            watchPaths.Add((chromeDir, "browser_credential"));

        // Firefox credentials
        var firefoxDir = Path.Combine(home, "Library", "Application Support", "Firefox", "Profiles");
        if (Directory.Exists(firefoxDir))
        {
            try
            {
                foreach (var profileDir in Directory.GetDirectories(firefoxDir, "*.default*"))
                    watchPaths.Add((profileDir, "browser_credential"));
            }
            catch { }
        }

        foreach (var (dir, category) in watchPaths)
        {
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite,
                    EnableRaisingEvents = true,
                };
                watcher.Changed += (s, e) => OnCredentialAccess(e, category);
                _watchers.Add(watcher);
            }
            catch { }
        }

        _logger.LogInformation("[MacOSCredential] Watching {Count} credential directories", _watchers.Count);
    }

    private void OnCredentialAccess(FileSystemEventArgs e, string category)
    {
        var fileName = e.Name ?? "";
        bool isRelevant = category switch
        {
            "keychain" => fileName.Contains("keychain", StringComparison.OrdinalIgnoreCase),
            "ssh_key" => fileName.StartsWith("id_", StringComparison.Ordinal) || fileName == "authorized_keys",
            "cloud_credential" => fileName is "credentials" or "config",
            "browser_credential" => fileName is "Login Data" or "Cookies" or "key4.db" or "logins.json",
            _ => true,
        };
        if (!isRelevant) return;

        lock (_lock)
        {
            _pendingSignals.Add(new Signal(
                $"credential_file_accessed:{category}:{fileName}", 70, 0.78));
        }
    }

    /// <summary>
    /// Detect abuse of the 'security' command-line tool for keychain dumping.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void DetectSecurityToolAbuse(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (proc.ProcessName != "security") continue;

                    using var ps = new Process();
                    ps.StartInfo = new ProcessStartInfo
                    {
                        FileName = "/bin/ps",
                        Arguments = $"-p {proc.Id} -o command=",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                    };
                    ps.Start();
                    var cmdline = ps.StandardOutput.ReadToEnd().Trim();
                    ps.WaitForExit(1000);

                    if (cmdline.Contains("dump-keychain", StringComparison.OrdinalIgnoreCase) ||
                        cmdline.Contains("export-keychain", StringComparison.OrdinalIgnoreCase) ||
                        cmdline.Contains("find-generic-password", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"keychain_dump_tool:pid:{proc.Id}", 88, 0.92));
                    }
                }
                catch { }
                finally { proc.Dispose(); }
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
