namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Credential honeypot (canary) for Linux and macOS.
/// Deploys fake credential files that only credential-harvesting tools would access:
/// - Fake SSH private key (~/.ssh/id_rsa_backup)
/// - Fake AWS credentials (~/.aws/credentials.bak)
/// - Fake .netrc file (~/.netrc_old)
///
/// Monitors access time (atime) changes on these canary files.
/// Any access = near-zero false positive credential harvesting indicator (0.97 confidence).
/// </summary>
public class UnixCredentialCanary : IPlatformMonitor
{
    private readonly ILogger<UnixCredentialCanary> _logger;
    private bool _canariesDeployed;
    private readonly Dictionary<string, DateTime> _canaryBaselines = new();

    public string PlatformName => "UnixCredentialCanary";
    public bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public UnixCredentialCanary(ILogger<UnixCredentialCanary>? logger = null)
    {
        _logger = logger ?? NullLogger<UnixCredentialCanary>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_canariesDeployed)
        {
            DeployCanaries();
            _canariesDeployed = true;
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        // Check if any canary was accessed
        foreach (var (path, deployTime) in _canaryBaselines)
        {
            if (!File.Exists(path))
            {
                // Canary deleted - harvester tried to clean up
                signals.Add(new Signal(
                    $"credential_canary_tripped:deleted:{Path.GetFileName(path)}", 95, 0.97));
                _logger.LogCritical(
                    "SECURITY: Credential canary DELETED - credential harvesting detected: {Path}", path);
                continue;
            }

            try
            {
                var lastAccess = File.GetLastAccessTimeUtc(path);
                if (lastAccess > deployTime.AddSeconds(5)) // Small buffer for filesystem noise
                {
                    signals.Add(new Signal(
                        $"credential_canary_tripped:accessed:{Path.GetFileName(path)}", 92, 0.97));
                    _logger.LogCritical(
                        "SECURITY: Credential canary ACCESSED - credential harvesting detected: {Path}", path);
                    // Reset baseline so we don't re-alert
                    _canaryBaselines[path] = lastAccess;
                }
            }
            catch { }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void DeployCanaries()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Fake SSH key (looks like a backup an attacker would grab)
        DeployCanary(Path.Combine(home, ".ssh", "id_rsa_backup"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAA\n" +
            "tzc2gtZWQyNTUxOQAAACBhZWhhdmVkcl9jYW5hcnlfa2V5X2RvX25vdF91c2UA\n" +
            "AAAAEGJlaGF2ZWRyX2NhbmFyeQ==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n");

        // Fake AWS credentials backup
        var awsDir = Path.Combine(home, ".aws");
        if (Directory.Exists(awsDir))
        {
            DeployCanary(Path.Combine(awsDir, "credentials.bak"),
                "[default]\n" +
                "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
                "# behavedr canary - do not use\n");
        }

        // Fake .netrc (many tools read this for credentials)
        DeployCanary(Path.Combine(home, ".netrc_old"),
            "machine github.com\n" +
            "login behavedr-canary-user\n" +
            "password ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");

        // Fake .pgpass (PostgreSQL credentials)
        DeployCanary(Path.Combine(home, ".pgpass_backup"),
            "localhost:5432:production:admin:SuperSecret123!\n" +
            "# behavedr canary credential - do not use\n");

        _logger.LogInformation("[CredentialCanary] Deployed {Count} canary files", _canaryBaselines.Count);
    }

    private void DeployCanary(string path, string content)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (dir is not null && !Directory.Exists(dir)) return; // Don't create dirs that don't exist

            if (File.Exists(path)) return; // Don't overwrite existing files

            File.WriteAllText(path, content);

            // Set restrictive permissions (600) and record baseline
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
                catch { }
            }

            _canaryBaselines[path] = DateTime.UtcNow;
        }
        catch { }
    }
}
