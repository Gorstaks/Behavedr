namespace Behavedr.Core.Monitors;

using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Unix behavioral analysis monitor (Linux + macOS).
/// Equivalent to Windows BehavioralMonitor - detects:
/// - GTFOBin abuse (Unix LOLBins: curl, wget, python, perl, awk, nmap, etc.)
/// - Command-line obfuscation (base64 piping, hex encoding, variable expansion tricks)
/// - Suspicious parent-child relationships (web server -> shell, cron -> network tool)
/// - Download cradles (curl|bash, wget -O-|sh, python -c "import urllib...")
/// - Privilege escalation patterns (sudo misuse, pkexec, doas)
/// </summary>
public class UnixBehavioralMonitor : IPlatformMonitor
{
    private readonly ILogger<UnixBehavioralMonitor> _logger;

    public string PlatformName => "UnixBehavioral";
    public bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public UnixBehavioralMonitor(ILogger<UnixBehavioralMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<UnixBehavioralMonitor>.Instance;
    }

    // GTFOBins - legitimate Unix binaries abusable for download, exec, file read/write, SUID escalation
    private static readonly (string Pattern, string Description, double Weight, double Confidence)[] GtfoBinPatterns =
    [
        (@"curl\s+.*\|\s*(ba)?sh", "curl pipe to shell", 82, 0.88),
        (@"wget\s+.*-O\s*-\s*\|\s*(ba)?sh", "wget pipe to shell", 82, 0.88),
        (@"curl\s+.*-o\s+/tmp/", "curl download to tmp", 55, 0.65),
        (@"wget\s+.*-P\s*/tmp/", "wget download to tmp", 55, 0.65),
        (@"python[23]?\s+-c\s+.*import\s+(urllib|socket|os)", "python inline exec", 65, 0.72),
        (@"perl\s+-e\s+.*socket|IO::Socket", "perl inline socket", 68, 0.75),
        (@"ruby\s+-e\s+.*TCPSocket|Net::HTTP", "ruby inline network", 68, 0.75),
        (@"php\s+-r\s+.*fsockopen|file_get_contents", "php inline network", 68, 0.75),
        (@"awk\s+.*BEGIN\s*\{.*/inet/tcp", "awk network abuse", 75, 0.8),
        (@"nmap\s+.*--script|nmap\s+-s[STV]", "nmap scanning", 50, 0.6),
        (@"openssl\s+s_client\s+.*connect", "openssl reverse connect", 60, 0.7),
        (@"socat\s+.*exec:", "socat exec binding", 78, 0.82),
        (@"find\s+.*-exec\s+.*sh\s", "find exec shell", 55, 0.62),
        (@"tar\s+.*--checkpoint-action.*exec", "tar exec abuse", 72, 0.78),
        (@"dpkg\s+.*--pre-invoke|--post-invoke", "dpkg hook abuse", 70, 0.75),
        (@"vim\s+-c\s+.*:!|vim\s+.*-E\s+.*system\(", "vim shell escape", 58, 0.65),
        (@"ssh\s+.*ProxyCommand", "ssh proxy command exec", 55, 0.62),
        (@"crontab\s+-[re]", "crontab modification", 50, 0.6),
        (@"at\s+.*<<<|echo\s+.*\|\s*at\s", "at job creation", 50, 0.6),
    ];

    // Suspicious parent-child relationships on Unix
    private static readonly Dictionary<string, HashSet<string>> SuspiciousParentChild = new(StringComparer.OrdinalIgnoreCase)
    {
        ["apache2"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "dash", "python", "perl", "nc", "ncat" },
        ["nginx"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "dash", "python", "perl", "nc" },
        ["httpd"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "dash", "python", "perl" },
        ["php-fpm"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "nc", "ncat", "python" },
        ["node"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "nc", "python" },
        ["java"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "nc", "curl", "wget" },
        ["cron"] = new(StringComparer.OrdinalIgnoreCase) { "nc", "ncat", "curl", "wget", "python" },
        ["crond"] = new(StringComparer.OrdinalIgnoreCase) { "nc", "ncat", "curl", "wget", "python" },
        ["postgres"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "nc", "curl" },
        ["mysqld"] = new(StringComparer.OrdinalIgnoreCase) { "bash", "sh", "nc", "curl" },
    };

    private static readonly Regex ObfuscationRegex = new(
        @"(\$\(\s*echo\s+.*\|\s*base64\s+-d\)|\$\{.*//.*\}.*\$\{|\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}|printf\s+.*\\\\x)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex DownloadCradleRegex = new(
        @"(curl|wget|fetch|lwp-download)\s+.*(http|ftp).*\|\s*(ba)?sh",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            if (OperatingSystem.IsLinux())
                ScanLinuxProcesses(signals, ct);
            else if (OperatingSystem.IsMacOS())
                ScanMacOSProcesses(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixBehavioral] Error during scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void ScanLinuxProcesses(List<Signal> signals, CancellationToken ct)
    {
        if (!Directory.Exists("/proc")) return;

        foreach (var procDir in Directory.GetDirectories("/proc"))
        {
            if (ct.IsCancellationRequested) break;
            var pidStr = Path.GetFileName(procDir);
            if (!int.TryParse(pidStr, out var pid)) continue;
            if (pid <= 1 || pid == Environment.ProcessId) continue;

            try
            {
                var commPath = Path.Combine(procDir, "comm");
                if (!File.Exists(commPath)) continue;
                var processName = File.ReadAllText(commPath).Trim();

                var cmdlinePath = Path.Combine(procDir, "cmdline");
                if (!File.Exists(cmdlinePath)) continue;
                var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ').Trim();
                if (string.IsNullOrEmpty(cmdline)) continue;

                // GTFOBin pattern matching
                MatchGtfoBinPatterns(cmdline, processName, pid, signals);

                // Obfuscation detection
                if (ObfuscationRegex.IsMatch(cmdline))
                {
                    signals.Add(new Signal(
                        $"obfuscated_cmdline:{processName}:pid:{pid}", 68, 0.75));
                }

                // Download cradle detection
                if (DownloadCradleRegex.IsMatch(cmdline))
                {
                    signals.Add(new Signal(
                        $"download_cradle:{processName}:pid:{pid}", 78, 0.83));
                }

                // Parent-child anomaly detection
                var statPath = Path.Combine(procDir, "stat");
                if (File.Exists(statPath))
                {
                    try
                    {
                        var stat = File.ReadAllText(statPath);
                        // Format: pid (name) state ppid ...
                        var closeP = stat.LastIndexOf(')');
                        if (closeP > 0 && stat.Length > closeP + 4)
                        {
                            var fields = stat[(closeP + 2)..].Split(' ');
                            if (fields.Length > 2 && int.TryParse(fields[1], out var ppid))
                            {
                                var parentName = GetProcessName(ppid);
                                if (parentName is not null &&
                                    SuspiciousParentChild.TryGetValue(parentName, out var children) &&
                                    children.Contains(processName))
                                {
                                    signals.Add(new Signal(
                                        $"suspicious_parent_child:{parentName}->{processName}:pid:{pid}",
                                        75, 0.82));
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private void ScanMacOSProcesses(List<Signal> signals, CancellationToken ct)
    {
        // Use ps to get PID, PPID, command for all processes
        try
        {
            using var proc = new System.Diagnostics.Process();
            proc.StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "/bin/ps",
                Arguments = "ax -o pid,ppid,comm,args",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            foreach (var line in output.Split('\n').Skip(1))
            {
                if (ct.IsCancellationRequested) break;
                var parts = line.Trim().Split((char[]?)null, 4, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;
                if (!int.TryParse(parts[0], out var pid)) continue;
                if (!int.TryParse(parts[1], out var ppid)) continue;
                var processName = Path.GetFileName(parts[2]);
                var cmdline = parts[3];

                MatchGtfoBinPatterns(cmdline, processName, pid, signals);

                if (ObfuscationRegex.IsMatch(cmdline))
                    signals.Add(new Signal($"obfuscated_cmdline:{processName}:pid:{pid}", 68, 0.75));
                if (DownloadCradleRegex.IsMatch(cmdline))
                    signals.Add(new Signal($"download_cradle:{processName}:pid:{pid}", 78, 0.83));

                // Parent-child
                var parentName = GetMacOSProcessName(ppid);
                if (parentName is not null &&
                    SuspiciousParentChild.TryGetValue(parentName, out var children) &&
                    children.Contains(processName))
                {
                    signals.Add(new Signal(
                        $"suspicious_parent_child:{parentName}->{processName}:pid:{pid}", 75, 0.82));
                }
            }
        }
        catch { }
    }

    private static void MatchGtfoBinPatterns(string cmdline, string processName, int pid, List<Signal> signals)
    {
        foreach (var (pattern, description, weight, confidence) in GtfoBinPatterns)
        {
            if (Regex.IsMatch(cmdline, pattern, RegexOptions.IgnoreCase))
            {
                signals.Add(new Signal(
                    $"gtfobin:{description}:{processName}:pid:{pid}", weight, confidence));
                break; // One signal per process
            }
        }
    }

    private static string? GetProcessName(int pid)
    {
        try
        {
            var commPath = $"/proc/{pid}/comm";
            return File.Exists(commPath) ? File.ReadAllText(commPath).Trim() : null;
        }
        catch { return null; }
    }

    private static string? GetMacOSProcessName(int pid)
    {
        try
        {
            using var proc = new System.Diagnostics.Process();
            proc.StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "/bin/ps",
                Arguments = $"-p {pid} -o comm=",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var name = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(1000);
            return string.IsNullOrEmpty(name) ? null : Path.GetFileName(name);
        }
        catch { return null; }
    }
}
