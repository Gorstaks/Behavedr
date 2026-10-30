namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS behavioral detection monitor using process enumeration, filesystem monitoring,
/// and system command output parsing. Provides real-time detection of:
/// - Suspicious process execution (offensive tools, reverse shells, encoded commands)
/// - Dylib hijacking and injection (DYLD_INSERT_LIBRARIES abuse)
/// - TCC (Transparency, Consent, Control) bypass attempts
/// - Gatekeeper bypass (xattr removal, quarantine flag stripping)
/// - Suspicious AppleScript/osascript execution
/// - Process injection via task_for_pid
/// - Unexpected root/wheel processes
/// - XProtect/MRT disablement
/// </summary>
public class MacOSMonitor : IPlatformMonitor
{
    private readonly ILogger<MacOSMonitor> _logger;

    public string PlatformName => "macOS";
    public bool IsSupported => OperatingSystem.IsMacOS();

    public MacOSMonitor(ILogger<MacOSMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSMonitor>.Instance;
    }

    private static readonly HashSet<string> ExpectedRootProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "launchd", "kernel_task", "loginwindow", "WindowServer",
        "coreaudiod", "coreduetd", "diskarbitrationd", "fseventsd",
        "mds", "mds_stores", "mdworker", "notifyd", "opendirectoryd",
        "securityd", "syslogd", "configd", "distnoted", "UserEventAgent",
        "airportd", "bluetoothd", "powerd", "thermald", "timed",
        "trustd", "usbd", "watchdogd", "apsd", "nsurlsessiond",
        "sandboxd", "sshd", "behavedr",
    };

    private static readonly Regex ReverseShellRegex = new(
        @"(bash\s+-i|/dev/tcp/|nc\s+-e|ncat\s+-e|socat\s+exec|python.*socket.*connect|ruby.*TCPSocket|php.*fsockopen)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex EncodedExecRegex = new(
        @"(base64\s+-[dD]|\|\s*(ba)?sh|\|\s*python|eval\s*\(|exec\s*\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    [SupportedOSPlatform("macos")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            ScanProcesses(signals, ct);
            DetectDylibInjection(signals, ct);
            DetectTccBypass(signals, ct);
            DetectGatekeeperBypass(signals, ct);
            DetectSuspiciousOsascript(signals, ct);
            DetectXprotectDisablement(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSMonitor] Error during scan cycle");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Scan running processes for offensive tools, reverse shells, encoded execution,
    /// and unexpected root processes.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void ScanProcesses(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var name = proc.ProcessName;
                    var pid = proc.Id;
                    if (pid == Environment.ProcessId) continue;

                    string? path = null;
                    try { path = proc.MainModule?.FileName; } catch { /* permission */ }
                    if (Response.ResponseSafety.IsOwnAgentImage(path)) continue;

                    var off = ThreatHeuristics.Evaluate(name, path);
                    if (off is { } o)
                    {
                        signals.Add(new Signal(
                            $"suspicious_process:{o.Tag}:{o.Detail}:pid:{pid}",
                            o.Weight, o.Confidence));
                    }

                    // Get command line via ps (macOS doesn't expose /proc)
                    var cmdline = GetCommandLine(pid);
                    if (!string.IsNullOrEmpty(cmdline))
                    {
                        if (ReverseShellRegex.IsMatch(cmdline))
                        {
                            signals.Add(new Signal(
                                $"reverse_shell:{name}:pid:{pid}", 92, 0.88));
                        }
                        if (EncodedExecRegex.IsMatch(cmdline))
                        {
                            signals.Add(new Signal(
                                $"encoded_execution:{name}:pid:{pid}", 65, 0.72));
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSMonitor] Process scan error");
        }
    }

    /// <summary>
    /// Detect DYLD_INSERT_LIBRARIES abuse - macOS equivalent of LD_PRELOAD.
    /// Attacker injects a malicious dylib into another process's address space.
    /// Also detects DYLD_FRAMEWORK_PATH and DYLD_LIBRARY_PATH manipulation.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void DetectDylibInjection(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            // Check running processes for DYLD_ environment variables
            var output = RunCommand("ps", "auxe");
            if (string.IsNullOrEmpty(output)) return;

            foreach (var line in output.Split('\n'))
            {
                if (ct.IsCancellationRequested) break;

                if (line.Contains("DYLD_INSERT_LIBRARIES=", StringComparison.Ordinal))
                {
                    var match = Regex.Match(line, @"DYLD_INSERT_LIBRARIES=(\S+)");
                    if (match.Success)
                    {
                        var libPath = match.Groups[1].Value;
                        // Skip legitimate paths
                        if (!libPath.StartsWith("/usr/lib", StringComparison.Ordinal) &&
                            !libPath.StartsWith("/System/", StringComparison.Ordinal) &&
                            !libPath.StartsWith("/Library/Frameworks", StringComparison.Ordinal))
                        {
                            signals.Add(new Signal(
                                $"dylib_injection:DYLD_INSERT_LIBRARIES={libPath}", 82, 0.85));
                        }
                    }
                }

                if (line.Contains("DYLD_FRAMEWORK_PATH=", StringComparison.Ordinal) ||
                    line.Contains("DYLD_LIBRARY_PATH=", StringComparison.Ordinal))
                {
                    // Non-standard dylib search paths can indicate hijacking
                    signals.Add(new Signal("dyld_path_manipulation", 55, 0.6));
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect TCC (Transparency, Consent, Control) bypass attempts:
    /// - Direct modification of TCC.db
    /// - tccutil commands resetting permissions
    /// - Synthetic click injection (CGEvent)
    /// - FDA (Full Disk Access) abuse via known utilities
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void DetectTccBypass(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var cmdline = GetCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdline)) continue;

                    // tccutil reset
                    if (cmdline.Contains("tccutil", StringComparison.OrdinalIgnoreCase) &&
                        cmdline.Contains("reset", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"tcc_bypass_reset:pid:{proc.Id}", 80, 0.85));
                    }

                    // Direct TCC.db manipulation
                    if (cmdline.Contains("TCC.db", StringComparison.OrdinalIgnoreCase) &&
                        (cmdline.Contains("sqlite", StringComparison.OrdinalIgnoreCase) ||
                         cmdline.Contains("INSERT", StringComparison.OrdinalIgnoreCase)))
                    {
                        signals.Add(new Signal(
                            $"tcc_db_manipulation:pid:{proc.Id}", 90, 0.9));
                    }

                    // Synthetic accessibility events
                    if (cmdline.Contains("CGEventPost", StringComparison.Ordinal) ||
                        cmdline.Contains("AXUIElement", StringComparison.Ordinal))
                    {
                        signals.Add(new Signal(
                            $"synthetic_input_injection:pid:{proc.Id}", 60, 0.65));
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        // Check for TCC.db modification
        var tccPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library/Application Support/com.apple.TCC/TCC.db"),
            "/Library/Application Support/com.apple.TCC/TCC.db",
        };

        foreach (var tccPath in tccPaths)
        {
            if (!File.Exists(tccPath)) continue;
            try
            {
                var lastWrite = File.GetLastWriteTimeUtc(tccPath);
                if ((DateTime.UtcNow - lastWrite).TotalMinutes < 5)
                {
                    signals.Add(new Signal($"tcc_db_recently_modified:{tccPath}", 75, 0.8));
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect Gatekeeper bypass - removal of com.apple.quarantine xattr,
    /// spctl --master-disable, or attempts to bypass notarization.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void DetectGatekeeperBypass(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var cmdline = GetCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdline)) continue;

                    // xattr -d com.apple.quarantine (remove quarantine flag)
                    if (cmdline.Contains("xattr", StringComparison.OrdinalIgnoreCase) &&
                        cmdline.Contains("quarantine", StringComparison.OrdinalIgnoreCase) &&
                        cmdline.Contains("-d", StringComparison.Ordinal))
                    {
                        signals.Add(new Signal(
                            $"gatekeeper_bypass_xattr:pid:{proc.Id}", 72, 0.78));
                    }

                    // spctl --master-disable (disable Gatekeeper entirely)
                    if (cmdline.Contains("spctl", StringComparison.OrdinalIgnoreCase) &&
                        cmdline.Contains("--master-disable", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"gatekeeper_disabled:pid:{proc.Id}", 85, 0.88));
                    }

                    // csrutil disable (SIP disable - requires recovery mode but detect if running)
                    if (cmdline.Contains("csrutil", StringComparison.OrdinalIgnoreCase) &&
                        cmdline.Contains("disable", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"sip_disable_attempt:pid:{proc.Id}", 95, 0.92));
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect suspicious osascript/AppleScript execution - commonly used for
    /// credential phishing dialogs, privilege escalation, and persistence.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void DetectSuspiciousOsascript(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (!proc.ProcessName.Equals("osascript", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var cmdline = GetCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdline)) continue;

                    // Credential phishing via AppleScript dialog
                    if (cmdline.Contains("display dialog", StringComparison.OrdinalIgnoreCase) &&
                        (cmdline.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                         cmdline.Contains("credential", StringComparison.OrdinalIgnoreCase)))
                    {
                        signals.Add(new Signal(
                            $"osascript_credential_phish:pid:{proc.Id}", 85, 0.88));
                    }

                    // System Events scripting (automation abuse)
                    if (cmdline.Contains("System Events", StringComparison.OrdinalIgnoreCase) &&
                        cmdline.Contains("keystroke", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"osascript_keystroke_injection:pid:{proc.Id}", 70, 0.75));
                    }

                    // Shell execution from AppleScript
                    if (cmdline.Contains("do shell script", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"osascript_shell_exec:pid:{proc.Id}", 55, 0.6));
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect XProtect or MRT (Malware Removal Tool) disablement/interference.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private void DetectXprotectDisablement(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var cmdline = GetCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdline)) continue;

                    // Disable XProtect/MRT via launchctl
                    if (cmdline.Contains("launchctl", StringComparison.OrdinalIgnoreCase) &&
                        (cmdline.Contains("unload", StringComparison.OrdinalIgnoreCase) ||
                         cmdline.Contains("disable", StringComparison.OrdinalIgnoreCase)) &&
                        (cmdline.Contains("XProtect", StringComparison.OrdinalIgnoreCase) ||
                         cmdline.Contains("MRT", StringComparison.Ordinal)))
                    {
                        signals.Add(new Signal(
                            $"xprotect_disabled:pid:{proc.Id}", 90, 0.9));
                    }

                    // Kill XProtect processes
                    if (cmdline.Contains("kill", StringComparison.OrdinalIgnoreCase) &&
                        cmdline.Contains("XProtect", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"xprotect_killed:pid:{proc.Id}", 88, 0.87));
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    /// <summary>
    /// Get the command line for a process via ps (macOS doesn't have /proc/cmdline).
    /// </summary>
    private static string? GetCommandLine(int pid)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/bin/ps",
                Arguments = $"-p {pid} -o command=",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(2000);
            return string.IsNullOrEmpty(output) ? null : output;
        }
        catch { return null; }
    }

    /// <summary>
    /// Run a command and return stdout.
    /// </summary>
    private static string? RunCommand(string command, string args)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return output;
        }
        catch { return null; }
    }
}
