namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS code-signature integrity checks:
/// 1. Self codesign verify of the running Behavedr binary (codesign -v)
/// 2. Scan new/changed LaunchDaemons for unsigned or ad-hoc signed payloads
/// 3. Detect disabled SIP (csrutil status) as a soft integrity signal
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacOSCodeSignMonitor : IPlatformMonitor
{
    private readonly ILogger<MacOSCodeSignMonitor> _logger;
    private DateTime _lastDeepScan = DateTime.MinValue;
    private bool? _selfSignOk;
    private readonly HashSet<string> _checkedPlists = new(StringComparer.Ordinal);

    public string PlatformName => "MacOSCodeSign";
    public bool IsSupported => OperatingSystem.IsMacOS();

    public MacOSCodeSignMonitor(ILogger<MacOSCodeSignMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSCodeSignMonitor>.Instance;
    }

    [SupportedOSPlatform("macos")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            // Self-check once, then every 5 minutes
            if (_selfSignOk is null || (DateTime.UtcNow - _lastDeepScan).TotalMinutes >= 5)
            {
                VerifySelf(signals);
                CheckSip(signals);
                _lastDeepScan = DateTime.UtcNow;
            }

            if ((DateTime.UtcNow - _lastDeepScan).TotalSeconds >= 30 || _checkedPlists.Count == 0)
                ScanLaunchDaemons(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MacOSCodeSign] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("macos")]
    private void VerifySelf(List<Signal> signals)
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
            return;

        var (exit, stderr) = Run("codesign", $"-v --strict \"{exe}\"", 5000);
        // codesign -v returns 0 if valid; unsigned / invalid -> non-zero
        if (exit == 0)
        {
            _selfSignOk = true;
            return;
        }

        _selfSignOk = false;
        // Dev/unsigned portable builds are common - medium weight, not critical
        var detail = stderr.Contains("code object is not signed", StringComparison.OrdinalIgnoreCase)
            ? "unsigned"
            : "invalid";
        signals.Add(new Signal($"codesign_self:{detail}", 60, 0.75));
        _logger.LogWarning("[MacOSCodeSign] Self signature check failed ({Detail}): {Err}", detail, stderr.Trim());
    }

    [SupportedOSPlatform("macos")]
    private void CheckSip(List<Signal> signals)
    {
        var (exit, output) = Run("csrutil", "status", 4000);
        if (exit != 0) return;

        if (output.Contains("disabled", StringComparison.OrdinalIgnoreCase))
            signals.Add(new Signal("sip_disabled", 70, 0.9));
    }

    [SupportedOSPlatform("macos")]
    private void ScanLaunchDaemons(List<Signal> signals, CancellationToken ct)
    {
        var dirs = new[]
        {
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
        };

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] plists;
            try { plists = Directory.GetFiles(dir, "*.plist"); }
            catch { continue; }

            foreach (var plist in plists)
            {
                if (ct.IsCancellationRequested) break;
                if (!_checkedPlists.Add(plist)) continue;

                try
                {
                    var text = File.ReadAllText(plist);
                    // Extract ProgramArguments / Program path roughly
                    var exePath = ExtractProgramPath(text);
                    if (exePath is null || !File.Exists(exePath)) continue;

                    var (exit, _) = Run("codesign", $"-v --strict \"{exePath}\"", 3000);
                    if (exit != 0)
                    {
                        signals.Add(new Signal(
                            $"codesign_unsigned_persistence:{Path.GetFileName(plist)}:{Path.GetFileName(exePath)}",
                            82, 0.86));
                    }
                }
                catch { }
            }
        }
    }

    private static string? ExtractProgramPath(string plistXml)
    {
        // Prefer <key>Program</key><string>...</string>
        const string programKey = "<key>Program</key>";
        var idx = plistXml.IndexOf(programKey, StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var s = plistXml.IndexOf("<string>", idx, StringComparison.OrdinalIgnoreCase);
            var e = plistXml.IndexOf("</string>", s + 8, StringComparison.OrdinalIgnoreCase);
            if (s >= 0 && e > s)
                return plistXml[(s + 8)..e].Trim();
        }

        // Fallback: first absolute path string
        idx = plistXml.IndexOf("<string>/", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var e = plistXml.IndexOf("</string>", idx, StringComparison.OrdinalIgnoreCase);
            if (e > idx)
                return plistXml[(idx + 8)..e].Trim();
        }

        return null;
    }

    private static (int ExitCode, string Output) Run(string file, string args, int timeoutMs)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = file,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(timeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return (-1, "");
            }

            stdoutTask.Wait(1000);
            stderrTask.Wait(500);
            // codesign writes to stderr for -v
            var combined = (stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : "") +
                           (stderrTask.IsCompletedSuccessfully ? stderrTask.Result : "");
            return (proc.ExitCode, combined);
        }
        catch
        {
            return (-1, "");
        }
    }
}
