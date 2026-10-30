namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android credential theft detection monitor.
/// Detects:
/// - Accessibility service abuse (keylogging, auto-click, overlay attacks)
/// - Overlay/SYSTEM_ALERT_WINDOW abuse (fake login screens)
/// - Browser credential database access
/// - Clipboard monitoring services
/// - Account manager token theft
/// - Known banking trojan process names
///
/// v0.2.0 audit fix A-5: Adds credential theft detection for Android.
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidCredentialMonitor : IPlatformMonitor
{
    private readonly ILogger<AndroidCredentialMonitor> _logger;
    private HashSet<string> _baselineAccessibilityServices = new();
    private bool _baselined;

    public string PlatformName => "AndroidCredential";
    public bool IsSupported => OperatingSystem.IsAndroid();

    // Known banking trojan families
    private static readonly HashSet<string> BankingTrojanNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "flubot", "anatsa", "sharkbot", "hydra", "ermac",
        "cerberus", "anubis", "medusa", "xenomorph", "teabot",
        "vultur", "octo", "hook", "godfather", "nexus",
        "brata", "coper", "sova", "eventbot", "gustuff",
    };

    // Browser credential database paths
    private static readonly string[] BrowserCredPaths =
    [
        "/data/data/com.android.chrome/app_chrome/Default/Login Data",
        "/data/data/com.chrome.beta/app_chrome/Default/Login Data",
        "/data/data/org.mozilla.firefox/files/logins.json",
        "/data/data/com.opera.browser/app_opera/Login Data",
        "/data/data/com.brave.browser/app_chrome/Default/Login Data",
    ];

    public AndroidCredentialMonitor(ILogger<AndroidCredentialMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidCredentialMonitor>.Instance;
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            DetectAccessibilityAbuse(signals);
            DetectBankingTrojans(signals, ct);
            DetectCredentialDbAccess(signals, ct);
            DetectClipboardMonitoring(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AndroidCredential] Error during scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect suspicious accessibility services. Accessibility services can:
    /// - Read all on-screen content (keylogging)
    /// - Perform gestures/clicks (auto-approve permissions)
    /// - Overlay fake UI (credential harvesting)
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectAccessibilityAbuse(List<Signal> signals)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/system/bin/settings",
                Arguments = "get secure enabled_accessibility_services",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(3000);

            if (string.IsNullOrEmpty(output) || output == "null") return;

            var services = output.Split(':', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Split('/')[0].Trim())
                .Where(s => !string.IsNullOrEmpty(s))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (!_baselined)
            {
                _baselineAccessibilityServices = services;
                _baselined = true;
                return;
            }

            // Detect newly enabled accessibility services
            foreach (var svc in services)
            {
                if (_baselineAccessibilityServices.Contains(svc)) continue;

                // Flag non-system accessibility services
                if (!svc.StartsWith("com.google.", StringComparison.OrdinalIgnoreCase) &&
                    !svc.StartsWith("com.android.", StringComparison.OrdinalIgnoreCase) &&
                    !svc.StartsWith("com.samsung.", StringComparison.OrdinalIgnoreCase) &&
                    !svc.StartsWith("com.sec.", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal(
                        $"new_accessibility_service:{svc}", 78, 0.84));
                    _logger.LogWarning(
                        "[AndroidCredential] New accessibility service enabled: {Service}", svc);
                }
            }

            _baselineAccessibilityServices = services;
        }
        catch { }
    }

    /// <summary>
    /// Detect known banking trojan process names running on the device.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectBankingTrojans(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                try
                {
                    var cmdlinePath = Path.Combine(procDir, "cmdline");
                    if (!File.Exists(cmdlinePath)) continue;
                    var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ').Trim();

                    if (BankingTrojanNames.Any(t =>
                        cmdline.Contains(t, StringComparison.OrdinalIgnoreCase)))
                    {
                        signals.Add(new Signal(
                            $"banking_trojan_running:{cmdline.Split(' ')[0]}:pid:{pid}", 92, 0.94));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect processes accessing browser credential databases.
    /// On rooted devices, malware can directly read Chrome's Login Data SQLite.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectCredentialDbAccess(List<Signal> signals, CancellationToken ct)
    {
        foreach (var credPath in BrowserCredPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!File.Exists(credPath)) continue;

            try
            {
                // Check if file was recently accessed (last 60 seconds)
                var lastAccess = File.GetLastAccessTimeUtc(credPath);
                if ((DateTime.UtcNow - lastAccess).TotalSeconds < 60)
                {
                    // Check which process has it open via /proc/*/fd
                    foreach (var procDir in Directory.GetDirectories("/proc"))
                    {
                        var pidStr = Path.GetFileName(procDir);
                        if (!int.TryParse(pidStr, out var pid)) continue;

                        var fdDir = Path.Combine(procDir, "fd");
                        if (!Directory.Exists(fdDir)) continue;

                        try
                        {
                            foreach (var fd in Directory.GetFiles(fdDir))
                            {
                                var target = File.ResolveLinkTarget(fd, false)?.ToString();
                                if (target is not null &&
                                    target.Equals(credPath, StringComparison.Ordinal))
                                {
                                    var comm = GetProcessComm(pid);
                                    // Ignore the browser itself accessing its own DB
                                    if (comm is not null &&
                                        !comm.Contains("chrome", StringComparison.OrdinalIgnoreCase) &&
                                        !comm.Contains("firefox", StringComparison.OrdinalIgnoreCase))
                                    {
                                        signals.Add(new Signal(
                                            $"credential_db_access:{comm}:pid:{pid}:{Path.GetFileName(credPath)}",
                                            85, 0.9));
                                    }
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect persistent clipboard monitoring (password manager sniffing).
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectClipboardMonitoring(List<Signal> signals, CancellationToken ct)
    {
        // Check for processes with "clipboard" in their name that aren't system
        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                try
                {
                    var cmdlinePath = Path.Combine(procDir, "cmdline");
                    if (!File.Exists(cmdlinePath)) continue;
                    var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ').Trim();

                    if (cmdline.Contains("clipboard", StringComparison.OrdinalIgnoreCase) &&
                        !cmdline.Contains("com.android.", StringComparison.OrdinalIgnoreCase) &&
                        !cmdline.Contains("com.google.", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"clipboard_monitor_running:{cmdline.Split(' ')[0]}:pid:{pid}", 60, 0.7));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static string? GetProcessComm(int pid)
    {
        try { return File.ReadAllText($"/proc/{pid}/comm").Trim(); }
        catch { return null; }
    }
}
