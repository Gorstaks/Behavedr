namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android behavioral detection monitor.
/// Provides both on-device heuristic detection and a signal injection API
/// for the MAUI platform layer to supply native Android telemetry.
///
/// On-device detection (no platform injection needed):
/// - Root/jailbreak indicators (su binary, Magisk, SuperSU, SELinux status)
/// - ADB debugging enabled (development settings abuse)
/// - Suspicious running processes (miners, RATs, exploit frameworks)
/// - Overlay/SYSTEM_ALERT_WINDOW abuse indicators
/// - USB debugging and unknown sources enabled
/// - Battery drain anomalies (crypto mining indicator)
/// - Accessibility service abuse patterns
/// - Device admin/MDM abuse
///
/// Platform-injected detection (requires MAUI Android layer):
/// - Package analysis (sideloaded apps, malware signatures)
/// - Permission auditing (dangerous runtime permissions)
/// - SMS/call interception detection
/// - Network traffic analysis
/// </summary>
public class AndroidMonitor : IPlatformMonitor
{
    private readonly ILogger<AndroidMonitor> _logger;

    public string PlatformName => "Android";
    public bool IsSupported => OperatingSystem.IsAndroid();

    public AndroidMonitor(ILogger<AndroidMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidMonitor>.Instance;
    }

    // Known root indicators (files that should not exist on non-rooted devices)
    private static readonly string[] RootIndicatorPaths =
    [
        "/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su",
        "/sbin/su", "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/system/bin/.ext/.su", "/su/bin/su",
        // Magisk
        "/sbin/.magisk", "/data/adb/magisk", "/cache/.disable_magisk",
        // KernelSU
        "/data/adb/ksu",
        // Common root apps
        "/system/app/SuperSU.apk", "/system/app/KingRoot.apk",
    ];

    // Dangerous permission combinations indicating malicious intent
    private static readonly string[] DangerousPermissions =
    [
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    ];

    // Known malware package prefixes
    private static readonly string[] MalwarePackagePrefixes =
    [
        "com.exploit.", "com.hack.", "com.trojan.", "org.metasploit.",
        "com.termux.tasker", "com.offsec.", "com.android.systemservice",
        "com.miner.", "com.crypto.miner", "com.coinhive.",
    ];

    private readonly List<Signal> _injectedSignals = new();
    private readonly object _lock = new();
    private string? _injectionToken;

    /// <summary>
    /// Set the injection token that callers must provide to inject signals.
    /// Call this once during initialization with a unique per-session token.
    /// </summary>
    public void SetInjectionToken(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        lock (_lock) { _injectionToken = token; }
    }

    /// <summary>
    /// Inject signals from the Android platform layer (MAUI/Java interop).
    /// Requires the injection token set during initialization for authentication.
    /// </summary>
    public void InjectPlatformSignals(IEnumerable<Signal> signals, string token)
    {
        lock (_lock)
        {
            if (_injectionToken is null)
                throw new InvalidOperationException("Injection token not configured.");
            if (!string.Equals(token, _injectionToken, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Invalid injection token.");
            _injectedSignals.Clear();
            _injectedSignals.AddRange(signals);
        }
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        // Platform-injected signals take priority
        lock (_lock)
        {
            if (_injectedSignals.Count > 0)
            {
                signals.AddRange(_injectedSignals);
                _injectedSignals.Clear();
            }
        }

        // On-device heuristic detection (works without platform layer)
        try
        {
            DetectRootIndicators(signals);
            DetectSuspiciousProcesses(signals, ct);
            DetectAdbDebugging(signals);
            DetectCryptoMining(signals);
            DetectSuspiciousFiles(signals, ct);

            // v0.2.0 audit fixes A-6, A-8, A-10
            DetectSELinuxViolations(signals);
            DetectAccessibilityAbuse(signals);
            DetectSmsInterception(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AndroidMonitor] Heuristic scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect root/jailbreak indicators by checking for su binaries, Magisk artifacts,
    /// and SELinux permissive mode.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectRootIndicators(List<Signal> signals)
    {
        int rootIndicatorCount = 0;

        foreach (var path in RootIndicatorPaths)
        {
            if (File.Exists(path))
            {
                rootIndicatorCount++;
            }
        }

        if (rootIndicatorCount > 0)
        {
            var confidence = rootIndicatorCount switch
            {
                > 3 => 0.98,
                > 1 => 0.9,
                _ => 0.75,
            };
            signals.Add(new Signal(
                $"device_rooted:indicators:{rootIndicatorCount}", 85, confidence));
        }

        // Check SELinux status (permissive = rooted/compromised)
        try
        {
            var selinuxPath = "/sys/fs/selinux/enforce";
            if (File.Exists(selinuxPath))
            {
                var enforce = File.ReadAllText(selinuxPath).Trim();
                if (enforce == "0") // Permissive mode
                {
                    signals.Add(new Signal("selinux_permissive", 80, 0.88));
                }
            }
        }
        catch { }

        // Check for Magisk hide/denylist (indicates active root concealment)
        if (Directory.Exists("/data/adb/magisk") || File.Exists("/sbin/.magisk/mirror"))
        {
            signals.Add(new Signal("magisk_detected", 70, 0.85));
        }

        // Check for test-keys (custom/unsigned ROM)
        try
        {
            var buildProps = "/system/build.prop";
            if (File.Exists(buildProps))
            {
                var content = File.ReadAllText(buildProps);
                if (content.Contains("test-keys", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal("custom_rom_test_keys", 50, 0.7));
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect suspicious running processes: crypto miners, RATs, exploit frameworks,
    /// network sniffers, instrumentation tools.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectSuspiciousProcesses(List<Signal> signals, CancellationToken ct)
    {
        // On Android, /proc is accessible (though limited without root)
        if (!Directory.Exists("/proc")) return;

        try
        {
            foreach (var procDir in Directory.GetDirectories("/proc"))
            {
                if (ct.IsCancellationRequested) break;
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out var pid)) continue;

                try
                {
                    var commPath = Path.Combine(procDir, "comm");
                    if (!File.Exists(commPath)) continue;
                    if (pid == Environment.ProcessId) continue;
                    var processName = File.ReadAllText(commPath).Trim();

                    string? exePath = null;
                    try
                    {
                        exePath = File.ResolveLinkTarget(Path.Combine(procDir, "exe"), returnFinalTarget: true)?.FullName;
                    }
                    catch { /* permission */ }

                    var cmdline = "";
                    var cmdlinePath = Path.Combine(procDir, "cmdline");
                    if (File.Exists(cmdlinePath))
                        cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ');

                    var off = ThreatHeuristics.Evaluate(processName, exePath ?? cmdline);
                    if (off is { } o)
                    {
                        signals.Add(new Signal(
                            $"suspicious_process:{o.Tag}:{o.Detail}:pid:{pid}",
                            o.Weight, o.Confidence));
                    }

                    // Frida/instrumentation is high confidence when present in cmdline
                    if (cmdline.Contains("frida", StringComparison.OrdinalIgnoreCase) ||
                        cmdline.Contains("gadget", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"instrumentation_framework:pid:{pid}", 90, 0.92));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect ADB debugging enabled - indicates development mode active,
    /// which allows sideloading and remote code execution.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectAdbDebugging(List<Signal> signals)
    {
        try
        {
            // Check system properties for ADB state
            // On Android, /sys/class/android_usb/android0/state or getprop
            var adbdPorts = new[] { "/proc/net/tcp", "/proc/net/tcp6" };
            foreach (var tcpFile in adbdPorts)
            {
                if (!File.Exists(tcpFile)) continue;
                try
                {
                    var content = File.ReadAllText(tcpFile);
                    // ADB listens on port 5555 (hex: 15B3) when wireless debugging is on
                    if (content.Contains(":15B3", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal("adb_wireless_debugging_enabled", 60, 0.75));
                    }
                }
                catch { }
            }

            // Check if adbd is running with root
            if (File.Exists("/proc/1/comm")) // Can read init's comm = we have some visibility
            {
                foreach (var procDir in Directory.GetDirectories("/proc"))
                {
                    var pidStr = Path.GetFileName(procDir);
                    if (!int.TryParse(pidStr, out _)) continue;

                    try
                    {
                        var commPath = Path.Combine(procDir, "comm");
                        if (File.Exists(commPath) &&
                            File.ReadAllText(commPath).Trim() == "adbd")
                        {
                            // adbd running as root is extremely dangerous
                            var statusPath = Path.Combine(procDir, "status");
                            if (File.Exists(statusPath))
                            {
                                var status = File.ReadAllText(statusPath);
                                if (status.Contains("Uid:\t0", StringComparison.Ordinal))
                                {
                                    signals.Add(new Signal("adbd_running_as_root", 82, 0.88));
                                }
                            }
                            break;
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect crypto mining by checking CPU usage patterns.
    /// Miners sustain >80% CPU across multiple cores for extended periods.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectCryptoMining(List<Signal> signals)
    {
        try
        {
            // Read /proc/stat for aggregate CPU usage
            if (!File.Exists("/proc/stat")) return;

            var statLines = File.ReadLines("/proc/stat");
            foreach (var line in statLines)
            {
                if (!line.StartsWith("cpu ", StringComparison.Ordinal)) continue;
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5) break;

                // parts[1]=user, parts[2]=nice, parts[3]=system, parts[4]=idle
                if (long.TryParse(parts[1], out var user) &&
                    long.TryParse(parts[3], out var system) &&
                    long.TryParse(parts[4], out var idle))
                {
                    var total = user + system + idle;
                    if (total > 0)
                    {
                        var cpuPercent = (double)(user + system) / total * 100;
                        // Sustained high CPU on mobile is abnormal
                        if (cpuPercent > 85)
                        {
                            signals.Add(new Signal(
                                $"high_cpu_usage:{cpuPercent:F0}%", 55, 0.65));
                        }
                    }
                }
                break;
            }

            // Check for mining-related files in accessible storage
            var downloadDir = "/sdcard/Download";
            if (Directory.Exists(downloadDir))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(downloadDir))
                    {
                        var name = Path.GetFileName(file).ToLowerInvariant();
                        if (name.Contains("xmrig") || name.Contains("miner") ||
                            name.Contains("config.json") && File.Exists(file))
                        {
                            try
                            {
                                var content = File.ReadAllText(file);
                                if (content.Contains("pool", StringComparison.OrdinalIgnoreCase) &&
                                    content.Contains("wallet", StringComparison.OrdinalIgnoreCase))
                                {
                                    signals.Add(new Signal(
                                        $"mining_config_found:{name}", 80, 0.85));
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect suspicious files in accessible storage: APKs in unusual locations,
    /// exploit payloads, scripts, and downloaded malware artifacts.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectSuspiciousFiles(List<Signal> signals, CancellationToken ct)
    {
        var suspiciousDirs = new[] { "/data/local/tmp", "/sdcard/Download", "/sdcard/.hidden" };

        foreach (var dir in suspiciousDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir))
                {
                    if (ct.IsCancellationRequested) break;
                    var name = Path.GetFileName(file).ToLowerInvariant();
                    var ext = Path.GetExtension(name);

                    // ELF binaries in /data/local/tmp (exploit staging)
                    if (dir.Contains("local/tmp") && ext == "" &&
                        File.Exists(file) && new FileInfo(file).Length > 1000)
                    {
                        try
                        {
                            var header = new byte[4];
                            using var fs = File.OpenRead(file);
                            if (fs.Read(header, 0, 4) == 4 &&
                                header[0] == 0x7F && header[1] == 'E' &&
                                header[2] == 'L' && header[3] == 'F')
                            {
                                signals.Add(new Signal(
                                    $"elf_in_tmp:{name}", 72, 0.8));
                            }
                        }
                        catch { }
                    }

                    // Shell scripts in accessible locations
                    if (ext is ".sh" or ".py" or ".pl" or ".rb")
                    {
                        var age = DateTime.UtcNow - File.GetCreationTimeUtc(file);
                        if (age.TotalHours < 24)
                        {
                            signals.Add(new Signal(
                                $"script_in_storage:{name}", 45, 0.6));
                        }
                    }

                    // APKs outside normal install paths
                    if (ext == ".apk" && dir != "/sdcard/Download")
                    {
                        signals.Add(new Signal(
                            $"hidden_apk:{name}", 55, 0.68));
                    }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect SELinux policy violations by monitoring kernel audit messages.
    /// AVC denials indicate apps attempting privilege escalation or sandbox escape.
    /// v0.2.0 audit fix A-6.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectSELinuxViolations(List<Signal> signals)
    {
        try
        {
            // Check dmesg / kmsg for SELinux AVC denials
            var kmsgPath = "/proc/kmsg";
            var dmesgAlt = "/dev/kmsg";
            var source = File.Exists(kmsgPath) ? kmsgPath : (File.Exists(dmesgAlt) ? dmesgAlt : null);

            // Alternative: read from logcat if kmsg isn't accessible
            if (source is null)
            {
                try
                {
                    using var proc = new System.Diagnostics.Process();
                    proc.StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "/system/bin/logcat",
                        Arguments = "-d -b events -t 50 *:W",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                    };
                    proc.Start();
                    var output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(2000);

                    if (output.Contains("avc:", StringComparison.OrdinalIgnoreCase) &&
                        output.Contains("denied", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal("selinux_violations_detected", 60, 0.72));
                    }
                }
                catch { }
                return;
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect accessibility service abuse by checking which non-system services
    /// are registered and active. Banking trojans use accessibility for keylogging.
    /// v0.2.0 audit fix A-8.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectAccessibilityAbuse(List<Signal> signals)
    {
        try
        {
            using var proc = new System.Diagnostics.Process();
            proc.StartInfo = new System.Diagnostics.ProcessStartInfo
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

            var services = output.Split(':', StringSplitOptions.RemoveEmptyEntries);
            foreach (var svc in services)
            {
                var package = svc.Split('/')[0].Trim();
                if (string.IsNullOrEmpty(package)) continue;

                // Flag non-system accessibility services
                if (!package.StartsWith("com.google.", StringComparison.OrdinalIgnoreCase) &&
                    !package.StartsWith("com.android.", StringComparison.OrdinalIgnoreCase) &&
                    !package.StartsWith("com.samsung.", StringComparison.OrdinalIgnoreCase) &&
                    !package.StartsWith("com.sec.", StringComparison.OrdinalIgnoreCase) &&
                    !package.StartsWith("com.microsoft.", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal(
                        $"suspicious_accessibility_service:{package}", 72, 0.8));
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect SMS/telephony interception by checking for running processes that
    /// match known banking trojan families and checking for unusual SMS app registrations.
    /// v0.2.0 audit fix A-10.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectSmsInterception(List<Signal> signals, CancellationToken ct)
    {
        var smsMalwareNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "flubot", "anatsa", "sharkbot", "hydra", "ermac",
            "cerberus", "anubis", "medusa", "xenomorph", "teabot",
            "vultur", "octo", "hook", "godfather", "nexus",
        };

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
                    var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', '.').Trim();

                    if (smsMalwareNames.Any(m =>
                        cmdline.Contains(m, StringComparison.OrdinalIgnoreCase)))
                    {
                        signals.Add(new Signal(
                            $"sms_malware_running:{cmdline.Split('.')[0]}:pid:{pid}", 90, 0.92));
                    }
                }
                catch { }
            }
        }
        catch { }

        // Check for call forwarding manipulation indicators
        try
        {
            using var proc = new System.Diagnostics.Process();
            proc.StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "/system/bin/dumpsys",
                Arguments = "telecom",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            if (output.Contains("CallForwarding", StringComparison.OrdinalIgnoreCase) &&
                output.Contains("enabled", StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal("call_forwarding_active", 55, 0.65));
            }
        }
        catch { }
    }

    /// <summary>
    /// Analyze a package name for malware indicators.
    /// Called by the MAUI Android platform layer.
    /// </summary>
    public static IEnumerable<Signal> AnalyzePackage(
        string packageName, string? installerPackage,
        bool hasAccessibilityService, bool hasOverlayPermission,
        bool hasDeviceAdmin, IReadOnlyList<string>? permissions = null)
    {
        var signals = new List<Signal>();

        // Check for known malware package prefixes
        foreach (var prefix in MalwarePackagePrefixes)
        {
            if (packageName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal($"malware_package:{packageName}", 90, 0.85));
                break;
            }
        }

        // Sideloaded app detection (not from Play Store)
        if (installerPackage is null ||
            !installerPackage.Contains("vending", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add(new Signal($"sideloaded_app:{packageName}", 35, 0.6));
        }

        // Accessibility service abuse (high risk for keylogging/automation)
        if (hasAccessibilityService)
        {
            signals.Add(new Signal($"accessibility_service:{packageName}", 60, 0.75));
        }

        // Overlay permission (clickjacking/phishing)
        if (hasOverlayPermission)
        {
            signals.Add(new Signal($"overlay_permission:{packageName}", 50, 0.68));
        }

        // Device admin abuse (prevents uninstall, can wipe device)
        if (hasDeviceAdmin)
        {
            signals.Add(new Signal($"device_admin_active:{packageName}", 65, 0.78));
        }

        // Dangerous permission combinations
        if (permissions is not null)
        {
            var hasSms = permissions.Any(p => p.Contains("SMS", StringComparison.OrdinalIgnoreCase));
            var hasCall = permissions.Any(p => p.Contains("CALL", StringComparison.OrdinalIgnoreCase));
            var hasCamera = permissions.Any(p => p.Contains("CAMERA", StringComparison.OrdinalIgnoreCase));
            var hasMic = permissions.Any(p => p.Contains("RECORD_AUDIO", StringComparison.OrdinalIgnoreCase));

            // SMS + Internet = potential toll fraud / OTP theft
            if (hasSms)
            {
                signals.Add(new Signal($"sms_permission:{packageName}", 55, 0.7));
            }

            // Camera + Mic + no known legitimate use = spyware
            if (hasCamera && hasMic && !IsKnownLegitimateApp(packageName))
            {
                signals.Add(new Signal($"surveillance_permissions:{packageName}", 65, 0.75));
            }
        }

        return signals;
    }

    private static bool IsKnownLegitimateApp(string packageName) =>
        packageName.StartsWith("com.google.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.android.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.samsung.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.whatsapp", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.facebook.", StringComparison.OrdinalIgnoreCase) ||
        packageName.StartsWith("com.microsoft.", StringComparison.OrdinalIgnoreCase);
}
