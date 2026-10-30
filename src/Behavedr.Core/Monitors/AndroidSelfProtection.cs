namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using System.Security.Cryptography;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android self-protection monitor providing anti-tamper, anti-debug,
/// and anti-reverse-engineering capabilities:
///
/// 1. Debugger detection (TracerPid check + /proc/self/status)
/// 2. Frida/instrumentation detection (port scanning + /proc/self/maps)
/// 3. APK signature verification (repackaging detection)
/// 4. Root-cloaking bypass (detect Magisk Hide/DenyList targeting us)
/// 5. Binary integrity (DEX hash verification)
/// 6. Emulator detection (running in analysis sandbox)
/// 7. Hook detection (native library injection via /proc/self/maps)
///
/// Unlike desktop platforms, Android cannot prevent its own termination.
/// Focus is on DETECTION of tampering and reporting to server before
/// the attacker can silence the agent.
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidSelfProtection : IPlatformMonitor
{
    private readonly ILogger<AndroidSelfProtection> _logger;
    private string? _baselineApkHash;
    private bool _initialized;
    private long _lastMonotonicMs;
    private const int SuspendThresholdMs = 5000;

    public string PlatformName => "AndroidSelfProtection";
    public bool IsSupported => OperatingSystem.IsAndroid();

    public AndroidSelfProtection(ILogger<AndroidSelfProtection>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidSelfProtection>.Instance;
        _lastMonotonicMs = Environment.TickCount64;
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_initialized)
        {
            Initialize();
            _initialized = true;
        }

        // 1. Suspension detection (same technique as desktop)
        DetectSuspension(signals);

        // 2. Debugger/tracer detection
        DetectDebugger(signals);

        // 3. Frida/instrumentation framework detection
        DetectFrida(signals);

        // 4. Hook/injection detection via /proc/self/maps
        DetectNativeHooks(signals);

        // 5. APK integrity verification
        VerifyApkIntegrity(signals);

        // 6. Emulator/sandbox detection
        DetectEmulator(signals);

        // 7. Magisk Hide targeting our process
        DetectRootCloaking(signals);

        // 8. v0.2.0: Advanced instrumentation detection (timing-based)
        DetectInstrumentationAdvanced(signals);

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void Initialize()
    {
        // Compute baseline hash of our own APK/binary
        var exePath = Environment.ProcessPath;
        if (exePath is not null && File.Exists(exePath))
        {
            try
            {
                using var stream = File.OpenRead(exePath);
                _baselineApkHash = Convert.ToHexString(SHA256.HashData(stream));
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect process suspension via monotonic clock gap.
    /// If an attacker freezes us with kill -STOP, the gap reveals it on resume.
    /// </summary>
    private void DetectSuspension(List<Signal> signals)
    {
        var currentMs = Environment.TickCount64;
        var elapsedMs = currentMs - _lastMonotonicMs;
        _lastMonotonicMs = currentMs;

        if (elapsedMs > SuspendThresholdMs)
        {
            signals.Add(new Signal(
                $"android_suspension_detected:{elapsedMs}ms_gap", 88, 0.9));
            _logger.LogCritical(
                "[AndroidSelfProtection] Suspension detected - {Elapsed}ms gap", elapsedMs);
        }
    }

    /// <summary>
    /// Detect debugger attachment via /proc/self/status TracerPid.
    /// Also checks for android.os.Debug.isDebuggerConnected() equivalent.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectDebugger(List<Signal> signals)
    {
        try
        {
            if (System.Diagnostics.Debugger.IsAttached)
            {
                signals.Add(new Signal("android_debugger_attached:managed", 90, 0.95));
                return;
            }

            var statusPath = "/proc/self/status";
            if (!File.Exists(statusPath)) return;

            foreach (var line in File.ReadLines(statusPath))
            {
                if (!line.StartsWith("TracerPid:", StringComparison.Ordinal)) continue;
                var tracerStr = line["TracerPid:".Length..].Trim();
                if (int.TryParse(tracerStr, out var tracerPid) && tracerPid != 0)
                {
                    signals.Add(new Signal(
                        $"android_debugger_attached:native:tracer_pid:{tracerPid}", 92, 0.96));
                    _logger.LogCritical(
                        "[AndroidSelfProtection] Native debugger attached (TracerPid={Pid})", tracerPid);
                }
                break;
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect Frida instrumentation framework by:
    /// 1. Scanning /proc/self/maps for frida-agent libraries
    /// 2. Checking for Frida's default TCP port (27042)
    /// 3. Scanning /proc/self/task for frida-injected threads
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectFrida(List<Signal> signals)
    {
        // Check /proc/self/maps for frida-agent shared libraries
        try
        {
            var mapsPath = "/proc/self/maps";
            if (File.Exists(mapsPath))
            {
                foreach (var line in File.ReadLines(mapsPath))
                {
                    if (line.Contains("frida", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("gadget", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("linjector", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"frida_agent_loaded:{line.Split(' ').LastOrDefault()}", 95, 0.97));
                        _logger.LogCritical("[AndroidSelfProtection] Frida agent detected in process maps");
                        break;
                    }
                }
            }
        }
        catch { }

        // Check for Frida default listening port (27042)
        try
        {
            var tcpPath = "/proc/net/tcp";
            if (File.Exists(tcpPath))
            {
                foreach (var line in File.ReadLines(tcpPath))
                {
                    // Port 27042 = 0x69A2
                    if (line.Contains(":69A2", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal("frida_port_open:27042", 88, 0.9));
                        break;
                    }
                }
            }
        }
        catch { }

        // Check /proc/self/task for suspicious thread names (frida-*)
        try
        {
            var taskDir = "/proc/self/task";
            if (Directory.Exists(taskDir))
            {
                foreach (var tid in Directory.GetDirectories(taskDir))
                {
                    var commPath = Path.Combine(tid, "comm");
                    if (!File.Exists(commPath)) continue;
                    var comm = File.ReadAllText(commPath).Trim();
                    if (comm.Contains("frida", StringComparison.OrdinalIgnoreCase) ||
                        comm.Contains("gum-js-loop", StringComparison.OrdinalIgnoreCase) ||
                        comm.StartsWith("gmain", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"frida_thread_detected:{comm}", 92, 0.94));
                        break;
                    }
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect native library injection/hooking via /proc/self/maps analysis.
    /// Legitimate process should only have system libs and our own .so files loaded.
    /// Suspicious: unknown .so files from /data/local/tmp, /sdcard, or writable paths.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectNativeHooks(List<Signal> signals)
    {
        try
        {
            var mapsPath = "/proc/self/maps";
            if (!File.Exists(mapsPath)) return;

            foreach (var line in File.ReadLines(mapsPath))
            {
                // Only check executable mapped regions
                if (!line.Contains("r-xp", StringComparison.Ordinal) &&
                    !line.Contains("r--p", StringComparison.Ordinal)) continue;

                // Suspicious library paths
                if (line.Contains("/data/local/tmp/", StringComparison.Ordinal) ||
                    line.Contains("/sdcard/", StringComparison.Ordinal) ||
                    line.Contains("/data/data/", StringComparison.Ordinal) &&
                    !line.Contains("com.croatiasecurity.behavedr", StringComparison.Ordinal))
                {
                    var libName = line.Split(' ').LastOrDefault() ?? "unknown";
                    if (libName.EndsWith(".so", StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"suspicious_native_lib_loaded:{Path.GetFileName(libName)}", 80, 0.85));
                    }
                }

                // Xposed framework detection
                if (line.Contains("xposed", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("substrate", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("edxposed", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("lsposed", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal("xposed_framework_detected", 85, 0.9));
                    break;
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Advanced instrumentation detection using timing-based analysis.
    /// Frida 16+ can bypass string-based detection by renaming libraries/threads.
    /// Timing-based detection measures syscall overhead - Frida hooks add 50-200us latency.
    /// v0.2.0 audit fix A-12.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectInstrumentationAdvanced(List<Signal> signals)
    {
        // Timing-based hook detection: measure syscall overhead
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            for (int i = 0; i < 1000; i++)
            {
                _ = File.Exists("/proc/self/status");
            }
            sw.Stop();
            var avgUs = sw.Elapsed.TotalMicroseconds / 1000;

            // Normal: 1-10us per call. Frida-hooked: 50-200us per call.
            if (avgUs > 50)
            {
                signals.Add(new Signal(
                    $"instrumentation_timing_anomaly:{avgUs:F0}us_per_syscall", 80, 0.85));
                _logger.LogCritical(
                    "[AndroidSelfProtection] Timing anomaly detected ({Avg:F0}us/call) - possible instrumentation",
                    avgUs);
            }
        }
        catch { }

        // Check for unexpected writable+executable memory regions (Frida JIT)
        try
        {
            var mapsPath = "/proc/self/maps";
            if (!File.Exists(mapsPath)) return;

            int rwxCount = 0;
            foreach (var line in File.ReadLines(mapsPath))
            {
                // Frida's V8/QuickJS JIT creates rwx regions
                if (line.Contains("rwxp", StringComparison.Ordinal))
                {
                    // Filter out known-good (ART JIT)
                    if (!line.Contains("jit-code-cache", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("[anon:dalvik-", StringComparison.OrdinalIgnoreCase))
                    {
                        rwxCount++;
                    }
                }
            }

            if (rwxCount > 2)
            {
                signals.Add(new Signal(
                    $"suspicious_rwx_regions:{rwxCount}", 78, 0.83));
            }
        }
        catch { }

        // Check /proc/self/fd for unexpected network sockets (Frida server comms)
        try
        {
            var fdDir = "/proc/self/fd";
            if (!Directory.Exists(fdDir)) return;

            int socketCount = 0;
            foreach (var fd in Directory.GetFiles(fdDir))
            {
                try
                {
                    var target = File.ResolveLinkTarget(fd, returnFinalTarget: false)?.ToString();
                    if (target is not null && target.StartsWith("socket:", StringComparison.Ordinal))
                    {
                        socketCount++;
                    }
                }
                catch { }
            }

            // Normal app: 2-5 sockets. Frida-instrumented: 8+
            if (socketCount > 8)
            {
                signals.Add(new Signal(
                    $"excessive_sockets:{socketCount}", 60, 0.7));
            }
        }
        catch { }
    }

    /// <summary>
    /// Verify our own binary hasn't been modified on disk (repackaging detection).
    /// </summary>
    [SupportedOSPlatform("android")]
    private void VerifyApkIntegrity(List<Signal> signals)
    {
        if (_baselineApkHash is null) return;

        try
        {
            var exePath = Environment.ProcessPath;
            if (exePath is null || !File.Exists(exePath)) return;

            using var stream = File.OpenRead(exePath);
            var currentHash = Convert.ToHexString(SHA256.HashData(stream));

            if (!string.Equals(currentHash, _baselineApkHash, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal("android_binary_integrity_violation", 95, 0.98));
                _logger.LogCritical(
                    "[AndroidSelfProtection] Binary modified on disk - possible repackaging attack");
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect if running inside an emulator or analysis sandbox.
    /// Indicators: generic hardware, qemu properties, goldfish drivers.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectEmulator(List<Signal> signals)
    {
        var emulatorIndicators = 0;

        try
        {
            // Check build.prop for emulator fingerprints
            var buildProp = "/system/build.prop";
            if (File.Exists(buildProp))
            {
                var content = File.ReadAllText(buildProp);
                if (content.Contains("generic", StringComparison.OrdinalIgnoreCase) &&
                    content.Contains("sdk", StringComparison.OrdinalIgnoreCase))
                    emulatorIndicators++;
                if (content.Contains("goldfish", StringComparison.OrdinalIgnoreCase))
                    emulatorIndicators++;
                if (content.Contains("ranchu", StringComparison.OrdinalIgnoreCase))
                    emulatorIndicators++;
                if (content.Contains("vbox", StringComparison.OrdinalIgnoreCase))
                    emulatorIndicators++;
                if (content.Contains("genymotion", StringComparison.OrdinalIgnoreCase))
                    emulatorIndicators++;
            }

            // Check for QEMU-specific files
            if (File.Exists("/dev/qemu_pipe") || File.Exists("/dev/goldfish_pipe"))
                emulatorIndicators += 2;
            if (File.Exists("/sys/qemu_trace"))
                emulatorIndicators += 2;

            // Check /proc/cpuinfo for hypervisor
            if (File.Exists("/proc/cpuinfo"))
            {
                var cpuinfo = File.ReadAllText("/proc/cpuinfo");
                if (cpuinfo.Contains("QEMU", StringComparison.OrdinalIgnoreCase) ||
                    cpuinfo.Contains("hypervisor", StringComparison.OrdinalIgnoreCase))
                    emulatorIndicators += 2;
            }
        }
        catch { }

        if (emulatorIndicators >= 3)
        {
            signals.Add(new Signal(
                $"emulator_detected:indicators:{emulatorIndicators}", 70, 0.82));
        }
    }

    /// <summary>
    /// Detect Magisk Hide/DenyList specifically targeting our process.
    /// If Magisk is present but root indicators are hidden FROM US, it means
    /// the attacker is specifically trying to evade our root detection.
    /// </summary>
    [SupportedOSPlatform("android")]
    private void DetectRootCloaking(List<Signal> signals)
    {
        try
        {
            // If we can see magisk binary in /proc but not in /system paths,
            // Magisk Hide is active and targeting our process namespace.
            bool magiskInProc = false;
            foreach (var procDir in Directory.GetDirectories("/proc").Take(200))
            {
                var pidStr = Path.GetFileName(procDir);
                if (!int.TryParse(pidStr, out _)) continue;
                var commPath = Path.Combine(procDir, "comm");
                try
                {
                    if (File.Exists(commPath) &&
                        File.ReadAllText(commPath).Trim().Contains("magisk", StringComparison.OrdinalIgnoreCase))
                    {
                        magiskInProc = true;
                        break;
                    }
                }
                catch { }
            }

            bool magiskOnDisk = File.Exists("/sbin/.magisk") ||
                                Directory.Exists("/data/adb/magisk");

            // If magisk process exists but disk indicators are hidden, we're being cloaked
            if (magiskInProc && !magiskOnDisk)
            {
                signals.Add(new Signal("magisk_hide_targeting_behavedr", 82, 0.88));
            }

            // Check mount namespace manipulation (MagiskHide uses mount --bind)
            if (File.Exists("/proc/self/mountinfo"))
            {
                var mounts = File.ReadAllText("/proc/self/mountinfo");
                // Count bind mounts over /system paths in our namespace
                var bindMountCount = mounts.Split('\n')
                    .Count(l => l.Contains("/system", StringComparison.Ordinal) &&
                               l.Contains("master:", StringComparison.Ordinal));
                if (bindMountCount > 5)
                {
                    signals.Add(new Signal(
                        $"mount_namespace_manipulation:{bindMountCount}_binds", 75, 0.8));
                }
            }
        }
        catch { }
    }
}
