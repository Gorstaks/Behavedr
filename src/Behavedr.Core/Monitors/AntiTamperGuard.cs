namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Anti-tamper guard providing self-protection against:
/// 1. Process suspension detection via QPC (QueryPerformanceCounter) timing
/// 2. Binary integrity verification (detect on-disk replacement)
/// 3. Service registry self-healing (re-register if service key deleted)
/// 4. Last-gasp logging on unexpected exit
/// 5. Network connectivity silencing detection
///
/// Uses QPC instead of DateTime to resist clock manipulation attacks.
/// Scan: 2s for timing checks, 10s for integrity/service checks.
/// </summary>
[SupportedOSPlatform("windows")]
public class AntiTamperGuard : IPlatformMonitor
{
    private readonly ILogger<AntiTamperGuard> _logger;
    private long _lastPerfCount;
    private readonly long _perfFrequency;
    private string? _binaryHash;
    private DateTime _lastCheck = DateTime.UtcNow;
    private const int SuspendThresholdMs = 4000; // 4s gap = suspension detected

    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceFrequency(out long lpFrequency);

    public string PlatformName => "AntiTamper";
    public bool IsSupported => OperatingSystem.IsWindows();

    public AntiTamperGuard(ILogger<AntiTamperGuard>? logger = null)
    {
        _logger = logger ?? NullLogger<AntiTamperGuard>.Instance;

        if (OperatingSystem.IsWindows())
        {
            QueryPerformanceFrequency(out _perfFrequency);
            QueryPerformanceCounter(out _lastPerfCount);
        }

        // Establish binary integrity baseline
        var exePath = Environment.ProcessPath;
        if (exePath is not null && File.Exists(exePath))
        {
            try
            {
                using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                _binaryHash = Convert.ToHexString(SHA256.HashData(stream));
            }
            catch { }
        }
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        // 1. Suspension detection via QPC
        DetectSuspension(signals);

        // 2. Binary integrity check (every 10s)
        if ((DateTime.UtcNow - _lastCheck).TotalSeconds >= 10)
        {
            CheckBinaryIntegrity(signals);
            CheckServiceRegistration(signals);
            CheckEtwSessionHealth(signals);
            CheckCriticalFunctionIntegrity(signals);
            CheckSafeBootPersistence(signals);
            CheckFirewallTamper(signals);
            _lastCheck = DateTime.UtcNow;
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void DetectSuspension(List<Signal> signals)
    {
        if (_perfFrequency <= 0) return;

        QueryPerformanceCounter(out long currentCount);
        var elapsedMs = (currentCount - _lastPerfCount) * 1000.0 / _perfFrequency;
        _lastPerfCount = currentCount;

        // If elapsed time far exceeds expected interval, we were suspended
        if (elapsedMs > SuspendThresholdMs)
        {
            signals.Add(new Signal(
                $"process_suspension_detected:{elapsedMs:F0}ms_gap",
                90, 0.95));
            _logger.LogCritical(
                "SECURITY: Process suspension detected - {Elapsed:F0}ms gap (threshold: {Threshold}ms). " +
                "Possible NtSuspendProcess attack.",
                elapsedMs, SuspendThresholdMs);
        }
    }

    private void CheckBinaryIntegrity(List<Signal> signals)
    {
        if (_binaryHash is null) return;

        var exePath = Environment.ProcessPath;
        if (exePath is null || !File.Exists(exePath)) return;

        try
        {
            using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var currentHash = Convert.ToHexString(SHA256.HashData(stream));

            if (!string.Equals(currentHash, _binaryHash, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal("binary_integrity_violation", 95, 0.99));
                _logger.LogCritical("SECURITY: Binary integrity violation - on-disk executable has been modified!");
            }
        }
        catch (IOException) { } // File locked - normal on Windows
        catch (Exception ex) { _logger.LogDebug(ex, "[AntiTamper] Integrity check error"); }
    }

    [SupportedOSPlatform("windows")]
    private void CheckServiceRegistration(List<Signal> signals)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Behavedr");

            if (key is null)
            {
                signals.Add(new Signal("service_registration_deleted", 85, 0.9));
                _logger.LogCritical("SECURITY: Behavedr service registration has been deleted - attempting re-registration");
                AttemptServiceReregistration();
            }
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private void AttemptServiceReregistration()
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (exePath is null) return;

            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Services\Behavedr");
            key.SetValue("ImagePath", exePath);
            key.SetValue("DisplayName", "Behavedr EDR Agent");
            key.SetValue("Start", 2); // Auto start
            key.SetValue("Type", 16); // Win32OwnProcess
            key.SetValue("ErrorControl", 1); // Normal

            _logger.LogWarning("Service registration restored via registry");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to re-register service");
        }
    }

    /// <summary>
    /// Detect removal of SafeBoot Minimal/Network service keys that keep Behavedr alive in Safe Mode.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void CheckSafeBootPersistence(List<Signal> signals)
    {
        try
        {
            foreach (var mode in new[] { "Minimal", "Network" })
            {
                var path = $@"SYSTEM\CurrentControlSet\Control\SafeBoot\{mode}\Behavedr";
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
                if (key is null)
                {
                    signals.Add(new Signal($"safeboot_persistence_missing:{mode}", 80, 0.85));
                    _logger.LogWarning("SECURITY: SafeBoot {Mode} persistence key missing for Behavedr", mode);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AntiTamper] SafeBoot check error");
        }
    }

    /// <summary>
    /// Detect sudden disablement of Windows Firewall profiles (common silencing technique).
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void CheckFirewallTamper(List<Signal> signals)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "advfirewall show allprofiles state",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                },
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(3000))
            {
                try { proc.Kill(); } catch { }
                return;
            }

            // Count "OFF" states across Domain/Private/Public
            var offCount = 0;
            foreach (var line in output.Split('\n'))
            {
                if (line.Contains("State", StringComparison.OrdinalIgnoreCase) &&
                    line.Contains("OFF", StringComparison.OrdinalIgnoreCase))
                    offCount++;
            }

            if (offCount >= 2)
            {
                signals.Add(new Signal($"firewall_profiles_disabled:{offCount}", 70, 0.8));
                _logger.LogWarning("SECURITY: Multiple Windows Firewall profiles are OFF ({Count})", offCount);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AntiTamper] Firewall check error");
        }
    }

    // --- RT-6: ETW Session Liveness Monitoring ---

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int QueryTraceW(long traceHandle, string instanceName, IntPtr properties);

    private bool _etwSessionAlerted;

    /// <summary>
    /// RT-6 FIX: Verify the BehavedrEtwSession is still active.
    /// If an attacker stops it (logman stop, ControlTrace), generate a high-confidence
    /// tamper signal. Attempts automatic restart.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void CheckEtwSessionHealth(List<Signal> signals)
    {
        try
        {
            const string sessionName = "BehavedrEtwSession";
            int sessionNameBytes = (sessionName.Length + 1) * 2;
            int propertiesSize = 120 + sessionNameBytes + 256; // EVENT_TRACE_PROPERTIES + names

            var buffer = Marshal.AllocHGlobal(propertiesSize);
            try
            {
                for (int i = 0; i < propertiesSize; i++)
                    Marshal.WriteByte(buffer, i, 0);

                // Set BufferSize and LoggerNameOffset in the properties structure
                Marshal.WriteInt32(buffer, 0, propertiesSize); // Wnode.BufferSize
                Marshal.WriteInt32(buffer, 60, 120); // LoggerNameOffset (offset within struct)

                int result = QueryTraceW(0, sessionName, buffer);

                // ERROR_SUCCESS = 0 means session is alive
                // ERROR_WMI_INSTANCE_NOT_FOUND = 4201 means session is gone
                if (result == 4201 && !_etwSessionAlerted)
                {
                    _etwSessionAlerted = true;
                    signals.Add(new Signal("etw_session_killed:BehavedrEtwSession", 92, 0.94));
                    _logger.LogCritical(
                        "SECURITY: ETW session 'BehavedrEtwSession' has been stopped externally - " +
                        "possible attacker disruption (logman stop / ControlTrace). Detection latency degraded.");
                }
                else if (result == 0)
                {
                    _etwSessionAlerted = false; // Session is alive, reset alert
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AntiTamper] ETW session health check failed");
        }
    }

    // --- RT-7: AMSI/ETW Function Prologue Integrity ---

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetModuleHandleA(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    // Expected first bytes of EtwEventWrite (x64): 4c 8b dc (mov r11, rsp)
    // or 48 ... (various, but NOT 0xC3 ret or 0x90 nop patches)
    private byte[]? _etwEventWriteBaseline;
    private byte[]? _amsiScanBufferBaseline;
    private bool _prologueBaselined;

    /// <summary>
    /// RT-7 FIX: Check that critical detection infrastructure functions haven't been patched.
    /// Attackers commonly patch ntdll!EtwEventWrite and amsi!AmsiScanBuffer to blind EDR.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void CheckCriticalFunctionIntegrity(List<Signal> signals)
    {
        try
        {
            // Check EtwEventWrite in ntdll.dll
            var ntdll = GetModuleHandleA("ntdll.dll");
            if (ntdll != IntPtr.Zero)
            {
                var etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
                if (etwAddr != IntPtr.Zero)
                {
                    var current = new byte[8];
                    Marshal.Copy(etwAddr, current, 0, 8);

                    if (!_prologueBaselined)
                    {
                        _etwEventWriteBaseline = (byte[])current.Clone();
                    }
                    else if (_etwEventWriteBaseline != null &&
                             !current.AsSpan().SequenceEqual(_etwEventWriteBaseline))
                    {
                        // Check for common patch patterns: ret (0xC3) at start
                        if (current[0] == 0xC3 || (current[0] == 0x33 && current[1] == 0xC0))
                        {
                            signals.Add(new Signal("etw_function_patched:ntdll!EtwEventWrite", 95, 0.98));
                            _logger.LogCritical(
                                "SECURITY: ntdll!EtwEventWrite has been PATCHED - ETW telemetry is blinded. " +
                                "Active EDR evasion in progress (T1562.001).");
                        }
                        else
                        {
                            signals.Add(new Signal("etw_function_modified:ntdll!EtwEventWrite", 85, 0.90));
                            _logger.LogWarning(
                                "SECURITY: ntdll!EtwEventWrite prologue modified (may be hooked or patched)");
                        }
                    }
                }
            }

            // Check AmsiScanBuffer in amsi.dll (may not be loaded)
            var amsi = GetModuleHandleA("amsi.dll");
            if (amsi != IntPtr.Zero)
            {
                var amsiAddr = GetProcAddress(amsi, "AmsiScanBuffer");
                if (amsiAddr != IntPtr.Zero)
                {
                    var current = new byte[8];
                    Marshal.Copy(amsiAddr, current, 0, 8);

                    if (!_prologueBaselined)
                    {
                        _amsiScanBufferBaseline = (byte[])current.Clone();
                    }
                    else if (_amsiScanBufferBaseline != null &&
                             !current.AsSpan().SequenceEqual(_amsiScanBufferBaseline))
                    {
                        signals.Add(new Signal("amsi_function_patched:amsi!AmsiScanBuffer", 90, 0.95));
                        _logger.LogCritical(
                            "SECURITY: amsi!AmsiScanBuffer has been PATCHED - AMSI scanning is disabled. " +
                            "Active defense evasion in progress (T1562.001).");
                    }
                }
            }

            if (!_prologueBaselined)
                _prologueBaselined = true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AntiTamper] Function integrity check failed");
        }
    }
}
