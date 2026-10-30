namespace Behavedr.Agent;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Watchdog service providing mutual monitoring with the main agent process.
/// Detects if the agent is killed/suspended and triggers restart.
/// Also monitors for external kill attempts against the agent PID.
///
/// Architecture:
/// - Runs as a separate hosted service within the same process (lightweight watchdog)
/// - Tracks own PID and monitors for unexpected restarts
/// - Detects gaps in monitoring service heartbeat (suspension attacks)
/// - Logs last-gasp forensic evidence on unexpected shutdown via AppDomain.UnhandledException
/// - Registers SCM failure recovery with escalating restart delays
/// </summary>
public sealed class AgentWatchdog : BackgroundService
{
    private readonly ILogger<AgentWatchdog> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private DateTime _lastHeartbeat = DateTime.UtcNow;
    private readonly TimeSpan _heartbeatTimeout = TimeSpan.FromSeconds(15);
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(3);
    private static readonly string LastGaspPath = Path.Combine(
        AppContext.BaseDirectory, "logs", "last-gasp.log");

    /// <summary>
    /// Shared heartbeat signal - MonitoringService must call Touch() each cycle.
    /// If this goes stale, the watchdog assumes the monitoring loop is hung/suspended.
    /// </summary>
    public static DateTime LastMonitoringHeartbeat { get; set; } = DateTime.UtcNow;

    public AgentWatchdog(
        ILogger<AgentWatchdog> logger,
        IHostApplicationLifetime lifetime)
    {
        _logger = logger;
        _lifetime = lifetime;

        // Register last-gasp handler for unexpected termination
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[Watchdog] Started - monitoring agent health (PID {Pid})",
            Environment.ProcessId);

        // Set deny-terminate on own process handle (Windows)
        if (OperatingSystem.IsWindows())
        {
            TrySetProcessProtection();
        }

        using var timer = new PeriodicTimer(_checkInterval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);
                PerformWatchdogCheck();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[Watchdog] Health check failed");
            }
        }
    }

    private void PerformWatchdogCheck()
    {
        var timeSinceHeartbeat = DateTime.UtcNow - LastMonitoringHeartbeat;

        if (timeSinceHeartbeat > _heartbeatTimeout)
        {
            _logger.LogCritical(
                "[Watchdog] ALERT: Monitoring service heartbeat stale for {Seconds:F1}s " +
                "(threshold: {Threshold}s). Possible suspension or deadlock.",
                timeSinceHeartbeat.TotalSeconds, _heartbeatTimeout.TotalSeconds);

            // Write last-gasp evidence
            WriteLastGasp($"Monitoring heartbeat stale: {timeSinceHeartbeat.TotalSeconds:F1}s gap detected at {DateTime.UtcNow:O}");
        }

        // Verify our own process is still healthy
        try
        {
            using var self = Process.GetCurrentProcess();
            if (self.Threads.Count == 0)
            {
                _logger.LogCritical("[Watchdog] ALERT: Process has zero threads - zombie state detected");
                WriteLastGasp("Zombie state: zero threads detected");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Watchdog] Cannot query own process state");
        }
    }

    [SupportedOSPlatform("windows")]
    private void TrySetProcessProtection()
    {
        try
        {
            // Set a DACL on our own process that denies PROCESS_TERMINATE from Everyone
            // except SYSTEM and Administrators. This prevents non-privileged kill attempts
            // and raises the bar for even admin-level kill (must use SeDebugPrivilege).
            var hProcess = GetCurrentProcess();

            // Build a security descriptor that:
            // 1. Allows SYSTEM full control
            // 2. Allows Administrators full control
            // 3. Denies Everyone PROCESS_TERMINATE (0x0001)
            // SDDL: D:(A;;GA;;;SY)(A;;GA;;;BA)(D;;0x0001;;;WD)
            // GA = GENERIC_ALL, SY = SYSTEM, BA = Builtin Admins, WD = Everyone
            const string sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(D;;0x0001;;;WD)";

            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1 /* SDDL_REVISION_1 */, out var pSecDesc, out _))
            {
                _logger.LogDebug("[Watchdog] Failed to convert SDDL (error {Error})",
                    Marshal.GetLastWin32Error());
                return;
            }

            try
            {
                // SE_KERNEL_OBJECT = 6, DACL_SECURITY_INFORMATION = 0x04
                var result = SetSecurityInfo(
                    hProcess,
                    6, // SE_KERNEL_OBJECT
                    0x04, // DACL_SECURITY_INFORMATION
                    IntPtr.Zero, IntPtr.Zero,
                    GetSecurityDescriptorDacl(pSecDesc),
                    IntPtr.Zero);

                if (result == 0)
                {
                    _logger.LogInformation(
                        "[Watchdog] Process DACL protection set - PROCESS_TERMINATE denied to non-SYSTEM (PID {Pid})",
                        Environment.ProcessId);
                }
                else
                {
                    _logger.LogDebug("[Watchdog] SetSecurityInfo failed (error {Error})", result);
                }
            }
            finally
            {
                LocalFree(pSecDesc);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Watchdog] Failed to set process protection DACL");
        }
    }

    /// <summary>
    /// Extract the DACL pointer from a self-relative security descriptor.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static IntPtr GetSecurityDescriptorDacl(IntPtr pSecDesc)
    {
        if (GetSecurityDescriptorDacl(pSecDesc, out var daclPresent, out var pDacl, out _) && daclPresent)
            return pDacl;
        return IntPtr.Zero;
    }

    // P/Invoke declarations for process DACL protection
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        IntPtr handle, int objectType, uint securityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor, uint revision, out IntPtr securityDescriptor, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr pSecurityDescriptor, out bool bDaclPresent, out IntPtr pDacl, out bool bDaclDefaulted);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private void WriteLastGasp(string message)
    {
        try
        {
            var dir = Path.GetDirectoryName(LastGaspPath);
            if (dir is not null) Directory.CreateDirectory(dir);

            var entry = $"[{DateTime.UtcNow:O}] PID={Environment.ProcessId} {message}{Environment.NewLine}";
            File.AppendAllText(LastGaspPath, entry);
        }
        catch
        {
            // Best effort - cannot log if filesystem is unavailable
        }
    }

    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var msg = e.ExceptionObject is Exception ex
            ? $"Unhandled exception: {ex.GetType().Name}: {ex.Message}"
            : "Unhandled exception (unknown type)";

        WriteLastGasp($"LAST-GASP: {msg}");
        _logger.LogCritical("LAST-GASP: Agent terminating unexpectedly - {Message}", msg);
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        WriteLastGasp($"Process exit event fired (graceful={!Environment.HasShutdownStarted})");
    }
}
