namespace Behavedr.Core.Response;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Terminates a process when president-kill criteria are met.
/// Hard rails: never kill self, parent, agent install image, or path-verified OS processes.
/// Spoofed names under Temp do not receive protection.
/// </summary>
public class ProcessKillAction : IResponseAction
{
    private readonly ILogger<ProcessKillAction> _logger;

    public ProcessKillAction(ILogger<ProcessKillAction>? logger = null)
    {
        _logger = logger ?? NullLogger<ProcessKillAction>.Instance;
    }

    public string Name => "ProcessKill";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    /// <summary>
    /// V-1: residual TOCTOU between path check and kill (mitigated with pidfd on Linux).
    /// </summary>
    public Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        var processName = result.Event.ProcessName ?? "";
        var processId = result.Event.ProcessId;

        if (!int.TryParse(processId, out var pid))
            return Task.FromResult(ResponseOutcome.Failed(Name, $"Invalid process ID: {processId}"));

        if (ResponseSafety.ShouldRefuseKill(pid, processName, out var refuseReason))
        {
            _logger.LogWarning("Refusing kill PID {Pid} ({Name}): {Reason}", pid, processName, refuseReason);
            return Task.FromResult(ResponseOutcome.Skipped(Name, $"Safety: {refuseReason}"));
        }

        try
        {
            var process = Process.GetProcessById(pid);

            if (!string.IsNullOrEmpty(processName) &&
                !process.ProcessName.Equals(processName, StringComparison.OrdinalIgnoreCase) &&
                !process.ProcessName.Equals(Path.GetFileNameWithoutExtension(processName), StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("PID {Pid} no longer matches expected process {Expected}, now {Actual}",
                    pid, processName, process.ProcessName);
                return Task.FromResult(ResponseOutcome.Skipped(Name,
                    $"PID reused: expected {processName}, found {process.ProcessName}"));
            }

            // Re-check safety with live image path
            try
            {
                var livePath = process.MainModule?.FileName;
                if (ResponseSafety.IsOwnAgentImage(livePath) ||
                    (livePath is not null && ResponseSafety.IsOsSystemImagePath(livePath) &&
                     ResponseSafety.ShouldRefuseKill(pid, process.ProcessName, out _)))
                {
                    return Task.FromResult(ResponseOutcome.Skipped(Name, "Safety: live image re-check"));
                }
            }
            catch { /* access denied - continue with name/pid safety already applied */ }

            if (OperatingSystem.IsLinux())
            {
                var pidfdResult = TryKillViaPidfd(pid, process.ProcessName, result.Score);
                if (pidfdResult is not null)
                    return Task.FromResult(pidfdResult);
            }

            if (OperatingSystem.IsMacOS())
            {
                var verifyResult = VerifyMacOSProcessBeforeKill(pid, process.ProcessName);
                if (verifyResult is not null)
                    return Task.FromResult(verifyResult);
            }

            if (OperatingSystem.IsWindows())
            {
                try
                {
                    process.Refresh();
                    if (!string.IsNullOrEmpty(processName) &&
                        !process.ProcessName.Equals(processName, StringComparison.OrdinalIgnoreCase))
                    {
                        return Task.FromResult(ResponseOutcome.Skipped(Name,
                            $"PID reused before kill: expected {processName}, found {process.ProcessName}"));
                    }
                }
                catch (InvalidOperationException)
                {
                    return Task.FromResult(ResponseOutcome.Ok(Name,
                        $"Process {processName} (PID {pid}) already exited"));
                }
            }

            // Final self-check immediately before kill
            if (pid == Environment.ProcessId)
                return Task.FromResult(ResponseOutcome.Skipped(Name, "Safety: own process"));

            _logger.LogWarning("KILLING process: {Process} (PID {Pid}) - score={Score:F1}",
                process.ProcessName, pid, result.Score);

            process.Kill(entireProcessTree: true);

            if (process.WaitForExit(3000))
            {
                return Task.FromResult(ResponseOutcome.Ok(Name,
                    $"Killed {process.ProcessName} (PID {pid})"));
            }

            return Task.FromResult(ResponseOutcome.Ok(Name,
                $"Kill signal sent to {process.ProcessName} (PID {pid}), still exiting"));
        }
        catch (ArgumentException)
        {
            return Task.FromResult(ResponseOutcome.Ok(Name,
                $"Process {processName} (PID {pid}) already exited"));
        }
        catch (InvalidOperationException ex)
        {
            return Task.FromResult(ResponseOutcome.Failed(Name,
                $"Cannot kill {processName}: {ex.Message}"));
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return Task.FromResult(ResponseOutcome.Failed(Name,
                $"Access denied killing {processName}: {ex.Message}"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error killing {Process}", processName);
            return Task.FromResult(ResponseOutcome.Failed(Name, ex.Message));
        }
    }

    [SupportedOSPlatform("linux")]
    private ResponseOutcome? TryKillViaPidfd(int pid, string processName, double score)
    {
        try
        {
            if (ResponseSafety.ShouldRefuseKill(pid, processName, out var why))
                return ResponseOutcome.Skipped(Name, $"Safety: {why}");

            var exePath = $"/proc/{pid}/exe";
            string? resolvedPath = null;
            try
            {
                resolvedPath = File.ResolveLinkTarget(exePath, returnFinalTarget: true)?.ToString();
            }
            catch { /* ignore */ }

            if (ResponseSafety.IsOwnAgentImage(resolvedPath))
                return ResponseOutcome.Skipped(Name, "Safety: agent image via /proc/exe");

            if (resolvedPath is not null && ResponseSafety.IsOsSystemImagePath(resolvedPath))
            {
                // Only refuse if name is also protected family
                if (ResponseSafety.ShouldRefuseKill(pid, Path.GetFileNameWithoutExtension(resolvedPath), out var r2))
                    return ResponseOutcome.Skipped(Name, $"Safety: {r2}");
            }

            // NR from kernel tables (LinuxSyscallNumbers): 434/424 on x86_64 and arm64
            if (!Platform.LinuxSyscallNumbers.SupportsPidfd)
                return null;

            var pidfd = syscall_pidfd_open(Platform.LinuxSyscallNumbers.PidfdOpen, pid, 0);
            if (pidfd < 0)
                return null;

            try
            {
                // Re-check PID did not become us
                if (pid == Environment.ProcessId)
                    return ResponseOutcome.Skipped(Name, "Safety: own process");

                _logger.LogWarning(
                    "KILLING process via pidfd: {Process} (PID {Pid}) - score={Score:F1}",
                    processName, pid, score);

                const int SIGKILL = 9;
                var result = syscall_pidfd_send_signal(
                    Platform.LinuxSyscallNumbers.PidfdSendSignal, pidfd, SIGKILL, IntPtr.Zero, 0);
                if (result == 0)
                {
                    return ResponseOutcome.Ok(Name,
                        $"Killed {processName} (PID {pid}) via pidfd (race-free)");
                }

                var errno = Marshal.GetLastWin32Error();
                return ResponseOutcome.Failed(Name,
                    $"pidfd_send_signal failed for {processName} (errno {errno})");
            }
            finally
            {
                libc_close(pidfd);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[pidfd] Failed, falling back to standard kill");
            return null;
        }
    }

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern int syscall_pidfd_open(long sysno, int pid, uint flags);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern int syscall_pidfd_send_signal(long sysno, int pidfd, int sig, IntPtr info, uint flags);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int libc_close(int fd);

    [SupportedOSPlatform("macos")]
    private ResponseOutcome? VerifyMacOSProcessBeforeKill(int pid, string processName)
    {
        try
        {
            if (ResponseSafety.ShouldRefuseKill(pid, processName, out var why))
                return ResponseOutcome.Skipped(Name, $"Safety: {why}");

            var pathBuf = new byte[4096];
            var pathLen = proc_pidpath(pid, pathBuf, (uint)pathBuf.Length);
            if (pathLen <= 0)
                return null;

            var processPath = System.Text.Encoding.UTF8.GetString(pathBuf, 0, pathLen);
            if (ResponseSafety.IsOwnAgentImage(processPath))
                return ResponseOutcome.Skipped(Name, "Safety: agent image via proc_pidpath");

            var exeName = Path.GetFileNameWithoutExtension(processPath);
            if (!exeName.Contains(processName, StringComparison.OrdinalIgnoreCase) &&
                !processName.Contains(exeName, StringComparison.OrdinalIgnoreCase))
            {
                return ResponseOutcome.Skipped(Name,
                    $"PID reuse detected via proc_pidpath: expected {processName}, got {processPath}");
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    [DllImport("libproc.dylib", EntryPoint = "proc_pidpath")]
    private static extern int proc_pidpath(int pid, byte[] buffer, uint buffersize);
}
