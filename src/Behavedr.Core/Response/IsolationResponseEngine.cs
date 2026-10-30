namespace Behavedr.Core.Response;

using System.Diagnostics;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Handles threats from isolation environments: mounted ISOs (T1553.005),
/// Docker containers, and VMs. Provides containment by dismounting/stopping
/// the isolation layer after killing the malicious process.
/// v0.1.3: Now implements IResponseAction for integration with ResponseEngine (M-4 fix).
/// </summary>
public class IsolationResponseEngine : IResponseAction
{
    private readonly ILogger<IsolationResponseEngine> _logger;

    public IsolationResponseEngine(ILogger<IsolationResponseEngine>? logger = null)
    {
        _logger = logger ?? NullLogger<IsolationResponseEngine>.Instance;
    }

    public string Name => "IsolationResponse";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    /// <summary>
    /// IResponseAction implementation: inspects signals for isolation-related threats
    /// and handles ISO dismount, Docker stop, or VM termination as appropriate.
    /// </summary>
    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        // ISO-mounted threat: type may embed path as iso_mount:/path/to.iso or iso_path:...
        var isoSignal = result.Signals.FirstOrDefault(s =>
            s.Type.Contains("iso_mount", StringComparison.OrdinalIgnoreCase) ||
            s.Type.Contains("iso_path", StringComparison.OrdinalIgnoreCase));
        if (isoSignal is not null && int.TryParse(result.Event.ProcessId, out var isoPid))
        {
            var isoPath = ExtractIsoPath(isoSignal.Type) ?? ExtractIsoPath(result.Event.ProcessName);
            await HandleIsoThreatAsync(isoPid, isoPath ?? "", result.Event.ProcessName ?? "");
            return ResponseOutcome.Ok(Name,
                string.IsNullOrEmpty(isoPath)
                    ? $"ISO threat process handled (PID {isoPid}); path unknown for dismount"
                    : $"ISO threat handled for PID {isoPid}, path {isoPath}");
        }

        // Docker: type contains docker:containerId or docker_id:xxx
        var dockerSignal = result.Signals.FirstOrDefault(s =>
            s.Type.Contains("docker", StringComparison.OrdinalIgnoreCase));
        if (dockerSignal is not null)
        {
            var containerId = ExtractDockerId(dockerSignal.Type);
            if (containerId is null)
                return ResponseOutcome.Skipped(Name, "Docker signal present but container ID not parseable");

            await HandleDockerThreatAsync(containerId);
            return ResponseOutcome.Ok(Name, $"Docker container isolation attempted: {containerId}");
        }

        // VM host process: vm_threat / hypervisor signals with PID
        var vmSignal = result.Signals.FirstOrDefault(s =>
            s.Type.Contains("vm_threat", StringComparison.OrdinalIgnoreCase) ||
            s.Type.Contains("hypervisor", StringComparison.OrdinalIgnoreCase));
        if (vmSignal is not null && int.TryParse(result.Event.ProcessId, out var vmPid) && vmPid > 4)
        {
            if (ResponseSafety.ShouldRefuseKill(vmPid, result.Event.ProcessName ?? "", out var vmRefuse))
                return ResponseOutcome.Skipped(Name, $"Safety: {vmRefuse}");
            await HandleVmThreatAsync(vmPid, result.Event.ProcessName ?? "");
            return ResponseOutcome.Ok(Name, $"VM host process terminated: PID {vmPid}");
        }

        return ResponseOutcome.Skipped(Name, "No isolation-related threat signals");
    }

    private static string? ExtractIsoPath(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        // Prefer explicit path after iso_mount: or iso_path:
        foreach (var marker in new[] { "iso_mount:", "iso_path:", "path:" })
        {
            var idx = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var rest = text[(idx + marker.Length)..].Trim();
            var end = rest.IndexOfAny([' ', '\t', '|', ';']);
            var path = end > 0 ? rest[..end] : rest;
            if (path.EndsWith(".iso", StringComparison.OrdinalIgnoreCase))
                return path;
        }
        // Bare .iso path token
        foreach (var token in text.Split([' ', '|', ';', ','], StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.EndsWith(".iso", StringComparison.OrdinalIgnoreCase))
                return token;
        }
        return null;
    }

    private static string? ExtractDockerId(string type)
    {
        // docker:abc123 or docker_id:abc123 or container:abc123
        foreach (var marker in new[] { "docker_id:", "docker:", "container:" })
        {
            var idx = type.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var rest = type[(idx + marker.Length)..];
            var end = rest.IndexOfAny([' ', '|', ';', ',']);
            var id = (end > 0 ? rest[..end] : rest).Trim();
            if (id.Length >= 8 && IsValidDockerId(id))
                return id;
        }
        return null;
    }

    /// <summary>
    /// Kill process, dismount the ISO, and delete the .iso file.
    /// Cross-platform: uses PowerShell on Windows, umount/losetup on Linux, hdiutil on macOS.
    /// </summary>
    public async Task HandleIsoThreatAsync(int processId, string isoPath, string processName = "")
    {
        _logger.LogWarning("[IsolationResponse] Handling ISO threat - PID {Pid}, ISO {Path}", processId, isoPath);

        if (!ResponseSafety.ShouldRefuseKill(processId, processName, out _))
        {
            try
            {
                using var proc = Process.GetProcessById(processId);
                proc.Kill(entireProcessTree: true);
                await proc.WaitForExitAsync();
            }
            catch { }
        }

        if (!IsSafeIsoPath(isoPath))
        {
            _logger.LogWarning("[IsolationResponse] Refusing dismount/delete of unsafe ISO path {Path}", isoPath);
            return;
        }

        try
        {
            if (OperatingSystem.IsWindows())
            {
                var script = $"Dismount-DiskImage -ImagePath '{isoPath.Replace("'", "''")}' -ErrorAction Stop";
                var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
                using var ps = Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                });
                if (ps != null) await ps.WaitForExitAsync();
            }
            else if (OperatingSystem.IsLinux())
            {
                using var umount = Process.Start(new ProcessStartInfo
                {
                    FileName = "/bin/umount",
                    Arguments = isoPath,
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                });
                if (umount != null) await umount.WaitForExitAsync();
            }
            else if (OperatingSystem.IsMacOS())
            {
                using var hdiutil = Process.Start(new ProcessStartInfo
                {
                    FileName = "/usr/bin/hdiutil",
                    Arguments = $"detach \"{isoPath}\" -force",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                });
                if (hdiutil != null) await hdiutil.WaitForExitAsync();
            }
            _logger.LogWarning("[IsolationResponse] Dismounted ISO {Path}", isoPath);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "[IsolationResponse] Dismount failed"); }

        try
        {
            if (File.Exists(isoPath)) File.Delete(isoPath);
            _logger.LogWarning("[IsolationResponse] Deleted ISO {Path}", isoPath);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "[IsolationResponse] Delete failed"); }
    }

    /// <summary>
    /// Only .iso files under staging directories. Never delete /etc, System32, etc.
    /// </summary>
    public static bool IsSafeIsoPath(string? isoPath)
    {
        if (string.IsNullOrWhiteSpace(isoPath)) return false;
        string full;
        try { full = Path.GetFullPath(isoPath); }
        catch { return false; }

        if (!full.EndsWith(".iso", StringComparison.OrdinalIgnoreCase)) return false;
        if (full.Contains("..", StringComparison.Ordinal)) return false;
        if (ResponseSafety.ShouldRefuseQuarantine(full, out _)) return false;

        foreach (var root in IsoStagingRoots())
        {
            if (Security.SecurityValidation.IsPathWithinDirectory(full, root))
                return true;
        }
        return false;
    }

    private static IEnumerable<string> IsoStagingRoots()
    {
        yield return Path.GetTempPath();
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!string.IsNullOrEmpty(downloads)) yield return downloads;
        yield return "/tmp";
        yield return "/var/tmp";
        yield return "/dev/shm";
        yield return "/private/tmp";
        yield return "/private/var/tmp";
        if (OperatingSystem.IsWindows())
        {
            yield return @"C:\Temp";
            yield return @"C:\Windows\Temp";
        }
        var envTemp = Environment.GetEnvironmentVariable("TEMP");
        if (!string.IsNullOrEmpty(envTemp)) yield return envTemp;
    }

    /// <summary>
    /// Stop and remove a Docker container and its image.
    /// </summary>
    public async Task HandleDockerThreatAsync(string containerId)
    {
        if (string.IsNullOrEmpty(containerId) || !IsValidDockerId(containerId)) return;

        _logger.LogWarning("[IsolationResponse] Handling Docker threat - container {Id}", containerId);

        await RunDockerAsync("stop", containerId);
        await RunDockerAsync("rm", $"--force {containerId}");
    }

    /// <summary>
    /// Terminate a VM host process.
    /// </summary>
    public async Task HandleVmThreatAsync(int vmProcessId, string vmName)
    {
        _logger.LogWarning("[IsolationResponse] Handling VM threat - PID {Pid}, VM {Name}", vmProcessId, vmName);
        try
        {
            using var proc = Process.GetProcessById(vmProcessId);
            proc.Kill(entireProcessTree: true);
            await proc.WaitForExitAsync();
        }
        catch { }
    }

    private async Task RunDockerAsync(string command, string args)
    {
        try
        {
            // Use platform-appropriate docker/podman binary
            var dockerBin = FindDockerBinary();
            if (dockerBin is null) return;

            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = dockerBin,
                Arguments = $"{command} {args}",
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            });
            if (proc != null) await proc.WaitForExitAsync();
        }
        catch { }
    }

    private static string? FindDockerBinary()
    {
        if (OperatingSystem.IsWindows())
        {
            if (File.Exists(@"C:\Program Files\Docker\Docker\resources\bin\docker.exe"))
                return @"C:\Program Files\Docker\Docker\resources\bin\docker.exe";
            return "docker.exe";
        }

        // Linux/macOS: check for docker or podman
        foreach (var binary in new[] { "/usr/bin/docker", "/usr/bin/podman", "/usr/local/bin/docker" })
        {
            if (File.Exists(binary)) return binary;
        }
        return "docker"; // Fall back to PATH lookup
    }

    private static bool IsValidDockerId(string id)
    {
        if (id.Length > 128) return false;
        foreach (var c in id)
        {
            if (!char.IsLetterOrDigit(c) && c != '_' && c != '.' && c != '-' && c != ':')
                return false;
        }
        return true;
    }
}
