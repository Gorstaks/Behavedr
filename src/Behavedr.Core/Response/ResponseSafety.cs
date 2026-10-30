namespace Behavedr.Core.Response;

using System.Diagnostics;

/// <summary>
/// Hard safety rails for response actions. Attackers who read the threat model
/// should not be able to:
/// - Force the agent to kill itself or its install tree
/// - Gain kill-immunity by renaming malware to "explorer" / "Behavedr" under Temp
/// - Quarantine the agent binary or critical OS paths
/// - Network-block the agent image
/// </summary>
public static class ResponseSafety
{
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows kernel / session
        "system", "idle", "csrss", "wininit", "winlogon", "lsass", "services",
        "smss", "svchost", "dwm", "fontdrvhost", "sihost", "taskhostw",
        "registry", "memory compression", "secure system",
        // Shell (only when path-verified as system image)
        "explorer",
        // Linux / macOS init & desktop
        "init", "systemd", "launchd", "kernel_task", "loginwindow",
        "WindowServer", "kernel", "kthreadd",
        // Our product (name alone is NOT enough - path verified separately)
        "behavedr", "behavedr.agent", "behavedr.es",
    };

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd(Path.DirectorySeparatorChar)
        + Path.DirectorySeparatorChar;

    private static readonly string[] UnixSystemPrefixes =
    {
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/usr/libexec/", "/System/", "/Library/Apple/",
        "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
        "/System/Library/",
    };

    /// <summary>Never kill this PID (self, system, path-verified protected).</summary>
    public static bool ShouldRefuseKill(int pid, string processName, out string reason)
    {
        reason = "";

        if (pid <= 0)
        {
            reason = "invalid pid";
            return true;
        }

        // Hard floor: kernel / early boot / init
        if (OperatingSystem.IsWindows() && pid <= 4)
        {
            reason = "windows system PID";
            return true;
        }
        if (OperatingSystem.IsLinux() && pid <= 1)
        {
            reason = "linux init/kthreadd";
            return true;
        }
        if (OperatingSystem.IsMacOS() && pid <= 1)
        {
            reason = "macos kernel/launchd";
            return true;
        }

        // Never kill ourselves or our parent (service host / launchd supervision)
        if (pid == Environment.ProcessId)
        {
            reason = "own process";
            return true;
        }

        // Refuse killing our parent PID when discoverable (SCM / systemd / launchd host)
        var parentPid = TryGetParentProcessId(Environment.ProcessId);
        if (parentPid is > 0 && parentPid == pid)
        {
            reason = "parent process (service host)";
            return true;
        }

        string? imagePath = null;
        try
        {
            using var p = Process.GetProcessById(pid);
            imagePath = TryGetImagePath(p);
            // Re-check self via image (renamed agent still protected if under install tree)
            if (IsOwnAgentImage(imagePath))
            {
                reason = "agent install image";
                return true;
            }
        }
        catch
        {
            // Process may have exited - allow caller to handle
        }

        if (IsOwnAgentImage(imagePath))
        {
            reason = "agent install image";
            return true;
        }

        // Protected names ONLY when the image is a real OS system path.
        // "explorer.exe" in %TEMP% is NOT protected (rename immunity denied).
        // Path containing the word "Behavedr" under Temp is NOT protected.
        if (ProtectedProcessNames.Contains(processName) ||
            ProtectedProcessNames.Contains(Path.GetFileNameWithoutExtension(processName)))
        {
            if (imagePath is not null && IsOsSystemImagePath(imagePath))
            {
                reason = $"protected system process ({processName})";
                return true;
            }
            // Spoofed name outside system path -> do not refuse (allow kill)
            return false;
        }

        return false;
    }

    public static bool ShouldRefuseQuarantine(string filePath, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(filePath))
        {
            reason = "empty path";
            return true;
        }

        string full;
        try { full = Path.GetFullPath(filePath); }
        catch
        {
            reason = "invalid path";
            return true;
        }

        if (IsOwnAgentImage(full))
        {
            reason = "agent binary/install tree";
            return true;
        }

        // Never quarantine critical system trees
        if (IsOsSystemImagePath(full))
        {
            // Allow quarantine only for non-PE/scripts under system? Safer: refuse all system paths
            reason = "system path";
            return true;
        }

        // Never quarantine inside our own quarantine dir (loops)
        var q = Path.Combine(AppContext.BaseDirectory, "quarantine");
        try
        {
            if (full.StartsWith(Path.GetFullPath(q), StringComparison.OrdinalIgnoreCase))
            {
                reason = "already under quarantine";
                return true;
            }
        }
        catch { /* ignore */ }

        return false;
    }

    public static bool ShouldRefuseAppNetworkBlock(string imagePath, out string reason)
    {
        reason = "";
        if (IsOwnAgentImage(imagePath))
        {
            reason = "agent image";
            return true;
        }
        if (IsOsSystemImagePath(imagePath))
        {
            // Blocking svchost/system network is catastrophic
            reason = "system image";
            return true;
        }
        return false;
    }

    /// <summary>
    /// True only for our agent binaries under install roots or the running module.
    /// NOT any path that merely contains the string "Behavedr" (blocks Temp\Behavedr_evil.exe immunity).
    /// </summary>
    public static bool IsOwnAgentImage(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return false;

        string full;
        try { full = Path.GetFullPath(imagePath); }
        catch { return false; }

        try
        {
            using var self = Process.GetCurrentProcess();
            var selfPath = self.MainModule?.FileName;
            if (!string.IsNullOrEmpty(selfPath) &&
                string.Equals(Path.GetFullPath(selfPath), full, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        catch { /* ignore */ }

        var file = Path.GetFileName(full);
        var isAgentBinary =
            file.Equals("Behavedr.exe", StringComparison.OrdinalIgnoreCase) ||
            file.Equals("Behavedr", StringComparison.OrdinalIgnoreCase) ||
            file.Equals("Behavedr.dll", StringComparison.OrdinalIgnoreCase) ||
            file.Equals("libbehavedr_es.dylib", StringComparison.OrdinalIgnoreCase) ||
            file.StartsWith("Behavedr.", StringComparison.OrdinalIgnoreCase);

        if (!isAgentBinary)
            return false;

        foreach (var root in AgentInstallRoots())
        {
            if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>OS-owned system binaries only (not product name tricks).</summary>
    public static bool IsOsSystemImagePath(string imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return false;

        string full;
        try { full = Path.GetFullPath(imagePath); }
        catch { return false; }

        if (OperatingSystem.IsWindows())
        {
            if (full.StartsWith(WinDir, StringComparison.OrdinalIgnoreCase))
                return true;
            // System32 / SysWOW64 already under WinDir
            return false;
        }

        var normalized = full.Replace('\\', '/');
        foreach (var prefix in UnixSystemPrefixes)
        {
            if (normalized.StartsWith(prefix, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static IEnumerable<string> AgentInstallRoots()
    {
        yield return AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        yield return "/opt/behavedr/";
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrEmpty(pf))
            yield return Path.Combine(pf, "Behavedr") + Path.DirectorySeparatorChar;
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrEmpty(pf86))
            yield return Path.Combine(pf86, "Behavedr") + Path.DirectorySeparatorChar;
    }

    private static string? TryGetImagePath(Process p)
    {
        try
        {
            return p.MainModule?.FileName;
        }
        catch
        {
            if (OperatingSystem.IsLinux())
            {
                try
                {
                    return File.ResolveLinkTarget($"/proc/{p.Id}/exe", returnFinalTarget: true)?.FullName;
                }
                catch { /* ignore */ }
            }
            return null;
        }
    }

    private static int? TryGetParentProcessId(int pid)
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                // /proc/pid/stat: pid (comm) state ppid ...
                var stat = File.ReadAllText($"/proc/{pid}/stat");
                var close = stat.LastIndexOf(')');
                if (close < 0) return null;
                var rest = stat[(close + 1)..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                // fields after ')': state, ppid -> index 1
                if (rest.Length >= 2 && int.TryParse(rest[1], out var ppid))
                    return ppid;
            }
            else if (OperatingSystem.IsWindows())
            {
                // Toolhelp is heavy; skip if unavailable. Image/self checks still apply.
                return null;
            }
        }
        catch { /* ignore */ }
        return null;
    }
}
