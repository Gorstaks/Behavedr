namespace Behavedr.Core;

/// <summary>
/// Detection helpers that assume attackers have read the source and will rename tools.
/// Name substrings alone are low-confidence; staging paths and dual signals are high-confidence.
/// </summary>
public static class ThreatHeuristics
{
    /// <summary>Known offensive tool name fragments - telemetry only when alone.</summary>
    public static readonly string[] KnownToolNameFragments =
    [
        // Desktop / cross-platform (name alone = low weight in Evaluate)
        "mimikatz", "meterpreter", "empire", "sliver", "cobalt", "cobaltstrike",
        "chisel", "ligolo", "linpeas", "winpeas", "bloodhound", "rubeus",
        "sharpshooter", "seatbelt", "lazagne", "nanodump", "hashcat",
        "crackmapexec", "impacket", "secretsdump", "psexec",
        "swiftbelt", "bifrost", "osascript_backdoor",
        // Android-oriented
        "frida", "frida-server", "objection", "droidjack", "ahmyth", "spynote",
        "androrat", "cerberus", "xmrig", "ccminer", "magisk",
    ];

    /// <summary>
    /// Paths attackers favor for droppers. High confidence when an executable lands here.
    /// Not exhaustive; renames still hit path risk.
    /// </summary>
    private static readonly string[] StagingPathMarkers =
    [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/dev/shm/", "/run/user/",
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\temp\\",
        "\\users\\public\\", "\\$recycle.bin\\",
        "/users/shared/", "/var/folders/", // macOS cache-like
        "/storage/emulated/0/download/", "/data/local/tmp/",
    ];

    public static bool MatchesKnownToolName(string? nameOrPath)
    {
        if (string.IsNullOrEmpty(nameOrPath)) return false;
        foreach (var t in KnownToolNameFragments)
        {
            if (nameOrPath.Contains(t, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static bool IsStagingPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.Replace('/', '\\');
        var lower = path; // check both styles
        foreach (var m in StagingPathMarkers)
        {
            if (path.Contains(m, StringComparison.OrdinalIgnoreCase) ||
                p.Contains(m.Replace('/', '\\'), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        // World-writable home downloads
        if (path.Contains("/Downloads/", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\Download\\", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    public static bool LooksLikeExecutableName(string? nameOrPath)
    {
        if (string.IsNullOrEmpty(nameOrPath)) return false;
        var f = Path.GetFileName(nameOrPath);
        return f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".scr", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".hta", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".dmg", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".pkg", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".sh", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".so", StringComparison.OrdinalIgnoreCase)
               || f.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase)
               || (!f.Contains('.') && f.Length > 0); // unix binaries often no extension
    }

    /// <summary>
    /// Score offensive-tool-like activity without relying on a single renameable name.
    /// Returns null if nothing noteworthy.
    /// </summary>
    public static OffensiveScore? Evaluate(string? processName, string? path)
    {
        var nameHit = MatchesKnownToolName(processName) || MatchesKnownToolName(path);
        var staging = IsStagingPath(path);
        var exe = LooksLikeExecutableName(path) || LooksLikeExecutableName(processName);

        if (nameHit && staging)
        {
            return new OffensiveScore(
                Weight: 93,
                Confidence: 0.96,
                Tag: "staging_plus_known_tool_name",
                Detail: $"{processName}:{Truncate(path, 64)}");
        }

        if (staging && exe)
        {
            return new OffensiveScore(
                Weight: 78,
                Confidence: 0.88,
                Tag: "executable_from_staging_path",
                Detail: $"{processName}:{Truncate(path, 64)}");
        }

        if (nameHit)
        {
            // Rename-resistant attackers skip this - keep low so FPs don't weaponize kill
            return new OffensiveScore(
                Weight: 42,
                Confidence: 0.55,
                Tag: "known_tool_name_only",
                Detail: processName ?? path ?? "");
        }

        return null;
    }

    private static string Truncate(string? s, int n) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= n ? s : s[..n];

    public readonly record struct OffensiveScore(int Weight, double Confidence, string Tag, string Detail);
}
