namespace Behavedr.Core;

using System.Text;

/// <summary>
/// Detection helpers that assume attackers have read the source and will rename tools.
/// Name matches are exact (base file name only, no directory names or vague words), so
/// names alone stay low-confidence. Staging paths and dual signals are high-confidence.
/// A valid publisher signature lowers confidence but never grants immunity (Sentinel rule).
/// </summary>
public static class ThreatHeuristics
{
    /// <summary>
    /// Offensive tool names, normalized to lowercase letters and digits. Vague words such as
    /// "empire", "cobalt", "cerberus", "magisk", and "objection" were removed because they match
    /// ordinary software. Telemetry only when alone.
    /// </summary>
    public static readonly string[] KnownToolNameFragments =
    [
        "mimikatz", "meterpreter", "sliver", "cobaltstrike", "chisel", "ligolo", "linpeas",
        "winpeas", "bloodhound", "rubeus", "sharpshooter", "seatbelt", "lazagne", "nanodump",
        "hashcat", "crackmapexec", "impacket", "secretsdump", "psexec", "swiftbelt", "bifrost",
        "osascriptbackdoor", "fridaserver", "droidjack", "ahmyth", "spynote", "androrat",
        "xmrig", "ccminer",
    ];

    /// <summary>
    /// Architecture suffixes that may follow a tool name ("mimikatz_x64" normalizes to "mimikatzx64").
    /// </summary>
    private static readonly string[] AllowedNameSuffixes = ["x64", "x86", "win32", "win64", "arm64"];

    /// <summary>
    /// Optional publisher check set by the Windows agent. Returns true when a file has a valid
    /// Authenticode signature. Null on other platforms, which disables publisher trust.
    /// </summary>
    public static Func<string, bool>? IsPublisherSigned { get; set; }

    /// <summary>
    /// Paths attackers favor for droppers. Only temp-style locations count as strong staging.
    /// Downloads is a weaker marker, handled separately so ordinary installers are not treated
    /// the same as dropped payloads.
    /// </summary>
    private static readonly string[] StrongStagingMarkers =
    [
        "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
        "/dev/shm/", "/run/user/",
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\temp\\",
        "\\users\\public\\", "\\$recycle.bin\\",
        "/users/shared/", "/var/folders/",
        "/storage/emulated/0/download/", "/data/local/tmp/",
    ];

    /// <summary>
    /// Normalize a process name or path to its base name, lowercase, letters and digits only.
    /// "C:\Tools\Frida-Server.exe" becomes "fridaserver".
    /// </summary>
    internal static string NameKey(string? nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return "";

        var file = nameOrPath.Trim().Replace('/', '\\');
        int slash = file.LastIndexOf('\\');
        if (slash >= 0) file = file[(slash + 1)..];

        int dot = file.LastIndexOf('.');
        if (dot > 0) file = file[..dot];

        var sb = new StringBuilder(file.Length);
        foreach (var c in file)
        {
            if (char.IsLetterOrDigit(c))
                sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }

    public static bool MatchesKnownToolName(string? nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return false;

        // Some callers pass a command line rather than a path. Its first token is the program.
        return MatchesKey(NameKey(nameOrPath)) || MatchesKey(NameKey(FirstToken(nameOrPath)));
    }

    private static bool MatchesKey(string key)
    {
        if (key.Length == 0) return false;

        foreach (var tool in KnownToolNameFragments)
        {
            if (key == tool) return true;
            if (key.StartsWith(tool, StringComparison.Ordinal) &&
                AllowedNameSuffixes.Contains(key[tool.Length..]))
                return true;
        }
        return false;
    }

    private static string FirstToken(string s)
    {
        var t = s.Trim().TrimStart('"');
        int quote = t.IndexOf('"');
        if (quote > 0) t = t[..quote];
        int space = t.IndexOf(' ');
        return space > 0 ? t[..space] : t;
    }

    /// <summary>True when the path is in a strong staging location (temp, tmp, world-writable).</summary>
    public static bool IsStrongStagingPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.Replace('\\', '/');
        foreach (var marker in StrongStagingMarkers)
        {
            if (p.Contains(marker.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>True when the path is under a Downloads folder.</summary>
    public static bool IsDownloadsPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.Replace('\\', '/');
        return p.Contains("/Downloads/", StringComparison.OrdinalIgnoreCase) ||
               p.Contains("/Download/", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when the path is a strong staging location or a Downloads folder.</summary>
    public static bool IsStagingPath(string? path) => IsStrongStagingPath(path) || IsDownloadsPath(path);

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
        var strong = IsStrongStagingPath(path);
        var downloads = !strong && IsDownloadsPath(path);
        var exe = LooksLikeExecutableName(path) || LooksLikeExecutableName(processName);

        // A valid publisher signature lowers confidence. A signed binary still gets a weak
        // signal in a staging location, and a name hit alone is dropped.
        bool signed = !string.IsNullOrEmpty(path) && IsPublisherSigned?.Invoke(path) == true;
        if (signed)
        {
            if ((strong || downloads) && exe)
            {
                return new OffensiveScore(
                    Weight: 30,
                    Confidence: 0.5,
                    Tag: "staging_path_signed_binary",
                    Detail: $"{processName}:{Truncate(path, 64)}");
            }
            return null;
        }

        if (nameHit && strong)
        {
            return new OffensiveScore(
                Weight: 93,
                Confidence: 0.96,
                Tag: "staging_plus_known_tool_name",
                Detail: $"{processName}:{Truncate(path, 64)}");
        }

        if (strong && exe)
        {
            return new OffensiveScore(
                Weight: 78,
                Confidence: 0.88,
                Tag: "executable_from_staging_path",
                Detail: $"{processName}:{Truncate(path, 64)}");
        }

        if (nameHit && downloads)
        {
            return new OffensiveScore(
                Weight: 70,
                Confidence: 0.8,
                Tag: "known_tool_name_from_downloads",
                Detail: $"{processName}:{Truncate(path, 64)}");
        }

        if (downloads && exe)
        {
            // Installers and tools are downloaded all the time. This is context, not an alert.
            return new OffensiveScore(
                Weight: 35,
                Confidence: 0.5,
                Tag: "executable_from_downloads",
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
