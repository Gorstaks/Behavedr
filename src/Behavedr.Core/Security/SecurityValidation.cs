namespace Behavedr.Core.Security;

using System.Net;
using System.Text.RegularExpressions;

/// <summary>
/// Centralized input validation for security-sensitive operations.
/// Validates paths, filenames, IPs, PIDs, ports, and timestamps.
/// Prevents path traversal, command injection, and other input-based attacks.
/// </summary>
public static class SecurityValidation
{
    private static readonly Regex SafePathRegex = new(
        @"^[a-zA-Z]:\\[a-zA-Z0-9_\-\s\\\.%()\[\]]*$", RegexOptions.Compiled);

    private static readonly HashSet<string> WindowsReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"
    };

    /// <summary>Validates a filename is safe (no traversal, no reserved names).</summary>
    public static bool IsSafeFilename(string? filename)
    {
        if (string.IsNullOrWhiteSpace(filename)) return false;
        if (filename.Contains('\0')) return false;
        if (filename.Contains('/') || filename.Contains('\\')) return false;
        if (filename.Contains("..")) return false;

        foreach (var c in new[] { '<', '>', '|', '*', '?', '"', ':' })
            if (filename.Contains(c)) return false;

        var nameOnly = Path.GetFileNameWithoutExtension(filename);
        if (WindowsReservedNames.Contains(nameOnly)) return false;

        return true;
    }

    /// <summary>Validates that a full path stays within an expected directory.</summary>
    public static bool IsPathWithinDirectory(string? fullPath, string? expectedDir)
    {
        if (string.IsNullOrWhiteSpace(fullPath) || string.IsNullOrWhiteSpace(expectedDir))
            return false;
        try
        {
            var normalizedPath = Path.GetFullPath(fullPath);
            var normalizedDir = Path.GetFullPath(expectedDir);
            if (!normalizedDir.EndsWith(Path.DirectorySeparatorChar.ToString()))
                normalizedDir += Path.DirectorySeparatorChar;
            return normalizedPath.StartsWith(normalizedDir, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>Validates a Windows path format.</summary>
    public static bool ValidatePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (path.Contains("..")) return false;
        if (!Path.IsPathRooted(path)) return false;
        return !OperatingSystem.IsWindows() || SafePathRegex.IsMatch(path);
    }

    /// <summary>Validates an IP address string.</summary>
    public static bool ValidateIpAddress(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        return IPAddress.TryParse(ip, out _);
    }

    /// <summary>Returns true if the IP is private/reserved (RFC1918, loopback, link-local).</summary>
    public static bool IsPrivateIpAddress(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return true;
        if (ip is "localhost" or "::1") return true;
        if (!IPAddress.TryParse(ip, out var addr)) return true;
        var bytes = addr.GetAddressBytes();
        if (bytes.Length == 4)
        {
            if (bytes[0] == 127) return true;
            if (bytes[0] == 10) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
        }
        return false;
    }

    /// <summary>Validates a process ID is within reasonable range.</summary>
    public static bool IsValidProcessId(int pid) => pid >= 1 && pid <= 999999;

    /// <summary>Validates a network port number.</summary>
    public static bool IsValidPort(int port) => port >= 1 && port <= 65535;

    /// <summary>Validates a timestamp is recent (not in far past or future).</summary>
    public static bool IsRecentTimestamp(DateTime timestamp, TimeSpan tolerance)
    {
        var diff = DateTime.UtcNow - timestamp;
        return diff.Duration() < tolerance;
    }

    /// <summary>Constant-time string comparison to prevent timing attacks.</summary>
    public static bool SecureEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
