namespace Behavedr.Core.Monitors;

using System.Text.RegularExpressions;

/// <summary>
/// Command-line normalization and entropy-based detection utilities.
/// Normalizes command lines before pattern matching to defeat evasion via:
/// - Environment variable expansion (%comspec%, %temp%, etc.)
/// - Caret insertion (c^e^r^t^u^t^i^l)
/// - String concatenation indicators
/// - Unicode/null byte stripping
/// - Case normalization
///
/// Also provides Shannon entropy scoring for detecting encoded/obfuscated payloads.
/// </summary>
public static class CommandLineAnalyzer
{
    // Common environment variables to expand for detection
    private static readonly Dictionary<string, string> EnvVarExpansions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["%comspec%"] = "cmd.exe",
        ["%systemroot%"] = @"C:\Windows",
        ["%windir%"] = @"C:\Windows",
        ["%temp%"] = @"C:\Users\user\AppData\Local\Temp",
        ["%tmp%"] = @"C:\Users\user\AppData\Local\Temp",
        ["%appdata%"] = @"C:\Users\user\AppData\Roaming",
        ["%localappdata%"] = @"C:\Users\user\AppData\Local",
        ["%programdata%"] = @"C:\ProgramData",
        ["%programfiles%"] = @"C:\Program Files",
        ["%programfiles(x86)%"] = @"C:\Program Files (x86)",
        ["%userprofile%"] = @"C:\Users\user",
        ["%public%"] = @"C:\Users\Public",
    };

    private static readonly Regex CaretRemoval = new(@"\^(.)", RegexOptions.Compiled);
    private static readonly Regex EnvVarPattern = new(@"%[^%]+%", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex HighEntropySegment = new(@"[A-Za-z0-9+/=]{40,}", RegexOptions.Compiled);
    private static readonly Regex TickObfuscation = new(@"'(\w)'", RegexOptions.Compiled);

    /// <summary>
    /// Normalize a command line for detection purposes.
    /// Strips evasion techniques to reveal the underlying intent.
    /// </summary>
    public static string Normalize(string cmdLine)
    {
        if (string.IsNullOrWhiteSpace(cmdLine))
            return "";

        var normalized = cmdLine;

        // Remove null bytes and non-printable characters
        normalized = new string(normalized.Where(c => c >= 32 && c != 127).ToArray());

        // Remove caret escape characters (cmd.exe evasion: c^e^r^t^u^t^i^l)
        normalized = CaretRemoval.Replace(normalized, "$1");

        // Expand known environment variables
        normalized = EnvVarPattern.Replace(normalized, match =>
        {
            return EnvVarExpansions.GetValueOrDefault(match.Value.ToLowerInvariant(), match.Value);
        });

        // Remove PowerShell tick obfuscation (e.g., I`nv`oke becomes Invoke)
        normalized = normalized.Replace("`", "");

        // Remove PowerShell single-char string concatenation ('I'+'n'+'v' -> Inv)
        // Simplified: just remove single quotes around single chars
        normalized = TickObfuscation.Replace(normalized, "$1");

        // Collapse multiple spaces
        normalized = Regex.Replace(normalized, @"\s+", " ");

        return normalized.Trim();
    }

    /// <summary>
    /// Calculate Shannon entropy of a string segment.
    /// High entropy (> 4.0) suggests encoded/encrypted content.
    /// Normal English text: ~3.5-4.0. Base64 encoded data: ~5.5-6.0.
    /// Random bytes as hex: ~3.7-4.0. Random base64: ~5.9-6.0.
    /// </summary>
    public static double CalculateEntropy(string input)
    {
        if (string.IsNullOrEmpty(input) || input.Length < 2)
            return 0;

        var freq = new Dictionary<char, int>();
        foreach (var c in input)
        {
            freq[c] = freq.GetValueOrDefault(c) + 1;
        }

        double entropy = 0;
        double len = input.Length;
        foreach (var count in freq.Values)
        {
            var p = count / len;
            if (p > 0) entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    /// <summary>
    /// Detect high-entropy segments in a command line that indicate
    /// encoded/obfuscated payloads (base64, XOR-encoded shellcode, etc.)
    /// </summary>
    public static List<EntropyFinding> DetectHighEntropySegments(string cmdLine, double threshold = 4.5)
    {
        var findings = new List<EntropyFinding>();

        var matches = HighEntropySegment.Matches(cmdLine);
        foreach (Match match in matches)
        {
            var segment = match.Value;
            var entropy = CalculateEntropy(segment);

            if (entropy >= threshold)
            {
                findings.Add(new EntropyFinding(segment.Length, entropy, match.Index));
            }
        }

        return findings;
    }

    /// <summary>
    /// Check if a command line contains PowerShell-specific obfuscation patterns.
    /// </summary>
    public static bool HasPowerShellObfuscation(string cmdLine)
    {
        var lower = cmdLine.ToLowerInvariant();

        // String format operator abuse: "{0}{1}" -f 'Inv','oke'
        if (lower.Contains("-f ") && lower.Contains("'{") && lower.Contains("}'"))
            return true;

        // Character array: [char[]]@(73,110,118) -join ''
        if (lower.Contains("[char") && lower.Contains("-join"))
            return true;

        // Replace obfuscation: 'xnvxke'.Replace('x','I')
        if (Regex.IsMatch(lower, @"'[^']+'\s*\.\s*replace\s*\("))
            return true;

        // Reverse: 'ekovnI'[-1..-6] -join ''
        if (lower.Contains("[-1..") && lower.Contains("-join"))
            return true;

        // Variable-based concatenation: $a='Inv';$b='oke';iex "$a$b-Expression"
        if (Regex.IsMatch(lower, @"\$\w+='.{1,10}';\$\w+='.{1,10}'"))
            return true;

        return false;
    }

    /// <summary>
    /// Comprehensive command-line threat scoring.
    /// Returns a score (0-100) and confidence based on normalized analysis.
    /// </summary>
    public static (double Score, double Confidence, string Reason) AnalyzeCommandLine(string rawCmdLine)
    {
        if (string.IsNullOrWhiteSpace(rawCmdLine))
            return (0, 0, "empty");

        var normalized = Normalize(rawCmdLine);
        double maxScore = 0;
        double maxConfidence = 0;
        string reason = "clean";

        // High-entropy segments (likely encoded payload)
        var entropyFindings = DetectHighEntropySegments(normalized);
        if (entropyFindings.Count > 0)
        {
            var maxEntropy = entropyFindings.Max(f => f.Entropy);
            var maxLength = entropyFindings.Max(f => f.Length);

            if (maxEntropy > 5.5 && maxLength > 100)
            {
                maxScore = 75;
                maxConfidence = 0.85;
                reason = $"high_entropy_payload(entropy:{maxEntropy:F2},len:{maxLength})";
            }
            else if (maxEntropy > 4.5 && maxLength > 40)
            {
                maxScore = 50;
                maxConfidence = 0.65;
                reason = $"encoded_segment(entropy:{maxEntropy:F2},len:{maxLength})";
            }
        }

        // PowerShell obfuscation
        if (HasPowerShellObfuscation(normalized))
        {
            if (70 > maxScore)
            {
                maxScore = 70;
                maxConfidence = 0.8;
                reason = "powershell_obfuscation";
            }
        }

        // Normalization revealed hidden content (caret/tick removal changed the string significantly)
        var originalLen = rawCmdLine.Length;
        var normalizedLen = normalized.Length;
        if (originalLen > 20 && (originalLen - normalizedLen) > originalLen * 0.2)
        {
            if (60 > maxScore)
            {
                maxScore = 60;
                maxConfidence = 0.7;
                reason = "heavy_obfuscation_detected";
            }
        }

        return (maxScore, maxConfidence, reason);
    }
}

public record EntropyFinding(int Length, double Entropy, int Position);
