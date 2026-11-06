namespace Behavedr.Core.Monitors;

using System.Text.RegularExpressions;
using Behavedr.Core.Models;

/// <summary>
/// Command-line rules shared by the live process scanner and ETW process-start events.
///
/// Rules are scoped to the process types that legitimately use them:
/// - Download cradles and AMSI tampering apply to script hosts only, and fetch tools
///   (curl, wget) count only when they are given a URL. Bare words such as "curl" in
///   another program's arguments no longer match.
/// - Quoted text is treated as data when a search tool (Select-String, findstr, grep)
///   is in the command line. Searching for a malware string is not running it.
/// - Entropy checks apply to script hosts only, so long hashes and URLs in ordinary
///   command lines are not flagged.
/// Callers filter out the agent's own processes before calling <see cref="Evaluate"/>.
/// </summary>
public static class CommandLineThreatRules
{
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
        "certutil", "bitsadmin", "wmic", "bash", "sh", "zsh", "python", "python3", "node", "perl", "ruby",
    };

    private static readonly HashSet<string> PowerShellHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh",
    };

    private static readonly HashSet<string> FetchTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "curl", "wget",
    };

    private static readonly string[] SearchTools =
    [
        "select-string", "findstr", "grep", " rg ", " sls ",
    ];

    // The optional (\.exe) lets "certutil.exe -urlcache" match as well as "certutil -urlcache".
    private static readonly (string Pattern, string Description, double Weight, double Confidence)[] LolBinPatterns =
    [
        (@"certutil(\.exe)?\s+.*-urlcache", "certutil download", 70, 0.8),
        (@"certutil(\.exe)?\s+.*-decode", "certutil decode", 60, 0.75),
        (@"bitsadmin(\.exe)?\s+/transfer", "bitsadmin download", 65, 0.8),
        (@"mshta(\.exe)?\s+(http|vbscript|javascript)", "mshta script execution", 80, 0.85),
        (@"regsvr32(\.exe)?\s+/s\s+/n\s+/u\s+/i:", "regsvr32 squiblydoo", 85, 0.9),
        (@"rundll32(\.exe)?\s+.*,\s*(DllRegisterServer|Control_RunDLL)", "rundll32 abuse", 55, 0.65),
        (@"wmic(\.exe)?\s+.*process\s+call\s+create", "wmic process create", 70, 0.8),
        (@"forfiles(\.exe)?\s+/p\s+.*\s+/c", "forfiles command execution", 50, 0.6),
    ];

    private static readonly Regex EncodedPsRegex = new(
        @"-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{20,}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex BypassRegex = new(
        @"-(?:ep|executionpolicy)\s+(bypass|unrestricted)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Method names may follow a dot, as in "(New-Object Net.WebClient).DownloadString(...)".
    private static readonly Regex DownloadCradleRegex = new(
        @"(?<![\w-])(Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|DownloadString|DownloadFile|Start-BitsTransfer)(?![\w-])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // A fetch tool counts only when a URL follows its options, before any pipe or statement break.
    private static readonly Regex FetchUrlRegex = new(
        @"(?<![\w.-])(curl|wget)(\.exe)?\s[^|;&\r\n]*?https?://",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AmsiBypassRegex = new(
        @"(?<![\w-])(amsiInitFailed|AmsiScanBuffer|Remove-MpThreat)(?![\w-])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex QuotedTextRegex = new(
        @"""[^""]*""|'[^']*'",
        RegexOptions.Compiled);

    /// <summary>True when the process name is a script host, interpreter, or LOLBin.</summary>
    public static bool IsScriptHost(string processName) => ScriptHosts.Contains(processName);

    /// <summary>
    /// Evaluate one command line. <paramref name="processName"/> is the executable base name
    /// without extension (for example "powershell").
    /// </summary>
    public static List<Signal> Evaluate(string processName, string? cmdLine, int pid)
    {
        var signals = new List<Signal>();
        if (string.IsNullOrWhiteSpace(cmdLine) || string.IsNullOrWhiteSpace(processName))
            return signals;

        var name = processName.Trim();
        bool isScriptHost = ScriptHosts.Contains(name);
        bool isPowerShell = PowerShellHosts.Contains(name);
        bool isFetchTool = FetchTools.Contains(name);

        if (isScriptHost)
        {
            var (score, confidence, reason) = CommandLineAnalyzer.AnalyzeCommandLine(cmdLine);
            if (score >= 50)
                signals.Add(new Signal($"obfuscated_cmdline:{name}:pid:{pid}:{reason}", score, confidence));
        }

        var normalized = CommandLineAnalyzer.Normalize(cmdLine);

        // A search tool's quoted pattern is data, not execution.
        var matchable = HasSearchTool(normalized)
            ? QuotedTextRegex.Replace(normalized, "\"\"")
            : normalized;

        if (isPowerShell && EncodedPsRegex.IsMatch(normalized))
            signals.Add(new Signal($"encoded_powershell:pid:{pid}", 70, 0.8));

        if (isPowerShell && BypassRegex.IsMatch(normalized))
            signals.Add(new Signal($"execution_policy_bypass:pid:{pid}", 40, 0.6));

        bool cradle = (isScriptHost && DownloadCradleRegex.IsMatch(matchable))
                      || ((isScriptHost || isFetchTool) && FetchUrlRegex.IsMatch(matchable));
        if (cradle)
            signals.Add(new Signal($"download_cradle:{name}:pid:{pid}", 65, 0.75));

        if (isScriptHost && AmsiBypassRegex.IsMatch(matchable))
            signals.Add(new Signal($"amsi_bypass_attempt:pid:{pid}", 85, 0.9));

        foreach (var (pattern, description, weight, confidence) in LolBinPatterns)
        {
            if (Regex.IsMatch(matchable, pattern, RegexOptions.IgnoreCase))
            {
                signals.Add(new Signal($"lolbin:{description}:pid:{pid}", weight, confidence));
                break; // One LOLBin signal per process
            }
        }

        if (isPowerShell &&
            normalized.Contains("-w hidden", StringComparison.OrdinalIgnoreCase) &&
            normalized.Contains("-nop", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add(new Signal($"hidden_powershell:pid:{pid}", 60, 0.7));
        }

        return signals;
    }

    private static bool HasSearchTool(string normalized) =>
        SearchTools.Any(tool => normalized.Contains(tool, StringComparison.OrdinalIgnoreCase));
}
