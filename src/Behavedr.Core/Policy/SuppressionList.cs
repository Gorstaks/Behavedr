namespace Behavedr.Core.Policy;

using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Behavedr.Core.Models;

/// <summary>
/// One operator-approved suppression. A signal is dropped only when all of these match:
/// the signal type starts with <see cref="SignalPrefix"/>, the attributed process image equals
/// <see cref="ImagePath"/> (case-insensitive), and that image has a valid publisher signature.
/// Name-only or unsigned matches never suppress anything.
/// </summary>
public sealed class SuppressionRule
{
    /// <summary>Optional process base name. Empty means any process at the image path.</summary>
    public string ProcessName { get; init; } = "";

    /// <summary>Full image path of the approved binary. Required.</summary>
    public string ImagePath { get; init; } = "";

    /// <summary>Start of the signal type to suppress, for example <c>short_lived_powershell</c>.</summary>
    public string SignalPrefix { get; init; } = "";

    /// <summary>Why the operator approved the suppression. Required for the audit trail.</summary>
    public string Reason { get; init; } = "";
}

/// <summary>
/// Operator-managed suppressions, loaded from <c>suppressions.json</c> next to the agent.
/// Modeled on Sentinel's AllowlistService: only an explicit entry suppresses, the binary must
/// be signed, temp and download locations are never trusted, and President's Law categories
/// (credential theft, injection, ransomware, evasion, and similar) can never be suppressed.
/// </summary>
public sealed class SuppressionList
{
    public static readonly SuppressionList Empty = new(Array.Empty<SuppressionRule>(), null);

    private readonly IReadOnlyList<SuppressionRule> _rules;
    private readonly Func<string, bool>? _isSigned;

    public SuppressionList(IEnumerable<SuppressionRule> rules, Func<string, bool>? isSigned)
    {
        _rules = rules.ToList();
        _isSigned = isSigned;
    }

    public int Count => _rules.Count;

    /// <summary>
    /// Load rules from a JSON file of the form <c>{ "rules": [ ... ] }</c>. A missing or malformed
    /// file yields no rules. Entries that lack an absolute image path, a signal prefix, or a
    /// reason are skipped. Without <paramref name="isSigned"/>, no rule can match.
    /// </summary>
    public static SuppressionList Load(string path, Func<string, bool>? isSigned)
    {
        if (!File.Exists(path))
            return Empty;

        try
        {
            var json = File.ReadAllText(path);
            var file = JsonSerializer.Deserialize<SuppressionFile>(json, JsonOptions);
            var valid = (file?.Rules ?? new List<SuppressionRule>())
                .Where(r => Path.IsPathRooted(r.ImagePath)
                            && !string.IsNullOrWhiteSpace(r.SignalPrefix)
                            && !string.IsNullOrWhiteSpace(r.Reason))
                .ToList();
            return new SuppressionList(valid, isSigned);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return Empty;
        }
    }

    /// <summary>
    /// Remove suppressed signals. <paramref name="suppressed"/> returns how many were dropped,
    /// for metrics.
    /// </summary>
    public List<Signal> Apply(List<Signal> signals, out int suppressed)
    {
        suppressed = 0;
        if (_rules.Count == 0 || _isSigned is null)
            return signals;

        var kept = new List<Signal>(signals.Count);
        foreach (var signal in signals)
        {
            if (IsSuppressed(signal))
                suppressed++;
            else
                kept.Add(signal);
        }
        return kept;
    }

    private bool IsSuppressed(Signal signal)
    {
        if (ScoringEngine.IsPresidentsLawSignal(signal)) return false;

        var candidates = _rules.Where(r => signal.Type.StartsWith(r.SignalPrefix, StringComparison.Ordinal)).ToList();
        if (candidates.Count == 0) return false;
        if (!SignalAttribution.TryGetPid(signal.Type, out var pid)) return false;

        var image = TryGetImagePath(pid);
        if (string.IsNullOrEmpty(image)) return false;

        foreach (var rule in candidates)
        {
            if (!string.Equals(image, rule.ImagePath, StringComparison.OrdinalIgnoreCase)) continue;

            var processName = Path.GetFileNameWithoutExtension(image);
            if (rule.ProcessName.Length > 0 &&
                !string.Equals(processName, rule.ProcessName, StringComparison.OrdinalIgnoreCase))
                continue;

            if (_isSigned!(image)) return true;
        }
        return false;
    }

    private static string? TryGetImagePath(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private sealed class SuppressionFile
    {
        [JsonPropertyName("rules")]
        public List<SuppressionRule>? Rules { get; set; }
    }
}
