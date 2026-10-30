namespace Behavedr.Core;

using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Time-windowed behavioral correlation engine.
/// Correlates signals across multiple detection cycles within a 120-second sliding window.
/// Produces composite high-confidence detections when signals from different sources
/// appear on the SAME PID (or process tree) within the correlation window.
///
/// Composite rules (require 2+ distinct signal types on same PID):
/// - Injection + Network -> "In-Memory Implant Active" (0.96)
/// - Credential Access + Network -> "Credential Theft + Exfil" (0.95)
/// - Download Cradle + Execution -> "Staged Payload Active" (0.92)
/// - Parent-Child Anomaly + Encoded PS -> "Fileless Attack Chain" (0.94)
/// - Anti-Tamper + Suspension -> "Active EDR Evasion" (0.97)
/// - Multiple LOLBins on same PID -> "LOLBin Chain" (0.88)
///
/// Global (non-PID-scoped) composites:
/// - Anti-Tamper signals are system-wide (not PID-specific) and correlate with any other category.
/// </summary>
public class BehavioralCorrelationEngine
{
    private readonly ILogger<BehavioralCorrelationEngine> _logger;
    // Key: "pid:category" (e.g., "1234:Injection") for per-PID scoping
    // Special key: "global:AntiTamper" for system-wide signals
    private readonly Dictionary<string, List<TimestampedSignal>> _signalHistory = new();
    private readonly TimeSpan _correlationWindow = TimeSpan.FromSeconds(120);
    private readonly object _lock = new();

    private static readonly Regex PidExtractRegex = new(
        @"pid:(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public BehavioralCorrelationEngine(ILogger<BehavioralCorrelationEngine>? logger = null)
    {
        _logger = logger ?? NullLogger<BehavioralCorrelationEngine>.Instance;
    }

    /// <summary>
    /// Ingest signals from a detection cycle and check for composite matches.
    /// Returns any composite signals that should be added to the result.
    /// </summary>
    public List<Signal> Correlate(List<Signal> currentSignals)
    {
        var composites = new List<Signal>();
        var now = DateTime.UtcNow;

        lock (_lock)
        {
            // Add current signals to history (keyed by PID + category)
            foreach (var signal in currentSignals)
            {
                var category = CategorizeSignal(signal.Type);
                if (category == SignalCategory.Unknown) continue;

                var pid = ExtractPid(signal.Type);

                // Anti-tamper signals are system-wide (not tied to a specific PID)
                var key = category == SignalCategory.AntiTamper
                    ? $"global:{category}"
                    : $"{pid}:{category}";

                if (!_signalHistory.TryGetValue(key, out var list))
                {
                    list = new List<TimestampedSignal>();
                    _signalHistory[key] = list;
                }
                list.Add(new TimestampedSignal(signal, now, pid));
            }

            // Prune expired entries
            PruneExpired(now);

            // Evaluate composite rules (per-PID)
            EvaluateComposites(composites, now);
        }

        return composites;
    }

    private void EvaluateComposites(List<Signal> composites, DateTime now)
    {
        // Group active categories by PID
        var pidCategories = new Dictionary<string, HashSet<SignalCategory>>();
        var globalCategories = new HashSet<SignalCategory>();

        foreach (var (key, signals) in _signalHistory)
        {
            if (signals.Count == 0) continue;

            var parts = key.Split(':', 2);
            if (parts.Length != 2) continue;

            var pidStr = parts[0];
            if (!Enum.TryParse<SignalCategory>(parts[1], out var category)) continue;

            if (pidStr == "global")
            {
                globalCategories.Add(category);
            }
            else
            {
                if (!pidCategories.TryGetValue(pidStr, out var cats))
                {
                    cats = new HashSet<SignalCategory>();
                    pidCategories[pidStr] = cats;
                }
                cats.Add(category);
            }
        }

        // Evaluate per-PID composite rules
        foreach (var (pid, categories) in pidCategories)
        {
            // Injection + Network -> In-Memory Implant (same PID)
            if (categories.Contains(SignalCategory.Injection) &&
                categories.Contains(SignalCategory.Network))
            {
                composites.Add(new Signal($"composite:in_memory_implant_active:pid:{pid}", 96, 0.96));
            }

            // CredentialAccess + Network -> Credential Theft + Exfil (same PID)
            if (categories.Contains(SignalCategory.CredentialAccess) &&
                categories.Contains(SignalCategory.Network))
            {
                composites.Add(new Signal($"composite:credential_theft_exfiltration:pid:{pid}", 95, 0.95));
            }

            // ParentChild + EncodedExecution -> Fileless Attack Chain (same PID)
            if (categories.Contains(SignalCategory.ParentChild) &&
                categories.Contains(SignalCategory.EncodedExecution))
            {
                composites.Add(new Signal($"composite:fileless_attack_chain:pid:{pid}", 94, 0.94));
            }

            // Download + Execution -> Staged Payload (same PID)
            if (categories.Contains(SignalCategory.DownloadCradle) &&
                categories.Contains(SignalCategory.Execution))
            {
                composites.Add(new Signal($"composite:staged_payload_active:pid:{pid}", 92, 0.92));
            }

            // Multiple LOLBins on same PID -> LOLBin Chain
            var lolbinKey = $"{pid}:{nameof(SignalCategory.LolBin)}";
            var lolbinCount = _signalHistory.GetValueOrDefault(lolbinKey)?.Count ?? 0;
            if (lolbinCount >= 2)
            {
                composites.Add(new Signal($"composite:lolbin_chain({lolbinCount}):pid:{pid}", 88, 0.88));
            }
        }

        // Global composite: AntiTamper + any PID having signals -> Active EDR Evasion
        if (globalCategories.Contains(SignalCategory.AntiTamper) && pidCategories.Count > 0)
        {
            composites.Add(new Signal("composite:active_edr_evasion", 97, 0.97));
        }
    }

    private void PruneExpired(DateTime now)
    {
        foreach (var kvp in _signalHistory)
        {
            kvp.Value.RemoveAll(ts => now - ts.Timestamp > _correlationWindow);
        }

        // Remove empty keys
        var empty = _signalHistory.Where(kv => kv.Value.Count == 0).Select(kv => kv.Key).ToList();
        foreach (var key in empty) _signalHistory.Remove(key);
    }

    /// <summary>
    /// Extract PID from a signal type string.
    /// Patterns: "rwx_memory:notepad(pid:1234,regions:3)", "encoded_powershell:pid:5678"
    /// Returns "unknown" if no PID found.
    /// </summary>
    private static string ExtractPid(string signalType)
    {
        var match = PidExtractRegex.Match(signalType);
        return match.Success ? match.Groups[1].Value : "unknown";
    }

    private static SignalCategory CategorizeSignal(string signalType)
    {
        var lower = signalType.ToLowerInvariant();

        if (lower.Contains("rwx_memory") || lower.Contains("injection") || lower.Contains("hollowing"))
            return SignalCategory.Injection;
        if (lower.Contains("suspicious_port") || lower.Contains("connection_burst") || lower.Contains("beaconing") || lower.Contains("high_connection"))
            return SignalCategory.Network;
        if (lower.Contains("credential") || lower.Contains("lsass") || lower.Contains("browser_cred"))
            return SignalCategory.CredentialAccess;
        if (lower.Contains("parent_child"))
            return SignalCategory.ParentChild;
        if (lower.Contains("encoded_powershell") || lower.Contains("amsi_bypass"))
            return SignalCategory.EncodedExecution;
        if (lower.Contains("download_cradle"))
            return SignalCategory.DownloadCradle;
        if (lower.Contains("lolbin"))
            return SignalCategory.LolBin;
        if (lower.Contains("suspension") || lower.Contains("binary_integrity") || lower.Contains("anti_tamper") || lower.Contains("service_registration"))
            return SignalCategory.AntiTamper;
        if (lower.Contains("suspicious_process") || lower.Contains("process_burst"))
            return SignalCategory.Execution;

        return SignalCategory.Unknown;
    }

    private record TimestampedSignal(Signal Signal, DateTime Timestamp, string Pid);

    private enum SignalCategory
    {
        Unknown,
        Injection,
        Network,
        CredentialAccess,
        ParentChild,
        EncodedExecution,
        DownloadCradle,
        LolBin,
        AntiTamper,
        Execution,
    }
}
