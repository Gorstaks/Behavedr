namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// DNS query monitoring via NativeEtwSession (ETW DNS-Client provider).
/// Detects:
/// - DGA-like domain queries (high entropy, long labels, suspicious TLDs)
/// - High-frequency DNS queries from single process (DNS tunneling indicator)
/// - Queries to known-suspicious TLDs
/// - DNS queries from processes that shouldn't make them (LOLBins, shells)
///
/// Requires NativeEtwSession to be active in native mode for DNS events.
/// Falls back to no-op if DNS events are unavailable.
/// </summary>
[SupportedOSPlatform("windows")]
public class DnsQueryMonitor : IPlatformMonitor
{
    private readonly ILogger<DnsQueryMonitor> _logger;
    private readonly NativeEtwSession? _etwSession;
    private readonly Dictionary<int, List<DnsQueryRecord>> _queryHistory = new();
    private readonly object _lock = new();
    private const int MaxTrackedProcesses = 500;
    private const int DgaEntropyThreshold = 30; // Shannon entropy * 10 - lowered from 35 to catch shorter DGA
    private const int DgaMinDomainLength = 12;  // Lowered from 20 to catch short DGA domains

    // Suspicious TLDs commonly used in malware/C2
    private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        ".xyz", ".top", ".club", ".work", ".buzz", ".surf",
        ".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs popular with malware
        ".onion", ".bit", ".bazar", ".coin",
    };

    // Processes that normally don't make DNS queries
    private static readonly HashSet<string> UnexpectedDnsProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "wscript", "cscript",
        "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin",
    };

    public string PlatformName => "DnsMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    public DnsQueryMonitor(NativeEtwSession? etwSession = null, ILogger<DnsQueryMonitor>? logger = null)
    {
        _etwSession = etwSession;
        _logger = logger ?? NullLogger<DnsQueryMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (_etwSession is null || !_etwSession.IsNativeMode)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        var dnsEvents = _etwSession.DrainDnsEvents();
        if (dnsEvents.Count == 0)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        lock (_lock)
        {
            foreach (var evt in dnsEvents)
            {
                if (ct.IsCancellationRequested) break;
                if (string.IsNullOrEmpty(evt.QueryName)) continue;

                // Track query history per process
                if (!_queryHistory.TryGetValue(evt.ProcessId, out var history))
                {
                    if (_queryHistory.Count >= MaxTrackedProcesses)
                        EvictOldest();
                    history = new List<DnsQueryRecord>();
                    _queryHistory[evt.ProcessId] = history;
                }
                history.Add(new DnsQueryRecord(evt.QueryName, evt.Timestamp));

                // DGA detection: high entropy domain names
                var entropy = CalculateShannonEntropy(ExtractSecondLevelDomain(evt.QueryName));
                if (entropy > DgaEntropyThreshold && evt.QueryName.Length > DgaMinDomainLength)
                {
                    signals.Add(new Signal(
                        $"dga_domain_query:{evt.QueryName}",
                        65, 0.75));
                }

                // DGA detection: unique domain rate per process
                // DGA malware generates many unique domain queries in short bursts
                DetectUniqueDomainBurst(evt.ProcessId, evt.QueryName, signals);

                // Suspicious TLD detection
                foreach (var tld in SuspiciousTlds)
                {
                    if (evt.QueryName.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                    {
                        signals.Add(new Signal(
                            $"suspicious_tld_query:{evt.QueryName}",
                            45, 0.6));
                        break;
                    }
                }

                // Unexpected process making DNS queries
                var procName = GetProcessName(evt.ProcessId);
                if (procName is not null && UnexpectedDnsProcesses.Contains(procName))
                {
                    signals.Add(new Signal(
                        $"unexpected_dns_process:{procName}->{evt.QueryName}",
                        55, 0.7));
                }
            }

            // DNS tunneling detection: high query rate from single process
            DetectDnsTunneling(signals);

            // Prune old entries
            PruneHistory();
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void DetectDnsTunneling(List<Signal> signals)
    {
        var now = DateTime.UtcNow;
        var windowStart = now.AddSeconds(-30);

        foreach (var (pid, records) in _queryHistory)
        {
            var recentQueries = records.Count(r => r.Timestamp > windowStart);
            if (recentQueries > 50)
            {
                // 50+ DNS queries in 30 seconds from one process is suspicious
                var confidence = recentQueries switch
                {
                    > 200 => 0.92,
                    > 100 => 0.85,
                    > 50 => 0.7,
                    _ => 0.5
                };

                signals.Add(new Signal(
                    $"dns_tunneling_indicator:pid:{pid}({recentQueries}_queries_in_30s)",
                    75, confidence));
            }
        }
    }

    /// <summary>
    /// Detect DGA-style unique domain bursts: many unique second-level domains
    /// from a single process in a short window indicates algorithmic generation.
    /// Normal processes query the same domains repeatedly; DGA queries are unique.
    /// </summary>
    private void DetectUniqueDomainBurst(int pid, string queryName, List<Signal> signals)
    {
        if (!_queryHistory.TryGetValue(pid, out var history)) return;

        var windowStart = DateTime.UtcNow.AddSeconds(-60);
        var recentDomains = history
            .Where(r => r.Timestamp > windowStart)
            .Select(r => ExtractSecondLevelDomain(r.Domain))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        // 20+ unique second-level domains in 60 seconds from one process = DGA indicator
        if (recentDomains >= 20)
        {
            var confidence = recentDomains switch
            {
                > 100 => 0.93,
                > 50 => 0.85,
                > 20 => 0.75,
                _ => 0.6
            };

            signals.Add(new Signal(
                $"dga_unique_domain_burst:pid:{pid}({recentDomains}_unique_in_60s)",
                70, confidence));
        }
    }

    private void PruneHistory()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-2);
        foreach (var (pid, records) in _queryHistory)
        {
            records.RemoveAll(r => r.Timestamp < cutoff);
        }
        var empty = _queryHistory.Where(kv => kv.Value.Count == 0).Select(kv => kv.Key).ToList();
        foreach (var key in empty) _queryHistory.Remove(key);
    }

    private void EvictOldest()
    {
        var oldest = _queryHistory
            .OrderBy(kv => kv.Value.LastOrDefault()?.Timestamp ?? DateTime.MinValue)
            .Take(100).Select(kv => kv.Key).ToList();
        foreach (var key in oldest) _queryHistory.Remove(key);
    }

    /// <summary>
    /// Calculate Shannon entropy of a string (x10 for integer comparison).
    /// High entropy indicates randomized/algorithmically generated names.
    /// </summary>
    private static int CalculateShannonEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;

        var freq = new Dictionary<char, int>();
        foreach (var c in input.ToLowerInvariant())
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

        return (int)(entropy * 10);
    }

    private static string ExtractSecondLevelDomain(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        if (parts.Length >= 2)
            return parts[^2]; // Second-level domain label
        return domain;
    }

    private static string? GetProcessName(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return null; }
    }

    private record DnsQueryRecord(string Domain, DateTime Timestamp);
}
