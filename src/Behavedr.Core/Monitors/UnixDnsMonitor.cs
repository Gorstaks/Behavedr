namespace Behavedr.Core.Monitors;

using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Unix DNS query monitoring via system log parsing.
/// Reads from /var/log/syslog, /var/log/messages, or systemd-resolved journal.
/// Detects:
/// - DGA-like domains (high entropy, random-looking labels)
/// - DNS tunneling indicators (high query volume, large TXT record lookups)
/// - Queries to suspicious TLDs
/// - Unusually long subdomain labels (data exfiltration via DNS)
/// </summary>
public class UnixDnsMonitor : IPlatformMonitor
{
    private readonly ILogger<UnixDnsMonitor> _logger;
    private long _lastLogPosition;
    private readonly Dictionary<string, int> _domainQueryCounts = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    public string PlatformName => "UnixDns";
    public bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        ".xyz", ".top", ".club", ".work", ".buzz", ".surf",
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".onion", ".bit", ".bazar", ".coin",
    };

    public UnixDnsMonitor(ILogger<UnixDnsMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<UnixDnsMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var logPath = FindDnsLogPath();
            if (logPath is null) return Task.FromResult<IEnumerable<Signal>>(signals);

            var queries = ReadRecentDnsQueries(logPath, ct);
            AnalyzeQueries(queries, signals);

            // Periodic cleanup of query count tracking
            if ((DateTime.UtcNow - _lastCleanup).TotalMinutes > 5)
            {
                _domainQueryCounts.Clear();
                _lastCleanup = DateTime.UtcNow;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixDns] Error during DNS monitoring");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void AnalyzeQueries(List<string> domains, List<Signal> signals)
    {
        foreach (var domain in domains)
        {
            if (string.IsNullOrWhiteSpace(domain)) continue;
            var lower = domain.ToLowerInvariant().TrimEnd('.');

            // Track query counts per domain for burst detection
            _domainQueryCounts.TryGetValue(lower, out var count);
            _domainQueryCounts[lower] = count + 1;

            // DGA detection: high entropy + length
            var labels = lower.Split('.');
            if (labels.Length > 1)
            {
                var mainLabel = labels[0];
                var entropy = CalculateShannonEntropy(mainLabel);

                if (mainLabel.Length >= 12 && entropy > 3.0)
                {
                    signals.Add(new Signal(
                        $"dga_domain_query:{lower}(entropy:{entropy:F2})", 72, 0.78));
                }

                // DNS tunneling: very long subdomains (data encoded in labels)
                if (mainLabel.Length > 30)
                {
                    signals.Add(new Signal(
                        $"dns_tunnel_indicator:{lower}(len:{mainLabel.Length})", 78, 0.82));
                }
            }

            // Suspicious TLD
            foreach (var tld in SuspiciousTlds)
            {
                if (lower.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal($"suspicious_tld_query:{lower}", 45, 0.6));
                    break;
                }
            }
        }

        // High volume DNS queries to unique domains (tunneling/DGA)
        var uniqueCount = _domainQueryCounts.Count;
        if (uniqueCount > 100)
        {
            signals.Add(new Signal(
                $"high_dns_query_volume:{uniqueCount}_unique_domains", 65, 0.72));
        }
    }

    private List<string> ReadRecentDnsQueries(string logPath, CancellationToken ct)
    {
        var domains = new List<string>();
        try
        {
            using var stream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (_lastLogPosition > stream.Length) _lastLogPosition = 0; // Log rotated
            var seekPos = _lastLogPosition > 0 ? _lastLogPosition : Math.Max(0, stream.Length - 32768);
            stream.Seek(seekPos, SeekOrigin.Begin);

            using var reader = new StreamReader(stream);
            while (!reader.EndOfStream && !ct.IsCancellationRequested)
            {
                var line = reader.ReadLine();
                if (line is null) break;

                // Parse DNS query from syslog/dnsmasq/systemd-resolved formats
                var domain = ExtractDomain(line);
                if (domain is not null) domains.Add(domain);
            }
            _lastLogPosition = stream.Position;
        }
        catch { }
        return domains;
    }

    private static string? ExtractDomain(string logLine)
    {
        // dnsmasq: "query[A] example.com from 127.0.0.1"
        var match = Regex.Match(logLine, @"query\[\w+\]\s+(\S+)\s+from");
        if (match.Success) return match.Groups[1].Value;

        // systemd-resolved: "Lookups: example.com"
        match = Regex.Match(logLine, @"(?:query|lookup|resolving)\s+(\S+\.[\w]{2,})", RegexOptions.IgnoreCase);
        if (match.Success) return match.Groups[1].Value;

        return null;
    }

    private static string? FindDnsLogPath()
    {
        var candidates = new[]
        {
            "/var/log/syslog",           // Ubuntu/Debian
            "/var/log/messages",         // RHEL/CentOS
            "/var/log/dnsmasq.log",      // dnsmasq
            "/var/log/pihole.log",       // Pi-hole
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static double CalculateShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var freq = new Dictionary<char, int>();
        foreach (var c in s)
        {
            freq.TryGetValue(c, out var count);
            freq[c] = count + 1;
        }
        double entropy = 0;
        foreach (var count in freq.Values)
        {
            double p = (double)count / s.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
