namespace Behavedr.Core.Monitors;

using System.Net.Http;
using System.Security.Cryptography;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Connectivity canary verifying the agent can reach external endpoints.
/// Detects EDRSilencer WFP blocking, DNS poisoning, firewall rules silencing agent traffic.
/// 3 consecutive failures -> high-confidence "Network Silencing Detected" signal.
///
/// Anti-fingerprinting measures:
/// - Randomized User-Agent from a pool of common browser UAs
/// - Jittered check interval (15s around base interval)
/// - URL pool rotation (selects 2 random URLs per check from a larger pool)
/// - No product-identifying headers or patterns
/// </summary>
public class ConnectivityCanaryMonitor : IPlatformMonitor
{
    private readonly ILogger<ConnectivityCanaryMonitor> _logger;
    private readonly HttpClient _http;
    private int _consecutiveFailures;
    private DateTime _lastCheck = DateTime.MinValue;
    private DateTime? _firstFailure;
    private int _currentCheckInterval;
    private const int BaseCheckIntervalSeconds = 45;
    private const int JitterRangeSeconds = 15;

    // Expanded URL pool - select 2 random URLs per check to avoid fingerprinting
    private static readonly string[] CanaryUrlPool =
    [
        "https://cloudflare.com/cdn-cgi/trace",
        "https://www.google.com/generate_204",
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://www.msftconnecttest.com/connecttest.txt",
        "https://detectportal.firefox.com/success.txt",
        "https://captive.apple.com/hotspot-detect.html",
        "https://connectivity-check.ubuntu.com/",
        "https://www.cloudflare.com/favicon.ico",
    ];

    // Common browser User-Agent strings for blending in with normal traffic
    private static readonly string[] UserAgentPool =
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ];

    public string PlatformName => "ConnectivityCanary";
    public bool IsSupported => true;

    public ConnectivityCanaryMonitor(ILogger<ConnectivityCanaryMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<ConnectivityCanaryMonitor>.Instance;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        // Set initial randomized interval
        _currentCheckInterval = GetJitteredInterval();
    }

    public async Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if ((DateTime.UtcNow - _lastCheck).TotalSeconds < _currentCheckInterval)
            return signals;

        _lastCheck = DateTime.UtcNow;
        // Randomize next interval for anti-fingerprinting
        _currentCheckInterval = GetJitteredInterval();

        var reachable = await CheckConnectivityAsync(ct);

        if (!reachable)
        {
            _consecutiveFailures++;
            _firstFailure ??= DateTime.UtcNow;

            if (_consecutiveFailures >= 3)
            {
                var silenceDuration = DateTime.UtcNow - _firstFailure.Value;
                var confidence = silenceDuration.TotalMinutes > 10 ? 0.95 : 0.85;
                signals.Add(new Signal(
                    $"network_silencing_detected:failures:{_consecutiveFailures}",
                    90, confidence));
                _logger.LogCritical(
                    "SECURITY: Network silencing detected - {Failures} consecutive connectivity failures over {Duration:F0}s",
                    _consecutiveFailures, silenceDuration.TotalSeconds);
            }
        }
        else
        {
            if (_consecutiveFailures >= 3)
                _logger.LogInformation("Network connectivity restored after {Failures} failures", _consecutiveFailures);
            _consecutiveFailures = 0;
            _firstFailure = null;
        }

        return signals;
    }

    private async Task<bool> CheckConnectivityAsync(CancellationToken ct)
    {
        // Select 2 random URLs from the pool (avoids always hitting the same endpoints)
        var selectedUrls = SelectRandomUrls(2);
        var userAgent = SelectRandomUserAgent();

        foreach (var url in selectedUrls)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.UserAgent.Clear();
                request.Headers.UserAgent.ParseAdd(userAgent);

                var response = await _http.SendAsync(request, ct);
                if (response.IsSuccessStatusCode || (int)response.StatusCode == 204)
                    return true;
            }
            catch { }
        }
        return false;
    }

    /// <summary>
    /// Select N random URLs from the pool without replacement.
    /// </summary>
    private static string[] SelectRandomUrls(int count)
    {
        var indices = new HashSet<int>();
        while (indices.Count < count && indices.Count < CanaryUrlPool.Length)
        {
            indices.Add(RandomNumberGenerator.GetInt32(CanaryUrlPool.Length));
        }
        return indices.Select(i => CanaryUrlPool[i]).ToArray();
    }

    /// <summary>
    /// Select a random User-Agent string from the pool.
    /// </summary>
    private static string SelectRandomUserAgent()
    {
        return UserAgentPool[RandomNumberGenerator.GetInt32(UserAgentPool.Length)];
    }

    /// <summary>
    /// Get a jittered check interval: base  random jitter.
    /// Uses cryptographic RNG for unpredictability.
    /// </summary>
    private static int GetJitteredInterval()
    {
        var jitter = RandomNumberGenerator.GetInt32(-JitterRangeSeconds, JitterRangeSeconds + 1);
        return Math.Max(20, BaseCheckIntervalSeconds + jitter);
    }
}
