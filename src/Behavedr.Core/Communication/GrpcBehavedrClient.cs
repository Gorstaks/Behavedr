namespace Behavedr.Core.Communication;

using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Behavedr.Core.Models;
using Behavedr.Core.Response;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// HTTPS/JSON client for agent-to-server communication.
/// Uses mTLS (mutual TLS) with client certificates for authentication.
/// Protocol: simple REST-like HTTPS endpoints (gRPC-compatible upgrade path).
/// 
/// Endpoints:
///   POST /api/v1/detections  - report a detection
///   POST /api/v1/heartbeat   - agent heartbeat
///   GET  /api/v1/policy      - fetch policy updates
/// </summary>
public class GrpcBehavedrClient : IBehavedrClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<GrpcBehavedrClient> _logger;
    private readonly string _serverUrl;
    private readonly string _agentId;
    private bool _connected;

    public GrpcBehavedrClient(
        CommunicationConfig config,
        ILogger<GrpcBehavedrClient>? logger = null)
    {
        _logger = logger ?? NullLogger<GrpcBehavedrClient>.Instance;
        _serverUrl = config.ServerUrl.TrimEnd('/');
        _agentId = config.AgentId;

        var handler = CreateHttpHandler(config);
        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds),
        };
    }

    public bool IsConnected => _connected;

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        try
        {
            _logger.LogInformation("Connecting to server at {Url}", _serverUrl);

            // Test connectivity with a simple health check
            var response = await _httpClient.GetAsync($"{_serverUrl}/api/v1/health", ct);
            _connected = response.IsSuccessStatusCode;

            if (_connected)
                _logger.LogInformation("Connected to server successfully");
            else
                _logger.LogWarning("Server returned {StatusCode}", response.StatusCode);
        }
        catch (Exception ex)
        {
            _connected = false;
            _logger.LogWarning(ex, "Failed to connect to server at {Url}", _serverUrl);
        }
    }

    public async Task ReportDetectionAsync(DetectionReport report, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(report, JsonOptions);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var response = await _httpClient.PostAsync($"{_serverUrl}/api/v1/detections", content, ct);
            response.EnsureSuccessStatusCode();

            _logger.LogDebug("Detection reported: {Process} score={Score:F1}",
                report.Event.ProcessName, report.Score);
        }
        catch (Exception ex)
        {
            _connected = false;
            _logger.LogWarning(ex, "Failed to report detection to server");
            throw; // Let caller handle (offline buffering)
        }
    }

    public async Task SendHeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(heartbeat, JsonOptions);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var response = await _httpClient.PostAsync($"{_serverUrl}/api/v1/heartbeat", content, ct);
            _connected = response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _connected = false;
            _logger.LogDebug(ex, "Heartbeat failed");
        }
    }

    public async Task<PolicyUpdate?> FetchPolicyAsync(CancellationToken ct = default)
    {
        try
        {
            var response = await _httpClient.GetAsync($"{_serverUrl}/api/v1/policy?agentId={Uri.EscapeDataString(_agentId)}", ct);
            if (!response.IsSuccessStatusCode)
                return null;

            var json = await response.Content.ReadAsStringAsync(ct);
            var policy = JsonSerializer.Deserialize<PolicyUpdate>(json, JsonOptions);

            // SECURITY: Verify policy update signature before accepting
            if (policy is not null && !policy.VerifySignature())
            {
                _logger.LogCritical("SECURITY: Policy update signature verification FAILED - rejecting policy");
                return null;
            }

            return policy;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to fetch policy update");
            return null;
        }
    }

    public ValueTask DisposeAsync()
    {
        _httpClient.Dispose();
        return ValueTask.CompletedTask;
    }

    private static HttpClientHandler CreateHttpHandler(CommunicationConfig config)
    {
        var handler = new HttpClientHandler();

        // Load client certificate for mTLS
        if (!string.IsNullOrEmpty(config.ClientCertPath) && File.Exists(config.ClientCertPath))
        {
            var cert = string.IsNullOrEmpty(config.ClientCertPassword)
                ? X509CertificateLoader.LoadPkcs12FromFile(config.ClientCertPath, null)
                : X509CertificateLoader.LoadPkcs12FromFile(config.ClientCertPath, config.ClientCertPassword);

            handler.ClientCertificates.Add(cert);
        }

        // Certificate pinning: validate server cert against known CA.
        // SECURITY: Fail-closed - if no CA cert is configured, reject ALL server certificates.
        // This prevents MITM attacks when the agent is misconfigured.
        if (!string.IsNullOrEmpty(config.CaCertPath) && File.Exists(config.CaCertPath))
        {
            var caCert = X509CertificateLoader.LoadCertificateFromFile(config.CaCertPath);
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
            {
                if (cert is null) return false;

                // Accept only if signed by our pinned CA
                using var chain2 = new X509Chain();
                chain2.ChainPolicy.ExtraStore.Add(caCert);
                chain2.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain2.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain2.ChainPolicy.CustomTrustStore.Add(caCert);
                return chain2.Build(cert);
            };
        }
        else
        {
            // SECURITY: Fail-closed - no CA cert means we cannot verify the server identity.
            // Reject all connections to prevent MITM. Configure CaCertPath to enable comms.
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => false;
        }

        return handler;
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };
}

/// <summary>
/// Configuration for agent-server communication.
/// </summary>
public record CommunicationConfig
{
    public string ServerUrl { get; init; } = "https://localhost:5443";
    public string AgentId { get; init; } = Environment.MachineName;
    public string? ClientCertPath { get; init; }
    public string? ClientCertPassword { get; init; }
    public string? CaCertPath { get; init; }
    public int TimeoutSeconds { get; init; } = 30;
    public int HeartbeatIntervalSeconds { get; init; } = 60;
    public bool Enabled { get; init; } = false;

    public static CommunicationConfig Default => new();
}
