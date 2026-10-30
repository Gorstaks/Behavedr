namespace Behavedr.Agent;

using Behavedr.Core.Communication;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Background service managing the agent-to-server communication lifecycle.
/// Handles connection, heartbeats, offline buffer replay, and policy fetching.
/// v0.1.3: Wires communication layer that was previously dead code (C-3 fix).
/// v0.3.1: Applies signed policy updates via <see cref="PolicyApplicator"/>.
/// </summary>
public sealed class CommunicationService : BackgroundService
{
    private readonly IBehavedrClient _client;
    private readonly OfflineBuffer _offlineBuffer;
    private readonly CommunicationConfig _config;
    private readonly PolicyApplicator _policyApplicator;
    private readonly ILogger<CommunicationService> _logger;

    public CommunicationService(
        IBehavedrClient client,
        OfflineBuffer offlineBuffer,
        CommunicationConfig config,
        PolicyApplicator policyApplicator,
        ILogger<CommunicationService> logger)
    {
        _client = client;
        _offlineBuffer = offlineBuffer;
        _config = config;
        _policyApplicator = policyApplicator;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_config.Enabled)
        {
            _logger.LogInformation("Communication service disabled via configuration");
            return;
        }

        _logger.LogInformation("Communication service starting - server: {Url}", _config.ServerUrl);

        // Initial connection attempt
        await _client.ConnectAsync(stoppingToken);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_config.HeartbeatIntervalSeconds));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);

                // Send heartbeat
                var heartbeat = new AgentHeartbeat(
                    _config.AgentId,
                    Behavedr.Core.Platform.PlatformMonitors.CurrentPlatformSummary(),
                    typeof(Behavedr.Core.DetectionEngine).Assembly.GetName().Version?.ToString(3) ?? "0.1.4",
                    Behavedr.Core.Platform.PlatformMonitors.All.Count(m => m.IsSupported),
                    (long)(DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime()).TotalSeconds,
                    DateTime.UtcNow);

                await _client.SendHeartbeatAsync(heartbeat, stoppingToken);

                // If connected and have buffered reports, replay them
                if (_client.IsConnected && _offlineBuffer.PendingCount > 0)
                {
                    var replayed = await _offlineBuffer.ReplayAsync(_client, stoppingToken);
                    if (replayed > 0)
                        _logger.LogInformation("Replayed {Count} buffered reports", replayed);
                }

                // Fetch and apply signed policy updates
                if (_client.IsConnected)
                {
                    var policy = await _client.FetchPolicyAsync(stoppingToken);
                    if (policy is not null)
                    {
                        if (_policyApplicator.TryApply(policy, out var err))
                        {
                            _logger.LogInformation(
                                "Policy update applied (issued: {IssuedAt})", policy.IssuedAt);
                        }
                        else
                        {
                            _logger.LogWarning(
                                "Policy update rejected: {Error} (issued: {IssuedAt})",
                                err, policy.IssuedAt);
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Communication cycle error - will retry next interval");
            }
        }

        _logger.LogInformation("Communication service stopping");
        await _client.DisposeAsync();
    }
}
