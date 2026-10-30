namespace Behavedr.Agent;

using Behavedr.Core.Update;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Background service that periodically checks for agent updates.
/// v0.1.3: Wires AutoUpdater that was previously dead code (H-6 fix).
/// </summary>
public sealed class UpdateCheckService : BackgroundService
{
    private readonly AutoUpdater _updater;
    private readonly ILogger<UpdateCheckService> _logger;
    private readonly TimeSpan _checkInterval;
    private readonly bool _enabled;

    public UpdateCheckService(
        AutoUpdater updater,
        IConfiguration configuration,
        ILogger<UpdateCheckService> logger)
    {
        _updater = updater;
        _logger = logger;
        _checkInterval = TimeSpan.FromHours(
            configuration.GetValue("Update:CheckIntervalHours", 6));
        _enabled = configuration.GetValue("Update:Enabled", true);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_enabled)
        {
            _logger.LogInformation("Auto-update checks disabled via configuration");
            return;
        }

        _logger.LogInformation("Update check service started (interval: {Hours}h)",
            _checkInterval.TotalHours);

        // Delay initial check by 5 minutes to let the agent fully start
        await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var update = await _updater.CheckForUpdateAsync(stoppingToken);
                if (update is not null)
                {
                    _logger.LogInformation("Update available: v{Version}", update.Version);
                    var applied = await _updater.ApplyUpdateAsync(update, stoppingToken);
                    if (applied)
                    {
                        _logger.LogWarning("Update v{Version} staged - restart required to complete",
                            update.Version);
                    }
                }

                await Task.Delay(_checkInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Update check failed - will retry next interval");
                await Task.Delay(_checkInterval, stoppingToken);
            }
        }
    }
}
