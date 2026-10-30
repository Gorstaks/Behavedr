namespace Behavedr.Core;

using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Shared startup for desktop and mobile agents.
/// </summary>
public static class AgentBootstrap
{
    public static DetectionEngine CreateEngine(ScoringConfig? config = null, ILogger<DetectionEngine>? logger = null)
    {
        var scoring = new ScoringEngine(config);
        var correlation = new BehavioralCorrelationEngine();
        var engine = new DetectionEngine(scoring, correlation, logger);

        foreach (var monitor in PlatformMonitors.Supported())
            engine.RegisterMonitor(monitor);

        return engine;
    }

    public static IReadOnlyList<string> RegisteredMonitorNames(DetectionEngine engine) =>
        engine.RegisteredMonitors.Select(m => m.GetType().Name).ToList();
}
