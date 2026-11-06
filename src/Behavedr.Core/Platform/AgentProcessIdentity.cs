namespace Behavedr.Core.Platform;

using System.Collections.Concurrent;
using System.Diagnostics;

/// <summary>
/// Identifies processes the agent owns: the agent itself, direct children, and processes
/// the agent launched on purpose (response actions). Ownership is keyed by PID plus process
/// start time, so a recycled PID never inherits ownership (same approach as Sentinel's
/// SafeProcessExemptionRegistry).
/// </summary>
public static class AgentProcessIdentity
{
    private static readonly ConcurrentDictionary<int, long> SpawnedStartTicks = new();

    /// <summary>Record a child process the agent started so monitors ignore its activity.</summary>
    public static void TrackSpawned(int pid)
    {
        if (pid <= 4) return;
        if (TryGetStartTicks(pid, out var ticks))
            SpawnedStartTicks[pid] = ticks;
    }

    /// <summary>
    /// True for the agent process, for any process whose parent is the agent, and for
    /// processes recorded with <see cref="TrackSpawned"/> that are still the same process.
    /// </summary>
    public static bool IsAgentOwned(int pid, int? parentPid = null)
    {
        if (pid <= 0) return false;
        if (pid == Environment.ProcessId) return true;
        if (parentPid is { } parent && parent == Environment.ProcessId) return true;
        if (!SpawnedStartTicks.TryGetValue(pid, out var registered)) return false;

        if (TryGetStartTicks(pid, out var current) && current == registered)
            return true;

        // Process exited or the PID was reused: forget the stale entry.
        SpawnedStartTicks.TryRemove(pid, out _);
        return false;
    }

    private static bool TryGetStartTicks(int pid, out long ticks)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            ticks = process.StartTime.ToUniversalTime().Ticks;
            return true;
        }
        catch
        {
            ticks = 0;
            return false;
        }
    }
}
