namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

/// <summary>
/// Detects persistence via Windows Task Scheduler (T1053.005) and WMI
/// Event Subscriptions (T1546.003). Baselines existing tasks at startup
/// and alerts on new task creation at runtime.
/// </summary>
[SupportedOSPlatform("windows")]
public class ScheduledTaskMonitor : IPlatformMonitor
{
    private readonly ILogger<ScheduledTaskMonitor> _logger;
    private readonly HashSet<string> _baselineTasks = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alertedTasks = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _baselineWmiSubs = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselined;

    // Tasks from these authors/paths are expected system tasks
    private static readonly HashSet<string> TrustedTaskPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        @"\Microsoft\", @"\Apple\", @"\Google\", @"\Mozilla\",
        @"\Adobe\", @"\Hewlett-Packard\", @"\Intel\",
    };

    public string PlatformName => "ScheduledTaskMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    public ScheduledTaskMonitor(ILogger<ScheduledTaskMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<ScheduledTaskMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var currentTasks = EnumerateScheduledTasks();

            if (!_baselined)
            {
                _baselineTasks.UnionWith(currentTasks);
                _baselineWmiSubs.UnionWith(EnumerateWmiSubscriptions());
                _baselined = true;
                return Task.FromResult<IEnumerable<Signal>>(signals);
            }

            // Detect new scheduled tasks
            foreach (var task in currentTasks)
            {
                if (ct.IsCancellationRequested) break;
                if (_baselineTasks.Contains(task)) continue;
                if (_alertedTasks.Contains(task)) continue;

                _baselineTasks.Add(task);
                _alertedTasks.Add(task);

                // Skip known trusted task paths
                if (TrustedTaskPrefixes.Any(p => task.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                    continue;

                signals.Add(new Signal(
                    $"new_scheduled_task:{task}",
                    75, 0.80));
                _logger.LogWarning(
                    "SECURITY: New scheduled task created at runtime: '{Task}' - possible persistence (T1053.005)",
                    task);
            }

            // Detect new WMI event subscriptions
            var currentWmi = EnumerateWmiSubscriptions();
            foreach (var sub in currentWmi)
            {
                if (ct.IsCancellationRequested) break;
                if (_baselineWmiSubs.Contains(sub)) continue;
                _baselineWmiSubs.Add(sub);

                signals.Add(new Signal(
                    $"new_wmi_subscription:{sub}",
                    80, 0.85));
                _logger.LogCritical(
                    "SECURITY: New WMI event subscription created: '{Sub}' - possible persistence (T1546.003)",
                    sub);
            }

            if (_alertedTasks.Count > 500) _alertedTasks.Clear();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[ScheduledTaskMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Enumerate scheduled tasks via the Task Scheduler registry keys.
    /// This avoids COM interop complexity and works without Task Scheduler service access.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static HashSet<string> EnumerateScheduledTasks()
    {
        var tasks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            EnumerateTasksRecursive(
                Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
                tasks);
        }
        catch { }

        // Also check the Tree key for task paths
        try
        {
            EnumerateTreeRecursive(
                Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
                "",
                tasks);
        }
        catch { }

        return tasks;
    }

    [SupportedOSPlatform("windows")]
    private static void EnumerateTasksRecursive(RegistryKey root, string path, HashSet<string> tasks)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key == null) return;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                try
                {
                    using var taskKey = key.OpenSubKey(subKeyName);
                    var taskPath = taskKey?.GetValue("Path")?.ToString();
                    if (!string.IsNullOrEmpty(taskPath))
                        tasks.Add(taskPath);
                }
                catch { }
            }
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private static void EnumerateTreeRecursive(RegistryKey root, string path, string prefix, HashSet<string> tasks)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key == null) return;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                var fullPath = string.IsNullOrEmpty(prefix)
                    ? @"\" + subKeyName
                    : prefix + @"\" + subKeyName;

                // If this subkey has an "Id" value, it's a task leaf
                try
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    if (subKey?.GetValue("Id") != null)
                        tasks.Add(fullPath);
                    else
                        EnumerateTreeRecursive(root, path + @"\" + subKeyName, fullPath, tasks);
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>
    /// Enumerate WMI permanent event subscriptions (EventFilter + EventConsumer bindings).
    /// These are stored in the WMI repository and accessed via WMI queries.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private HashSet<string> EnumerateWmiSubscriptions()
    {
        var subs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"root\subscription",
                "SELECT * FROM __FilterToConsumerBinding");
            foreach (System.Management.ManagementObject binding in searcher.Get())
            {
                var filter = binding["Filter"]?.ToString() ?? "";
                var consumer = binding["Consumer"]?.ToString() ?? "";
                subs.Add($"{filter}->{consumer}");
            }
        }
        catch { }
        return subs;
    }
}
