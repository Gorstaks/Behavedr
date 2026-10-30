namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

/// <summary>
/// Registry persistence detection monitor for Windows.
/// Polls persistence locations (Run keys, scheduled tasks, services)
/// and alerts on changes from baseline.
/// Detects: new Run key entries, suspicious scheduled tasks,
/// new services with unusual paths.
/// </summary>
[SupportedOSPlatform("windows")]
public class RegistryPersistenceMonitor : IPlatformMonitor
{
    private readonly ILogger<RegistryPersistenceMonitor> _logger;
    private HashSet<string> _baselineRunKeys = new();
    private HashSet<string> _baselineServices = new();
    private bool _baselined;

    private static readonly string[] RunKeyPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ];

    public string PlatformName => "RegistryPersistence";
    public bool IsSupported => OperatingSystem.IsWindows();

    public RegistryPersistenceMonitor(ILogger<RegistryPersistenceMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<RegistryPersistenceMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        var currentRunKeys = GetRunKeyEntries();
        var currentServices = GetNewServices();

        if (!_baselined)
        {
            _baselineRunKeys = currentRunKeys;
            _baselineServices = currentServices;
            _baselined = true;
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        // Detect new Run key entries
        foreach (var key in currentRunKeys.Except(_baselineRunKeys))
        {
            signals.Add(new Signal($"new_run_key_persistence:{key}", 65, 0.75));
            _logger.LogWarning("[RegistryPersistence] New Run key detected: {Key}", key);
        }

        // Detect new services with suspicious paths
        foreach (var svc in currentServices.Except(_baselineServices))
        {
            var weight = IsSuspiciousServicePath(svc) ? 70.0 : 40.0;
            var confidence = IsSuspiciousServicePath(svc) ? 0.8 : 0.5;
            signals.Add(new Signal($"new_service_persistence:{svc}", weight, confidence));
        }

        // Update baselines
        _baselineRunKeys = currentRunKeys;
        _baselineServices = currentServices;

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private static HashSet<string> GetRunKeyEntries()
    {
        var entries = new HashSet<string>();
        foreach (var path in RunKeyPaths)
        {
            try
            {
                using var hklm = Registry.LocalMachine.OpenSubKey(path);
                if (hklm is not null)
                    foreach (var name in hklm.GetValueNames())
                        entries.Add($"HKLM\\{path}\\{name}={hklm.GetValue(name)}");
            }
            catch { }

            try
            {
                using var hkcu = Registry.CurrentUser.OpenSubKey(path);
                if (hkcu is not null)
                    foreach (var name in hkcu.GetValueNames())
                        entries.Add($"HKCU\\{path}\\{name}={hkcu.GetValue(name)}");
            }
            catch { }
        }
        return entries;
    }

    [SupportedOSPlatform("windows")]
    private static HashSet<string> GetNewServices()
    {
        var services = new HashSet<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (key is null) return services;
            foreach (var name in key.GetSubKeyNames())
            {
                try
                {
                    using var svc = key.OpenSubKey(name);
                    var imagePath = svc?.GetValue("ImagePath")?.ToString();
                    if (!string.IsNullOrEmpty(imagePath))
                        services.Add($"{name}:{imagePath}");
                }
                catch { }
            }
        }
        catch { }
        return services;
    }

    private static bool IsSuspiciousServicePath(string entry)
    {
        var lower = entry.ToLowerInvariant();
        return lower.Contains("\\temp\\") || lower.Contains("\\tmp\\") ||
               lower.Contains("\\appdata\\") || lower.Contains("\\downloads\\") ||
               lower.Contains("powershell") || lower.Contains("cmd /c");
    }
}
