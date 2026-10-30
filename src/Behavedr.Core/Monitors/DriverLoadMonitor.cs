namespace Behavedr.Core.Monitors;

using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

/// <summary>
/// Detects BYOVD (Bring Your Own Vulnerable Driver) attacks - kernel drivers used by
/// ransomware groups to disable EDR. Ported from Sentinel DriverLoadMonitor patterns:
/// registry service scan, Event Log 7045, known-vulnerable driver name/hash blocklist,
/// and .sys drops in user-writable paths.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DriverLoadMonitor : IPlatformMonitor
{
    private readonly ILogger<DriverLoadMonitor> _logger;
    private readonly HashSet<string> _baselineDriverServices = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alertedDrivers = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselined;
    private DateTime _lastEventLogQuery = DateTime.UtcNow.AddMinutes(-2);

    // Curated LOLDrivers / Microsoft blocklist subset (SHA-256)
    private static readonly HashSet<string> VulnerableDriverHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        "B7B6DCAB15849B26FDE79E98EA8DD653EB8A3CC4FACF3B829FBD17A3493A2A8E", // Truesight
        "01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD", // RTCore64
        "0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5", // DBUtil
        "11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5", // WinRing0
        "4429F32DB1CC70567919D7D47B844A91CF1329A6CD116F582305F3B7B60CD60B", // iqvw64e
        "73C98438AC64A68E88B7B0AFD11209B8A1FF5B05BA4C3DA0F3F3B5EA8E3EC70B", // Capcom
    };

    private static readonly HashSet<string> VulnerableDriverNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "RTCore64.sys", "RTCore32.sys", "DBUtil_2_3.sys", "DBUtilDrv2.sys",
        "gdrv.sys", "WinRing0x64.sys", "WinRing0.sys", "AsIO64.sys", "AsIO.sys",
        "ProcExp152.sys", "EneIo64.sys", "iqvw64e.sys", "Capcom.sys",
        "DirectIo64.sys", "KProcessHacker.sys", "HpPortIox64.sys",
        "Truesight.sys", "TrueSight.sys", "zamguard64.sys", "ZemanaAntiMalware.sys",
        "elrawdsk.sys", "MsIo64.sys", "NalDrv.sys", "phymemx64.sys",
        "winio64.sys", "inpoutx64.sys", "nbwdv.sys", "echo_driver.sys",
    };

    public string PlatformName => "DriverLoad";
    public bool IsSupported => OperatingSystem.IsWindows();

    public DriverLoadMonitor(ILogger<DriverLoadMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<DriverLoadMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            if (!_baselined)
            {
                BaselineExistingDrivers();
                _baselined = true;
                return Task.FromResult<IEnumerable<Signal>>(signals);
            }

            CheckRegistryForNewDrivers(signals, ct);
            CheckEventLogForDriverInstalls(signals);
            CheckSuspiciousDriverFiles(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DriverLoad] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void BaselineExistingDrivers()
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName);
                    var type = svcKey?.GetValue("Type");
                    if (type is int typeInt && (typeInt is 1 or 2))
                        _baselineDriverServices.Add(svcName);
                }
                catch { }
            }

            _logger.LogInformation("[DriverLoad] Baselined {Count} kernel driver services",
                _baselineDriverServices.Count);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DriverLoad] Baseline failed");
        }
    }

    [SupportedOSPlatform("windows")]
    private void CheckRegistryForNewDrivers(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                if (_baselineDriverServices.Contains(svcName) || _alertedDrivers.Contains(svcName))
                    continue;

                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName);
                    var type = svcKey?.GetValue("Type");
                    if (type is not int typeInt || (typeInt is not (1 or 2))) continue;

                    var imagePath = ExpandImagePath(svcKey?.GetValue("ImagePath")?.ToString() ?? "");
                    _baselineDriverServices.Add(svcName);
                    EvaluateDriver(signals, svcName, imagePath);
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DriverLoad] Registry scan error");
        }
    }

    [SupportedOSPlatform("windows")]
    private void CheckEventLogForDriverInstalls(List<Signal> signals)
    {
        try
        {
            var queryTime = _lastEventLogQuery;
            _lastEventLogQuery = DateTime.UtcNow;

            var xpath = $"*[System[EventID=7045 and TimeCreated[@SystemTime >= '{queryTime:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
            var query = new EventLogQuery("System", PathType.LogName, xpath);

            using var reader = new EventLogReader(query);
            EventRecord? record;
            while ((record = reader.ReadEvent()) is not null)
            {
                using (record)
                {
                    if (record.Properties is null || record.Properties.Count < 3) continue;

                    var serviceName = record.Properties[0]?.Value?.ToString() ?? "";
                    var imagePath = ExpandImagePath(record.Properties[1]?.Value?.ToString() ?? "");
                    var serviceType = record.Properties[2]?.Value?.ToString() ?? "";

                    if (!serviceType.Contains("kernel", StringComparison.OrdinalIgnoreCase) &&
                        !serviceType.Contains("driver", StringComparison.OrdinalIgnoreCase) &&
                        serviceType is not ("1" or "2"))
                        continue;

                    if (_alertedDrivers.Contains(serviceName)) continue;
                    EvaluateDriver(signals, serviceName, imagePath);
                }
            }
        }
        catch (EventLogNotFoundException) { }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DriverLoad] EventLog check error");
        }
    }

    [SupportedOSPlatform("windows")]
    private void CheckSuspiciousDriverFiles(List<Signal> signals, CancellationToken ct)
    {
        var paths = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var basePath in paths)
        {
            if (ct.IsCancellationRequested) break;
            if (string.IsNullOrEmpty(basePath) || !Directory.Exists(basePath)) continue;

            try
            {
                foreach (var sysFile in Directory.EnumerateFiles(basePath, "*.sys", SearchOption.TopDirectoryOnly).Take(8))
                {
                    try
                    {
                        if (File.GetCreationTimeUtc(sysFile) < DateTime.UtcNow.AddMinutes(-5))
                            continue;

                        var name = Path.GetFileName(sysFile);
                        if (VulnerableDriverNames.Contains(name))
                        {
                            signals.Add(new Signal(
                                $"byovd:sys_drop:{name}:{sysFile}", 95, 0.97));
                            continue;
                        }

                        // Any .sys in user-writable path is highly suspicious
                        signals.Add(new Signal(
                            $"byovd:sys_user_path:{name}", 80, 0.85));
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    [SupportedOSPlatform("windows")]
    private void EvaluateDriver(List<Signal> signals, string serviceName, string imagePath)
    {
        if (string.IsNullOrEmpty(serviceName)) return;
        _alertedDrivers.Add(serviceName);

        var fileName = Path.GetFileName(imagePath.Trim('"'));
        var isKnownName = !string.IsNullOrEmpty(fileName) && VulnerableDriverNames.Contains(fileName);
        var isUserWritable = IsUserWritablePath(imagePath);
        var hashMatch = TryMatchVulnerableHash(imagePath);

        if (hashMatch || isKnownName)
        {
            signals.Add(new Signal(
                $"byovd:known_vulnerable:{serviceName}:{fileName}", 98, 0.99));
            _logger.LogCritical("[DriverLoad] Known vulnerable driver service {Service} path {Path}",
                serviceName, imagePath);
            return;
        }

        if (isUserWritable)
        {
            signals.Add(new Signal(
                $"byovd:driver_user_path:{serviceName}:{fileName}", 90, 0.92));
            return;
        }

        // New kernel driver outside baseline - elevated but not automatic kill
        signals.Add(new Signal(
            $"byovd:new_kernel_driver:{serviceName}:{fileName}", 70, 0.75));
    }

    private static string ExpandImagePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        path = path.Trim().Trim('"');
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path["\\SystemRoot\\".Length..]);
        if (path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];
        return Environment.ExpandEnvironmentVariables(path);
    }

    private static bool IsUserWritablePath(string imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        var p = imagePath.ToLowerInvariant();
        return p.Contains(@"\temp\") ||
               p.Contains(@"\appdata\") ||
               p.Contains(@"\users\") ||
               p.Contains(@"\downloads\") ||
               p.Contains(@"\public\");
    }

    private static bool TryMatchVulnerableHash(string imagePath)
    {
        try
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
                return false;

            using var fs = File.OpenRead(imagePath);
            var hash = Convert.ToHexString(SHA256.HashData(fs));
            return VulnerableDriverHashes.Contains(hash);
        }
        catch
        {
            return false;
        }
    }
}
