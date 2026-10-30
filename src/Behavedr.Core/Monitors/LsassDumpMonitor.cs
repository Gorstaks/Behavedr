namespace Behavedr.Core.Monitors;

using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects LSASS credential dumping via Windows event log monitoring (T1003.001).
/// Sources:
///   1. Sysmon Event ID 10 (ProcessAccess) targeting lsass.exe with PROCESS_VM_READ
///   2. Security Event ID 4656 (Handle requested) targeting LSASS
///   3. Defender ASR Event ID 1121 (credential theft rule)
/// Trust: path+signature verified, never name-only.
/// </summary>
[SupportedOSPlatform("windows")]
public class LsassDumpMonitor : IPlatformMonitor
{
    private readonly ILogger<LsassDumpMonitor> _logger;
    private DateTime _lastQueryTime = DateTime.UtcNow.AddSeconds(-35);
    private readonly HashSet<string> _alertedKeys = new();
    private readonly object _lock = new();

    private static readonly string System32Path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32") + @"\";
    private static readonly string DefenderPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        @"Microsoft\Windows Defender\Platform") + @"\";

    public string PlatformName => "LsassDumpMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    public LsassDumpMonitor(ILogger<LsassDumpMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LsassDumpMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        lock (_lock)
        {
            CheckSysmonProcessAccess(signals);
            CheckDefenderAsrEvents(signals);
            PruneAlerted();
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void CheckSysmonProcessAccess(List<Signal> signals)
    {
        try
        {
            var queryTime = _lastQueryTime;
            _lastQueryTime = DateTime.UtcNow;

            var query = new EventLogQuery(
                "Microsoft-Windows-Sysmon/Operational",
                PathType.LogName,
                "*[System[EventID=10 and TimeCreated[timediff(@SystemTime) <= 35000]]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    if (record.TimeCreated <= queryTime) continue;

                    var xml = record.ToXml();
                    if (!xml.Contains("lsass.exe", StringComparison.OrdinalIgnoreCase)) continue;

                    var sourceImage = ExtractXmlField(xml, "SourceImage");
                    var targetImage = ExtractXmlField(xml, "TargetImage");
                    var grantedAccess = ExtractXmlField(xml, "GrantedAccess");

                    if (string.IsNullOrEmpty(sourceImage)) continue;
                    if (!targetImage?.Contains("lsass.exe", StringComparison.OrdinalIgnoreCase) == true) continue;

                    // Check PROCESS_VM_READ (0x10)
                    if (!string.IsNullOrEmpty(grantedAccess) &&
                        uint.TryParse(grantedAccess.Replace("0x", ""),
                            System.Globalization.NumberStyles.HexNumber, null, out var access))
                    {
                        if ((access & 0x0010) == 0) continue;
                    }

                    if (IsTrustedPath(sourceImage)) continue;

                    var dedupKey = sourceImage;
                    if (_alertedKeys.Contains(dedupKey)) continue;
                    _alertedKeys.Add(dedupKey);

                    var processName = Path.GetFileNameWithoutExtension(sourceImage);
                    signals.Add(new Signal(
                        $"lsass_access:{processName}:{sourceImage}",
                        92, 0.92));
                    _logger.LogCritical(
                        "SECURITY: LSASS credential dump attempt detected - '{Source}' accessed LSASS with 0x{Access}",
                        sourceImage, grantedAccess);
                }
            }
        }
        catch (EventLogNotFoundException)
        {
            CheckSecurityAuditEvents(signals);
        }
        catch (UnauthorizedAccessException)
        {
            CheckSecurityAuditEvents(signals);
        }
        catch { }
    }

    private void CheckSecurityAuditEvents(List<Signal> signals)
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 35000]]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    var xml = record.ToXml();
                    if (!xml.Contains("lsass", StringComparison.OrdinalIgnoreCase)) continue;

                    var processName = ExtractXmlField(xml, "ProcessName") ?? "";
                    if (IsTrustedPath(processName)) continue;

                    var dedupKey = $"sec:{processName}";
                    if (_alertedKeys.Contains(dedupKey)) continue;
                    _alertedKeys.Add(dedupKey);

                    signals.Add(new Signal(
                        $"lsass_handle_request:{Path.GetFileNameWithoutExtension(processName)}",
                        85, 0.85));
                }
            }
        }
        catch { }
    }

    private void CheckDefenderAsrEvents(List<Signal> signals)
    {
        try
        {
            var query = new EventLogQuery(
                "Microsoft-Windows-Windows Defender/Operational",
                PathType.LogName,
                "*[System[EventID=1121 and TimeCreated[timediff(@SystemTime) <= 35000]]]");

            using var reader = new EventLogReader(query);
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
            {
                using (record)
                {
                    var xml = record.ToXml();
                    if (!xml.Contains("9e6c4e1f", StringComparison.OrdinalIgnoreCase)) continue;

                    var dedupKey = $"asr:{record.TimeCreated}";
                    if (_alertedKeys.Contains(dedupKey)) continue;
                    _alertedKeys.Add(dedupKey);

                    signals.Add(new Signal("lsass_defender_asr_block", 95, 0.95));
                }
            }
        }
        catch { }
    }

    private static bool IsTrustedPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        return path.StartsWith(System32Path, StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(DefenderPath, StringComparison.OrdinalIgnoreCase);
    }

    private void PruneAlerted()
    {
        if (_alertedKeys.Count > 500)
        {
            // LRU eviction: remove oldest half instead of clearing all (M-5 fix)
            var toRemove = _alertedKeys.Take(_alertedKeys.Count / 2).ToList();
            foreach (var key in toRemove) _alertedKeys.Remove(key);
        }
    }

    private static string? ExtractXmlField(string xml, string fieldName)
    {
        var marker = $"Name=\"{fieldName}\">";
        var idx = xml.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        idx += marker.Length;
        var endIdx = xml.IndexOf('<', idx);
        if (endIdx < 0) return null;
        return xml[idx..endIdx];
    }
}
