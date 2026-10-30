namespace Behavedr.Core.Response;

using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Production Windows network isolation via Windows Firewall COM (HNetCfg.FwPolicy2).
/// Stable user-mode path that installs WFP filters through BFE - documented, elevates
/// with SYSTEM service. Primary isolator; <see cref="WindowsWfpEngine"/> is the direct WFP path.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewallEngine : IDisposable
{
    // NET_FW_ACTION_BLOCK = 0, ALLOW = 1
    private const int ActionBlock = 0;
    // NET_FW_RULE_DIR_IN = 1, OUT = 2
    private const int DirIn = 1;
    private const int DirOut = 2;
    // NET_FW_IP_PROTOCOL_ANY = 256
    private const int ProtocolAny = 256;
    // All profiles
    private const int ProfilesAll = 0x7FFFFFFF;

    private readonly ILogger _logger;
    private readonly HashSet<string> _ruleNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private const int MaxRules = 100;
    private dynamic? _policy;
    private bool _disposed;

    public bool IsAvailable { get; private set; }

    public WindowsFirewallEngine(ILogger? logger = null)
    {
        _logger = logger ?? NullLogger.Instance;
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (t is null)
            {
                _logger.LogWarning("[FwCOM] HNetCfg.FwPolicy2 ProgID not available");
                return;
            }
            _policy = Activator.CreateInstance(t);
            IsAvailable = _policy is not null;
            if (IsAvailable)
                _logger.LogInformation("[FwCOM] Windows Firewall policy engine ready");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[FwCOM] Failed to create FwPolicy2");
            IsAvailable = false;
        }
    }

    public bool BlockRemoteAddress(IPAddress address, string comment)
    {
        if (!IsAvailable || _policy is null)
            return false;
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return false;

        lock (_lock)
        {
            if (_ruleNames.Count >= MaxRules)
            {
                _logger.LogWarning("[FwCOM] Rule limit {Max}", MaxRules);
                return false;
            }
        }

        var ip = address.ToString();
        var baseName = $"Behavedr_Block_{SanitizeName(ip)}";
        bool okOut = AddRemoteRule(baseName + "_Out", ip, DirOut, comment);
        bool okIn = AddRemoteRule(baseName + "_In", ip, DirIn, comment);
        if (okOut || okIn)
        {
            _logger.LogWarning("[FwCOM] Blocked {Ip} out={Out} in={In}", ip, okOut, okIn);
            return true;
        }
        return false;
    }

    public bool BlockApplication(string imagePath, string comment)
    {
        if (!IsAvailable || _policy is null || string.IsNullOrWhiteSpace(imagePath))
            return false;
        if (!File.Exists(imagePath))
            return false;

        try
        {
            var ruleType = Type.GetTypeFromProgID("HNetCfg.FwRule");
            if (ruleType is null) return false;
            dynamic rule = Activator.CreateInstance(ruleType)!;
            var name = $"Behavedr_App_{Math.Abs(imagePath.GetHashCode(StringComparison.OrdinalIgnoreCase)):X8}";

            lock (_lock)
            {
                if (_ruleNames.Contains(name))
                    return true;
                if (_ruleNames.Count >= MaxRules)
                    return false;
            }

            rule.Name = name;
            rule.Description = string.IsNullOrEmpty(comment) ? "Behavedr process isolation" : comment;
            rule.ApplicationName = imagePath;
            rule.Action = ActionBlock;
            rule.Direction = DirOut;
            rule.Enabled = true;
            rule.Profiles = ProfilesAll;
            rule.Protocol = ProtocolAny;
            _policy.Rules.Add(rule);
            lock (_lock) _ruleNames.Add(name);
            _logger.LogWarning("[FwCOM] Blocked application outbound {Path}", imagePath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[FwCOM] App block failed for {Path}", imagePath);
            return false;
        }
    }

    /// <summary>Remove Behavedr-managed rules created in this process (best-effort).</summary>
    public int RemoveManagedRules()
    {
        if (!IsAvailable || _policy is null) return 0;
        int removed = 0;
        string[] names;
        lock (_lock) names = _ruleNames.ToArray();
        foreach (var name in names)
        {
            try
            {
                _policy.Rules.Remove(name);
                lock (_lock) _ruleNames.Remove(name);
                removed++;
            }
            catch
            {
                // rule may already be gone
            }
        }
        return removed;
    }

    private bool AddRemoteRule(string name, string remoteIp, int direction, string comment)
    {
        try
        {
            lock (_lock)
            {
                if (_ruleNames.Contains(name))
                    return true;
            }

            var ruleType = Type.GetTypeFromProgID("HNetCfg.FwRule");
            if (ruleType is null) return false;
            dynamic rule = Activator.CreateInstance(ruleType)!;
            rule.Name = name;
            rule.Description = string.IsNullOrEmpty(comment) ? "Behavedr isolation" : comment;
            rule.Protocol = ProtocolAny;
            rule.RemoteAddresses = remoteIp;
            rule.Action = ActionBlock;
            rule.Direction = direction;
            rule.Enabled = true;
            rule.Profiles = ProfilesAll;
            _policy!.Rules.Add(rule);
            lock (_lock) _ruleNames.Add(name);
            return true;
        }
        catch (COMException ex)
        {
            _logger.LogDebug(ex, "[FwCOM] AddRule failed {Name} hr=0x{Hr:X8}", name, ex.HResult);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[FwCOM] AddRule error {Name}", name);
            return false;
        }
    }

    private static string SanitizeName(string ip) =>
        ip.Replace(':', '_').Replace('.', '_').Replace('%', '_');

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Rules intentionally left installed until reboot/admin cleanup -
        // isolation must survive agent crash. Operators can remove Behavedr_* rules
        // or call RemoveManagedRules before process exit if desired.
        if (_policy is not null && Marshal.IsComObject(_policy))
        {
            try { Marshal.ReleaseComObject(_policy); } catch { /* ignore */ }
        }
        _policy = null;
        IsAvailable = false;
    }
}
