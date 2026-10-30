namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Windows named-pipe C2 / lateral movement detection (Cobalt Strike, PsExec, Impacket, etc.).
/// Ported from Sentinel patterns for Behavedr Windows parity.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NamedPipeMonitor : IPlatformMonitor
{
    private readonly ILogger<NamedPipeMonitor> _logger;
    private readonly HashSet<string> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselined;

    public string PlatformName => "NamedPipe";
    public bool IsSupported => OperatingSystem.IsWindows();

    private static readonly Regex[] KnownBadPatterns =
    [
        new(@"^msagent_[a-f0-9]{2,8}$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^MSSE-[0-9]{1,4}-server$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^postex_[a-f0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^postex_ssh_[a-f0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^status_[a-f0-9]{2,8}$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^psexecsvc(-[a-z0-9]+)?$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^RemCom_(stdin|stdout|stderr)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^meterpreter_", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^msf_", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^sliver_", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^havoc_[a-f0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"^[a-f0-9]{32,}$", RegexOptions.Compiled),
    ];

    private static readonly string[] LegitimatePrefixes =
    [
        "lsass", "ntsvcs", "scerpc", "samr", "netlogon", "wkssvc", "srvsvc",
        "browser", "atsvc", "eventlog", "spoolss", "winreg", "chrome.", "chromium.",
        "crashpad_", "mojo_", "discord-ipc-", "dotnet-diagnostic-", "docker_engine",
        "openssh-ssh-agent", "LOCAL\\edge_", "LOCAL\\chrome."
    ];

    public NamedPipeMonitor(ILogger<NamedPipeMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<NamedPipeMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if (!IsSupported) return Task.FromResult<IEnumerable<Signal>>(signals);

        try
        {
            string[] pipes;
            try { pipes = Directory.GetFiles(@"\\.\pipe\"); }
            catch { return Task.FromResult<IEnumerable<Signal>>(signals); }

            var names = pipes
                .Select(p => Path.GetFileName(p) ?? p)
                .Where(n => !string.IsNullOrEmpty(n))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (!_baselined)
            {
                _baseline.UnionWith(names);
                _baselined = true;
                return Task.FromResult<IEnumerable<Signal>>(signals);
            }

            foreach (var name in names)
            {
                if (ct.IsCancellationRequested) break;
                if (_baseline.Contains(name)) continue;
                _baseline.Add(name);

                if (LegitimatePrefixes.Any(l => name.StartsWith(l, StringComparison.OrdinalIgnoreCase) ||
                                                name.Contains(l, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var knownBad = KnownBadPatterns.Any(r => r.IsMatch(name));
                var highEntropy = name.Length >= 16 && IsHighEntropy(name);

                if (!knownBad && !highEntropy) continue;
                if (!_alerted.Add(name)) continue;

                if (knownBad)
                    signals.Add(new Signal($"named_pipe_c2:{name}", 90, 0.92));
                else
                    signals.Add(new Signal($"named_pipe_suspicious:{name}", 55, 0.60));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[NamedPipeMonitor] error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private static bool IsHighEntropy(string s)
    {
        if (s.Length < 12) return false;
        var counts = new int[256];
        foreach (var c in s)
            counts[c % 256]++;
        double ent = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            var p = (double)c / s.Length;
            ent -= p * Math.Log2(p);
        }
        return ent > 3.8;
    }
}
