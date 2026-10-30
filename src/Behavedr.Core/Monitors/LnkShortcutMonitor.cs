namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using System.Text;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects malicious Windows .lnk shortcuts (UNC targets, ms-msdt/search-ms, LOLBin remote args).
/// Lightweight binary parse without COM for reliability under SYSTEM.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LnkShortcutMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<LnkShortcutMonitor> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<string> _pending = new();
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private bool _started;

    public string PlatformName => "LnkShortcut";
    public bool IsSupported => OperatingSystem.IsWindows();

    private static readonly string[] LolBins =
    [
        "powershell", "pwsh", "cmd", "mshta", "wscript", "cscript",
        "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec"
    ];

    public LnkShortcutMonitor(ILogger<LnkShortcutMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LnkShortcutMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if (!IsSupported) return Task.FromResult<IEnumerable<Signal>>(signals);

        try
        {
            EnsureWatchers();

            List<string> batch;
            lock (_lock)
            {
                batch = new List<string>(_pending);
                _pending.Clear();
            }

            foreach (var path in batch)
            {
                if (ct.IsCancellationRequested) break;
                AnalyzeLnk(path, signals);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LnkShortcutMonitor] error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void EnsureWatchers()
    {
        if (_started) return;
        _started = true;

        foreach (var dir in GetWatchDirs())
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                var w = new FileSystemWatcher(dir, "*.lnk")
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
                };
                w.Created += (_, e) => Enqueue(e.FullPath);
                w.Changed += (_, e) => Enqueue(e.FullPath);
                w.EnableRaisingEvents = true;
                _watchers.Add(w);

                // Initial scan (shallow)
                foreach (var f in Directory.EnumerateFiles(dir, "*.lnk", SearchOption.TopDirectoryOnly).Take(50))
                    Enqueue(f);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LnkShortcutMonitor] watcher fail for {Dir}", dir);
            }
        }
    }

    private void Enqueue(string path)
    {
        lock (_lock)
        {
            if (_pending.Count < 100)
                _pending.Add(path);
        }
    }

    private static IEnumerable<string> GetWatchDirs()
    {
        var list = new List<string>();
        try
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var startMenu = Environment.GetFolderPath(Environment.SpecialFolder.StartMenu);
            var commonDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            var commonStart = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu);
            foreach (var d in new[] { desktop, startMenu, commonDesktop, commonStart })
            {
                if (!string.IsNullOrEmpty(d) && Directory.Exists(d))
                    list.Add(d);
            }

            var publicDesktop = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"Microsoft\Windows\Start Menu");
            // Also user Startup
            var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (!string.IsNullOrEmpty(startup) && Directory.Exists(startup))
                list.Add(startup);
        }
        catch { /* ignore */ }
        return list;
    }

    private void AnalyzeLnk(string path, List<Signal> signals)
    {
        if (!File.Exists(path)) return;
        if (!_alerted.Add(path)) return;

        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length < 0x4C) return;
            // Shell Link header magic
            if (BitConverter.ToUInt32(bytes, 0) != 0x0000004C) return;

            var text = Encoding.Unicode.GetString(bytes);
            var ascii = Encoding.ASCII.GetString(bytes);

            var unc = ascii.Contains(@"\\") || text.Contains(@"\\");
            var protocol = ascii.Contains("search-ms:", StringComparison.OrdinalIgnoreCase) ||
                           ascii.Contains("ms-msdt:", StringComparison.OrdinalIgnoreCase) ||
                           text.Contains("search-ms:", StringComparison.OrdinalIgnoreCase) ||
                           text.Contains("ms-msdt:", StringComparison.OrdinalIgnoreCase);

            var lolbinRemote = false;
            foreach (var lb in LolBins)
            {
                if ((ascii.Contains(lb, StringComparison.OrdinalIgnoreCase) ||
                     text.Contains(lb, StringComparison.OrdinalIgnoreCase)) &&
                    (ascii.Contains("http", StringComparison.OrdinalIgnoreCase) ||
                     ascii.Contains(@"\\") || text.Contains(@"\\")))
                {
                    lolbinRemote = true;
                    break;
                }
            }

            if (protocol)
                signals.Add(new Signal($"lnk_protocol_abuse:{Path.GetFileName(path)}", 92, 0.93));
            else if (unc && lolbinRemote)
                signals.Add(new Signal($"lnk_lolbin_unc:{Path.GetFileName(path)}", 88, 0.90));
            else if (unc)
                signals.Add(new Signal($"lnk_unc_target:{Path.GetFileName(path)}", 75, 0.80));
            else if (lolbinRemote)
                signals.Add(new Signal($"lnk_lolbin_remote:{Path.GetFileName(path)}", 80, 0.82));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[LnkShortcutMonitor] parse {Path}", path);
        }
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
            w.Dispose();
        _watchers.Clear();
    }
}
