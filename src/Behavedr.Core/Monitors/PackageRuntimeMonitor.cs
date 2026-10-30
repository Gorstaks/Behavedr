namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Cross-platform package-manager runtime abuse: postinstall LOLBins, exe drops
/// under package trees, and AI agent config poisoning (CLAUDE.md / Cursor / MCP).
/// </summary>
public sealed class PackageRuntimeMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<PackageRuntimeMonitor> _logger;
    private readonly HashSet<int> _pkgPids = new();
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _configEvents = new();
    private readonly object _lock = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private bool _watcherStarted;
    private DateTime _lastPrune = DateTime.UtcNow;

    public string PlatformName => "PackageRuntime";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private static readonly HashSet<string> PackageManagers = new(StringComparer.OrdinalIgnoreCase)
    {
        "npm", "npx", "pnpm", "yarn", "pip", "pip3", "uv", "cargo",
        "dotnet", "gem", "go", "nuget", "choco", "winget", "python", "python3"
    };

    private static readonly HashSet<string> DangerousChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "mshta", "certutil", "bitsadmin",
        "wscript", "cscript", "regsvr32", "rundll32", "curl", "wget",
        "bash", "sh", "zsh", "wsl", "nc", "ncat", "socat"
    };

    private static readonly string[] PackageTreeFragments =
    {
        "node_modules", "site-packages", ".cargo", "packages",
        ".nuget", "bower_components", "venv", ".venv"
    };

    private static readonly HashSet<string> DevConfigNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CLAUDE.md", ".cursorrules", "AGENTS.md", "mcp.json", ".mcp.json", "gemini.md"
    };

    public PackageRuntimeMonitor(ILogger<PackageRuntimeMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<PackageRuntimeMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if (!IsSupported) return Task.FromResult<IEnumerable<Signal>>(signals);

        try
        {
            EnsureWatcher();
            if ((DateTime.UtcNow - _lastPrune).TotalMinutes > 10)
            {
                _pkgPids.Clear();
                _alerted.Clear();
                _lastPrune = DateTime.UtcNow;
            }

            List<string> configCopy;
            lock (_lock)
            {
                configCopy = new List<string>(_configEvents);
                _configEvents.Clear();
            }

            foreach (var path in configCopy)
            {
                if (_alerted.Add("cfg:" + path))
                    signals.Add(new Signal($"dev_config_poison:{Path.GetFileName(path)}:{path}", 55, 0.60));
            }

            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return Task.FromResult<IEnumerable<Signal>>(signals); }

            var idToName = new Dictionary<int, string>();
            var idToPpid = new Dictionary<int, int>();

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    idToName[p.Id] = Normalize(p.ProcessName);
                    idToPpid[p.Id] = GetParentPid(p.Id);
                }
                catch { /* skip */ }
            }

            foreach (var (pid, name) in idToName)
            {
                if (PackageManagers.Contains(name))
                    _pkgPids.Add(pid);
            }

            foreach (var (pid, name) in idToName)
            {
                if (ct.IsCancellationRequested) break;
                if (!idToPpid.TryGetValue(pid, out var ppid)) continue;
                var parentName = idToName.GetValueOrDefault(ppid, "");
                if (!_pkgPids.Contains(ppid) && !PackageManagers.Contains(parentName))
                    continue;

                string? path = null;
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    path = GetImagePath(proc);
                }
                catch { /* deny */ }

                var dangerous = DangerousChildren.Contains(name);
                var inTree = path != null && PackageTreeFragments.Any(f =>
                    path.Contains(f, StringComparison.OrdinalIgnoreCase));
                var exeDrop = path != null && inTree &&
                    (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                     path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                     path.EndsWith(".so", StringComparison.OrdinalIgnoreCase) ||
                     path.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase));

                if (!dangerous && !exeDrop) continue;

                var key = $"{ppid}:{name}:{dangerous}:{exeDrop}";
                if (!_alerted.Add(key)) continue;

                if (dangerous && (name is "mshta" or "certutil" or "powershell" or "pwsh" or "bash" or "sh"))
                    signals.Add(new Signal($"pkg_lolbin:{parentName}->{name}:pid={pid}", 85, 0.88));
                else if (exeDrop)
                    signals.Add(new Signal($"pkg_exe_drop:{parentName}:{path}", 72, 0.75));
                else
                    signals.Add(new Signal($"pkg_child:{parentName}->{name}:pid={pid}", 60, 0.65));
            }

            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { /* ignore */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[PackageRuntimeMonitor] error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void EnsureWatcher()
    {
        if (_watcherStarted) return;
        _watcherStarted = true;

        // CI runners: skip FSW entirely (FSEvents can hang EnableRaisingEvents).
        if (IsCiEnvironment())
            return;

        // Shallow watches only - recursive Documents FSWs hang/slow CI on macOS runners.
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new List<string?>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            string.IsNullOrEmpty(home) ? null : Path.Combine(home, "source"),
            string.IsNullOrEmpty(home) ? null : Path.Combine(home, "repos"),
            string.IsNullOrEmpty(home) ? null : Path.Combine(home, "dev"),
            string.IsNullOrEmpty(home) ? null : Path.Combine(home, "Projects"),
        };

        foreach (var root in roots)
        {
            try
            {
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
                var w = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    Filter = "*.*",
                    InternalBufferSize = 16 * 1024
                };
                w.Created += OnConfigEvent;
                w.Changed += OnConfigEvent;
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[PackageRuntimeMonitor] config watcher unavailable for {Root}", root);
            }
        }
    }

    private void OnConfigEvent(object sender, FileSystemEventArgs e)
    {
        try
        {
            var name = Path.GetFileName(e.FullPath);
            if (string.IsNullOrEmpty(name) || !DevConfigNames.Contains(name)) return;
            var parts = e.FullPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (parts.Length > 14) return;
            lock (_lock)
            {
                if (_configEvents.Count < 50)
                    _configEvents.Add(e.FullPath);
            }
        }
        catch { /* ignore */ }
    }

    private static string Normalize(string name)
    {
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return name[..^4];
        if (name.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)) return name[..^4];
        return name;
    }

    private static int GetParentPid(int pid)
    {
        if (OperatingSystem.IsWindows())
            return WindowsParentPid(pid);
        if (OperatingSystem.IsLinux())
        {
            try
            {
                foreach (var line in File.ReadLines($"/proc/{pid}/status"))
                {
                    if (line.StartsWith("PPid:", StringComparison.Ordinal))
                        return int.Parse(line["PPid:".Length..].Trim());
                }
            }
            catch { /* ignore */ }
        }
        return 0;
    }

    [SupportedOSPlatform("windows")]
    private static int WindowsParentPid(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId={pid}");
            foreach (var obj in searcher.Get())
                return Convert.ToInt32(obj["ParentProcessId"]);
        }
        catch { /* ignore */ }
        return 0;
    }

    private static string? GetImagePath(Process p)
    {
        try
        {
            if (OperatingSystem.IsWindows()) return p.MainModule?.FileName;
            if (OperatingSystem.IsLinux() && File.Exists($"/proc/{p.Id}/exe"))
                return new FileInfo($"/proc/{p.Id}/exe").LinkTarget;
        }
        catch { /* deny */ }
        return null;
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
            w.Dispose();
        _watchers.Clear();
    }

    private static bool IsCiEnvironment() =>
        string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase);
}
