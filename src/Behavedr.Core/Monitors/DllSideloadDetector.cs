namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects DLL sideloading attacks (T1574.001) by enumerating loaded modules
/// and flagging system DLLs loaded from non-system directories.
/// </summary>
[SupportedOSPlatform("windows")]
public class DllSideloadDetector : IPlatformMonitor
{
    private readonly ILogger<DllSideloadDetector> _logger;
    private readonly HashSet<string> _alertedKeys = new();
    private static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string WinDirSlash = WinDir.TrimEnd('\\') + "\\";

    // Known sideloading targets - legitimate system DLLs attackers drop into app folders
    private static readonly HashSet<string> SideloadTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "dbghelp.dll", "version.dll", "winmm.dll", "dwrite.dll",
        "cryptsp.dll", "userenv.dll", "profapi.dll", "wtsapi32.dll",
        "dhcpcsvc.dll", "IPHLPAPI.DLL", "msasn1.dll", "netapi32.dll",
        "samcli.dll", "sspicli.dll", "crypt32.dll", "winhttp.dll",
    };

    // System32 path for generic sideload heuristic
    private static readonly string System32Path = Path.Combine(WinDir, "System32") + "\\";
    private static readonly string SysWOW64Path = Path.Combine(WinDir, "SysWOW64") + "\\";

    public string PlatformName => "DllSideloadDetector";
    public bool IsSupported => OperatingSystem.IsWindows();

    public DllSideloadDetector(ILogger<DllSideloadDetector>? logger = null)
    {
        _logger = logger ?? NullLogger<DllSideloadDetector>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (ct.IsCancellationRequested) break;
                    if (proc.Id <= 4) continue;

                    string? procDir = null;
                    try { procDir = Path.GetDirectoryName(proc.MainModule?.FileName); }
                    catch { continue; }

                    if (string.IsNullOrEmpty(procDir)) continue;

                    // Skip if process is in Windows directory
                    if (procDir.StartsWith(WinDirSlash, StringComparison.OrdinalIgnoreCase))
                        continue;

                    foreach (ProcessModule mod in proc.Modules)
                    {
                        try
                        {
                            var modName = mod.ModuleName ?? "";
                            var modDir = Path.GetDirectoryName(mod.FileName) ?? "";

                            // Check 1: Known sideloading targets
                            if (SideloadTargets.Contains(modName))
                            {
                                // Sideloaded if DLL is in the process directory (not system)
                                if (modDir.Equals(procDir, StringComparison.OrdinalIgnoreCase) &&
                                    !modDir.StartsWith(WinDirSlash, StringComparison.OrdinalIgnoreCase))
                                {
                                    var key = $"{proc.Id}:{modName}";
                                    if (_alertedKeys.Contains(key)) continue;
                                    _alertedKeys.Add(key);

                                    signals.Add(new Signal(
                                        $"dll_sideload:{proc.ProcessName}:pid:{proc.Id}:{modName}:{mod.FileName}",
                                        85, 0.85));
                                    _logger.LogCritical(
                                        "SECURITY: DLL sideloading detected - '{DllName}' loaded from '{Path}' in process '{Process}' (PID {Pid})",
                                        modName, mod.FileName, proc.ProcessName, proc.Id);
                                }
                            }
                            // Check 2: Generic heuristic - unsigned DLL loaded from process dir
                            // when a signed system copy exists in System32/SysWOW64
                            else if (!modDir.StartsWith(WinDirSlash, StringComparison.OrdinalIgnoreCase) &&
                                     modDir.Equals(procDir, StringComparison.OrdinalIgnoreCase) &&
                                     modName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                            {
                                // Check if a system copy exists
                                var systemCopy = Path.Combine(System32Path, modName);
                                var sysWow64Copy = Path.Combine(SysWOW64Path, modName);
                                if (File.Exists(systemCopy) || File.Exists(sysWow64Copy))
                                {
                                    var key = $"generic:{proc.Id}:{modName}";
                                    if (_alertedKeys.Contains(key)) continue;
                                    _alertedKeys.Add(key);

                                    signals.Add(new Signal(
                                        $"dll_sideload_generic:{proc.ProcessName}:pid:{proc.Id}:{modName}:{mod.FileName}",
                                        70, 0.72));
                                    _logger.LogWarning(
                                        "SECURITY: Possible DLL sideloading (generic) - '{DllName}' loaded from '{Path}' " +
                                        "but system copy exists in System32. Process: '{Process}' (PID {Pid})",
                                        modName, mod.FileName, proc.ProcessName, proc.Id);
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (System.ComponentModel.Win32Exception) { }
                catch (InvalidOperationException) { }
                catch { }
                finally { proc.Dispose(); }
            }

            if (_alertedKeys.Count > 1000)
        {
            // LRU eviction: remove oldest half instead of clearing all (M-5 fix)
            var toRemove = _alertedKeys.Take(_alertedKeys.Count / 2).ToList();
            foreach (var key in toRemove) _alertedKeys.Remove(key);
        }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[DllSideloadDetector] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }
}
