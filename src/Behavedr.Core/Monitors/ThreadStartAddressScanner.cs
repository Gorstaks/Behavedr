namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects reflective DLL injection, shellcode, and direct syscall execution (T1055)
/// by scanning thread start addresses against loaded module ranges.
/// Threads starting at unmapped memory indicate injected code execution.
/// </summary>
[SupportedOSPlatform("windows")]
public class ThreadStartAddressScanner : IPlatformMonitor
{
    private readonly ILogger<ThreadStartAddressScanner> _logger;
    private readonly HashSet<int> _alertedPids = new();

    private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "java", "javaw", "node", "python", "python3", "dotnet",
        "pwsh", "powershell", "chrome", "msedge", "firefox", "brave",
        "teams", "discord", "spotify", "code", "electron",
    };

    public string PlatformName => "ThreadStartAddressScanner";
    public bool IsSupported => OperatingSystem.IsWindows();

    public ThreadStartAddressScanner(ILogger<ThreadStartAddressScanner>? logger = null)
    {
        _logger = logger ?? NullLogger<ThreadStartAddressScanner>.Instance;
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
                    if (_alertedPids.Contains(proc.Id)) continue;
                    if (JitProcesses.Contains(proc.ProcessName)) continue;

                    var modules = new List<(IntPtr Base, IntPtr End)>();
                    try
                    {
                        foreach (ProcessModule mod in proc.Modules)
                        {
                            if (mod.BaseAddress != IntPtr.Zero)
                                modules.Add((mod.BaseAddress, IntPtr.Add(mod.BaseAddress, mod.ModuleMemorySize)));
                        }
                    }
                    catch (System.ComponentModel.Win32Exception) { continue; }

                    if (modules.Count == 0) continue;

                    foreach (ProcessThread thread in proc.Threads)
                    {
                        if (ct.IsCancellationRequested) break;
                        IntPtr startAddr;
                        try { startAddr = thread.StartAddress; }
                        catch { continue; }

                        if (startAddr == IntPtr.Zero) continue;

                        bool inside = false;
                        foreach (var (b, e) in modules)
                        {
                            if ((ulong)startAddr >= (ulong)b && (ulong)startAddr <= (ulong)e)
                            { inside = true; break; }
                        }

                        if (!inside)
                        {
                            _alertedPids.Add(proc.Id);
                            signals.Add(new Signal(
                                $"unmapped_thread_start:{proc.ProcessName}:pid:{proc.Id}:thread:{thread.Id}:addr:0x{startAddr:X}",
                                85, 0.90));
                            _logger.LogCritical(
                                "SECURITY: Unmapped thread start address in '{Process}' (PID {Pid}) - thread {Thread} at 0x{Addr:X}",
                                proc.ProcessName, proc.Id, thread.Id, (ulong)startAddr);
                            break;
                        }
                    }
                }
                catch (System.ComponentModel.Win32Exception) { }
                catch (InvalidOperationException) { }
                catch { }
                finally { proc.Dispose(); }
            }

            if (_alertedPids.Count > 500) _alertedPids.Clear();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[ThreadStartAddressScanner] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }
}
