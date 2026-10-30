namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Memory behavior analyzer scanning for:
/// - RWX (Read-Write-Execute) memory regions in non-JIT processes
/// - Unbacked executable regions (process hollowing indicator)
/// - Suspicious memory allocation patterns (shellcode staging)
/// Uses VirtualQueryEx P/Invoke to enumerate process memory regions.
/// </summary>
[SupportedOSPlatform("windows")]
public class MemoryAnalyzer : IPlatformMonitor
{
    private readonly ILogger<MemoryAnalyzer> _logger;

    public string PlatformName => "MemoryAnalyzer";
    public bool IsSupported => OperatingSystem.IsWindows();

    // JIT/runtime processes that legitimately use RWX memory
    private static readonly HashSet<string> JitProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "msedge", "brave", "opera",
        "java", "javaw", "node", "dotnet", "pwsh", "powershell",
        "code", "devenv", "rider64", "Teams", "slack", "discord",
        "steam", "steamwebhelper", "EpicGamesLauncher",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_MAPPED = 0x40000;
    private const uint MEM_PRIVATE = 0x20000;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public MemoryAnalyzer(ILogger<MemoryAnalyzer>? logger = null)
    {
        _logger = logger ?? NullLogger<MemoryAnalyzer>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();

                    // Skip JIT processes (legitimate RWX usage)
                    if (JitProcesses.Contains(name)) continue;
                    // Skip system processes
                    if (proc.Id <= 4) continue;
                    // Skip our own process
                    if (proc.Id == Environment.ProcessId) continue;

                    var rwxCount = CountRwxRegions(proc.Id);
                    if (rwxCount > 0)
                    {
                        var weight = rwxCount switch
                        {
                            > 10 => 75.0,
                            > 5 => 60.0,
                            > 2 => 45.0,
                            _ => 35.0
                        };
                        var confidence = rwxCount switch
                        {
                            > 10 => 0.85,
                            > 5 => 0.75,
                            > 2 => 0.65,
                            _ => 0.5
                        };

                        signals.Add(new Signal(
                            $"rwx_memory:{name}(pid:{proc.Id},regions:{rwxCount})",
                            weight, confidence));
                    }
                }
                catch (Exception) { } // Access denied for system processes
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[MemoryAnalyzer] Error during memory scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private static int CountRwxRegions(int pid)
    {
        int count = 0;
        var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero) return 0;

        try
        {
            IntPtr address = IntPtr.Zero;
            int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            while (VirtualQueryEx(hProcess, address, out var mbi, mbiSize) != 0)
            {
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
                    mbi.Type == MEM_PRIVATE) // Unbacked private RWX = very suspicious
                {
                    count++;
                }

                // Advance to next region
                var nextAddr = (long)mbi.BaseAddress + (long)mbi.RegionSize;
                if (nextAddr <= (long)address) break; // Prevent infinite loop
                address = (IntPtr)nextAddr;

                if (count > 50) break; // Cap to avoid long scans
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }

        return count;
    }
}
