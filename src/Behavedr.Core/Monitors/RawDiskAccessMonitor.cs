namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects processes performing raw disk I/O by opening physical device paths
/// (\\.\PhysicalDrive0, \\.\C:). Catches bootkits, forensic wiping, and
/// filesystem-level exfiltration (T1006).
/// </summary>
[SupportedOSPlatform("windows")]
public class RawDiskAccessMonitor : IPlatformMonitor
{
    private readonly ILogger<RawDiskAccessMonitor> _logger;
    private readonly HashSet<string> _alertedKeys = new();

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    private static readonly HashSet<string> AllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "vds", "vdsldr", "diskmgmt", "diskpart", "defrag",
        "chkdsk", "sfc", "dism", "wbengine", "vssvc",
        "msiexec", "trustedinstaller", "tiworker",
        "Taskmgr", "resmon", "perfmon", "mmc", "SystemInformer",
        "svchost", "system", "behavedr",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public string PlatformName => "RawDiskAccessMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    public RawDiskAccessMonitor(ILogger<RawDiskAccessMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<RawDiskAccessMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            // Method 1: Command-line heuristic (original approach)
            ScanCommandLinePatterns(signals, ct);

            // Method 2: RT-1 FIX - Handle-based detection via NtQuerySystemInformation
            ScanProcessHandlesForRawDisk(signals, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[RawDiskAccessMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void ScanCommandLinePatterns(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (ct.IsCancellationRequested) break;
                    if (proc.Id <= 4 || proc.Id == Environment.ProcessId) continue;

                    var name = proc.ProcessName;
                    if (AllowedProcesses.Contains(name)) continue;

                    string? cmdLine = null;
                    try
                    {
                        using var searcher = new System.Management.ManagementObjectSearcher(
                            $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            cmdLine = obj["CommandLine"]?.ToString();
                            break;
                        }
                    }
                    catch { }

                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    if (ContainsRawDiskPattern(cmdLine))
                    {
                        var key = $"{proc.Id}:{name}";
                        if (_alertedKeys.Contains(key)) continue;
                        _alertedKeys.Add(key);

                        string? imagePath = null;
                        try { imagePath = proc.MainModule?.FileName; } catch { }

                        bool isSystem = imagePath != null &&
                            imagePath.StartsWith(WinDir, StringComparison.OrdinalIgnoreCase);

                        if (!isSystem)
                        {
                            signals.Add(new Signal(
                                $"raw_disk_access:{name}:pid:{proc.Id}:path:{imagePath ?? "unknown"}",
                                85, 0.80));
                            _logger.LogCritical(
                                "SECURITY: Raw disk access detected - '{Process}' (PID {Pid}) accessing physical device",
                                name, proc.Id);
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    // --- RT-1 FIX: Handle-based raw disk detection via NtQuerySystemInformation ---

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass, IntPtr systemInformation,
        int systemInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(
        IntPtr handle, int objectInformationClass,
        IntPtr objectInformation, int objectInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
        uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    private const int SystemHandleInformation = 16;
    private const int ObjectNameInformation = 1;
    private const uint PROCESS_DUP_HANDLE = 0x0040;
    private const uint DUPLICATE_SAME_ACCESS = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_ENTRY
    {
        public int OwnerPid;
        public byte ObjectType;
        public byte HandleFlags;
        public short HandleValue;
        public IntPtr ObjectPointer;
        public uint GrantedAccess;
    }

    /// <summary>
    /// RT-1 FIX: Scan the system handle table for handles to raw disk device objects.
    /// Uses NtQuerySystemInformation(SystemHandleInformation) to enumerate all open handles,
    /// then NtQueryObject to resolve handle names matching PhysicalDrive/HarddiskVolume patterns.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private void ScanProcessHandlesForRawDisk(List<Signal> signals, CancellationToken ct)
    {
        try
        {
            // Get handle table size
            int size = 1024 * 1024; // Start with 1MB
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                int status;
                while ((status = NtQuerySystemInformation(SystemHandleInformation, buffer, size, out var needed)) == unchecked((int)0xC0000004)) // STATUS_INFO_LENGTH_MISMATCH
                {
                    Marshal.FreeHGlobal(buffer);
                    size = needed + 65536;
                    if (size > 64 * 1024 * 1024) return; // Safety cap at 64MB
                    buffer = Marshal.AllocHGlobal(size);
                }

                if (status != 0) return;

                int handleCount = Marshal.ReadInt32(buffer);
                int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_ENTRY>();
                var checkedPids = new HashSet<int>();

                for (int i = 0; i < handleCount && i < 500000; i++)
                {
                    if (ct.IsCancellationRequested) break;

                    var entry = Marshal.PtrToStructure<SYSTEM_HANDLE_ENTRY>(
                        buffer + 4 + (i * entrySize)); // +4 for handle count int

                    int pid = entry.OwnerPid;
                    if (pid <= 4 || pid == Environment.ProcessId) continue;
                    if (_alertedKeys.Contains($"handle:{pid}")) continue;

                    // Only check each PID once per scan
                    if (checkedPids.Contains(pid)) continue;

                    // Try to resolve handle name - expensive, so only do for suspicious access masks
                    // FILE_READ_DATA | FILE_WRITE_DATA on disk objects typically have high access
                    if (entry.GrantedAccess < 0x0012001F) continue; // Skip low-access handles

                    var procHandle = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
                    if (procHandle == IntPtr.Zero) continue;

                    try
                    {
                        if (!DuplicateHandle(procHandle, (IntPtr)entry.HandleValue,
                            GetCurrentProcess(), out var dupHandle, 0, false, DUPLICATE_SAME_ACCESS))
                            continue;

                        try
                        {
                            var name = QueryObjectName(dupHandle);
                            if (name != null && IsRawDiskObjectName(name))
                            {
                                checkedPids.Add(pid);
                                var procName = GetProcessNameSafe(pid);
                                if (procName != null && !AllowedProcesses.Contains(procName))
                                {
                                    var key = $"handle:{pid}";
                                    _alertedKeys.Add(key);

                                    signals.Add(new Signal(
                                        $"raw_disk_handle:{procName}:pid:{pid}:object:{name}",
                                        92, 0.92));
                                    _logger.LogCritical(
                                        "SECURITY: Raw disk device handle detected - '{Process}' (PID {Pid}) " +
                                        "has open handle to '{Object}' (T1006)",
                                        procName, pid, name);
                                }
                            }
                        }
                        finally { CloseHandle(dupHandle); }
                    }
                    finally { CloseHandle(procHandle); }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[RawDiskAccessMonitor] Handle scan failed (may require elevation)");
        }

        if (_alertedKeys.Count > 500) _alertedKeys.Clear();
    }

    private static string? QueryObjectName(IntPtr handle)
    {
        int size = 1024;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            int status = NtQueryObject(handle, ObjectNameInformation, buffer, size, out var needed);
            if (status != 0) return null;

            // UNICODE_STRING: ushort Length, ushort MaxLength, IntPtr Buffer
            int length = Marshal.ReadInt16(buffer);
            if (length <= 0) return null;
            var strPtr = Marshal.ReadIntPtr(buffer + 4); // After Length + MaxLength (4 bytes on x64 padded)
            if (strPtr == IntPtr.Zero)
                strPtr = buffer + IntPtr.Size + 4; // Inline buffer

            return Marshal.PtrToStringUni(buffer + IntPtr.Size, length / 2);
        }
        catch { return null; }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool IsRawDiskObjectName(string name)
    {
        return name.Contains(@"\Device\Harddisk", StringComparison.OrdinalIgnoreCase) ||
               name.Contains(@"\Device\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
               name.Contains(@"\Device\CdRom", StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetProcessNameSafe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return null; }
    }

    private static bool ContainsRawDiskPattern(string cmdLine)
    {
        return cmdLine.Contains(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\\.\PHYSICALDRIVE", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\Device\Harddisk", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\\.\C:", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\\.\D:", StringComparison.OrdinalIgnoreCase);
    }
}
