namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects PPID spoofing (T1134.004) by comparing kernel-reported parent PID
/// (from NtQueryInformationProcess PROCESS_BASIC_INFORMATION) against the
/// ETW-recorded creator PID in the ProcessAncestryCache.
/// </summary>
[SupportedOSPlatform("windows")]
public class ParentPidSpoofDetector : IPlatformMonitor
{
    private readonly ILogger<ParentPidSpoofDetector> _logger;
    private readonly ProcessAncestryCache _ancestryCache;
    private readonly HashSet<int> _alertedPids = new();

    public string PlatformName => "ParentPidSpoofDetector";
    public bool IsSupported => OperatingSystem.IsWindows();

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    public ParentPidSpoofDetector(ProcessAncestryCache? ancestryCache = null, ILogger<ParentPidSpoofDetector>? logger = null)
    {
        _ancestryCache = ancestryCache ?? new ProcessAncestryCache();
        _logger = logger ?? NullLogger<ParentPidSpoofDetector>.Instance;
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

                    var pbi = new PROCESS_BASIC_INFORMATION();
                    int status = NtQueryInformationProcess(
                        proc.Handle, 0, ref pbi,
                        Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);

                    if (status != 0) continue;

                    int kernelParentPid = (int)pbi.InheritedFromUniqueProcessId;
                    var cachedParentPid = _ancestryCache.GetParentPid(proc.Id);

                    if (cachedParentPid > 0 && cachedParentPid != kernelParentPid && kernelParentPid > 4)
                    {
                        signals.Add(new Signal(
                            $"ppid_spoof:{proc.ProcessName}:pid:{proc.Id}:kernel_parent:{kernelParentPid}:etw_parent:{cachedParentPid}",
                            90, 0.88));
                        _alertedPids.Add(proc.Id);
                        _logger.LogCritical(
                            "SECURITY: PPID spoofing detected - '{Process}' (PID {Pid}) kernel parent={KernelParent}, ETW parent={EtwParent}",
                            proc.ProcessName, proc.Id, kernelParentPid, cachedParentPid);
                    }
                }
                catch (System.ComponentModel.Win32Exception) { }
                catch (InvalidOperationException) { }
                catch { }
                finally { proc.Dispose(); }
            }

            if (_alertedPids.Count > 500)
        {
            // LRU eviction: remove oldest half instead of clearing all (M-5 fix)
            var toRemove = _alertedPids.Take(_alertedPids.Count / 2).ToList();
            foreach (var pid in toRemove) _alertedPids.Remove(pid);
        }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[ParentPidSpoofDetector] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }
}
