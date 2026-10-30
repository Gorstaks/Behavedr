namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Unified ETW (Event Tracing for Windows) session for real-time kernel telemetry.
/// Uses two-tier approach:
///   1. Primary: WMI Win32_ProcessStartTrace subscription (works without admin on some systems)
///   2. Future: Full ETW P/Invoke via StartTraceW/EnableTraceEx2/OpenTraceW/ProcessTrace
///      (requires elevation, provides ~50ms latency)
///
/// Provider GUIDs (verified from Microsoft documentation and Windows SDK):
///   Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
///   Microsoft-Windows-Threat-Intelligence: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
///     (Requires PPL/ELAM signed driver - not accessible from userland)
///   Microsoft-Windows-DNS-Client: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
///
/// References:
///   https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
///   https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
///   https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
///   https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EtwSession : IDisposable
{
    private readonly ILogger<EtwSession> _logger;
    private readonly List<EtwProcessEvent> _processEvents = new();
    private readonly object _lock = new();
    private bool _isActive;
    private Thread? _processingThread;
    private CancellationTokenSource? _cts;
    private System.Management.ManagementEventWatcher? _wmiProcessStart;
    private System.Management.ManagementEventWatcher? _wmiProcessStop;

    // 
    // ETW Constants - verified from Windows SDK headers (evntrace.h, evntcons.h, wmistr.h)
    // Source: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
    // 

    // evntrace.h - Logging Mode Constants
    // https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
    private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;

    // evntrace.h - EnableFlags for system trace (EVENT_TRACE_PROPERTIES.EnableFlags)
    // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
    private const uint EVENT_TRACE_FLAG_PROCESS = 0x00000001;
    private const uint EVENT_TRACE_FLAG_THREAD = 0x00000002;
    private const uint EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004;
    private const uint EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000;
    private const uint EVENT_TRACE_FLAG_REGISTRY = 0x00020000;
    private const uint EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200;
    private const uint EVENT_TRACE_FLAG_DISK_IO = 0x00000100;
    private const uint EVENT_TRACE_FLAG_FILE_IO = 0x02000000;
    private const uint EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000;

    // wmistr.h - WNODE_HEADER.Flags
    private const uint WNODE_FLAG_TRACED_GUID = 0x00020000;

    // evntcons.h - ProcessTraceMode flags for OpenTrace
    private const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
    private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;

    // evntrace.h - EnableTraceEx2 ControlCode
    private const uint EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0;
    private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
    private const uint EVENT_CONTROL_CODE_CAPTURE_STATE = 2;

    // evntrace.h - Trace levels
    private const byte TRACE_LEVEL_VERBOSE = 5;
    private const byte TRACE_LEVEL_INFORMATION = 4;

    // 
    // Provider GUIDs - verified from Microsoft documentation and logman.exe
    // 

    /// <summary>
    /// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
    /// Source: logman query providers Microsoft-Windows-Kernel-Process
    /// Verified: https://docs.velociraptor.app/artifact_references/pages/windows.etw.kernelprocess/
    /// </summary>
    private static readonly Guid KernelProcessProviderGuid =
        new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

    /// <summary>
    /// Microsoft-Windows-Threat-Intelligence: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
    /// Source: logman query providers Microsoft-Windows-Threat-Intelligence
    /// Note: Requires PPL (Protected Process Light) Anti-Malware access.
    /// Cannot be consumed from a standard userland process without ELAM driver.
    /// Verified: https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/
    /// </summary>
    private static readonly Guid ThreatIntelProviderGuid =
        new("F4E1897C-BB5D-5668-F1D8-040F4D8DD344");

    /// <summary>
    /// Microsoft-Windows-DNS-Client: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
    /// Source: logman query providers Microsoft-Windows-DNS-Client
    /// </summary>
    private static readonly Guid DnsClientProviderGuid =
        new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    public bool IsActive => _isActive;

    public EtwSession(ILogger<EtwSession>? logger = null)
    {
        _logger = logger ?? NullLogger<EtwSession>.Instance;
    }

    /// <summary>
    /// Start the ETW trace session. Uses WMI Win32_ProcessStartTrace/Win32_ProcessStopTrace
    /// as a managed, reliable approach. Full native ETW session via StartTraceW requires
    /// admin/SYSTEM and provides lower latency (~50ms vs ~1-2s for WMI).
    /// </summary>
    public bool TryStart()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            _cts = new CancellationTokenSource();
            _isActive = TryStartWmiSubscription();

            if (_isActive)
            {
                _logger.LogInformation("[EtwSession] Process trace subscription started (WMI)");
                _processingThread = new Thread(ProcessEventsLoop)
                {
                    IsBackground = true,
                    Name = "Behavedr-ETW-Processor",
                    Priority = ThreadPriority.AboveNormal
                };
                _processingThread.Start();
            }
            else
            {
                _logger.LogWarning("[EtwSession] Could not start process trace - falling back to polling");
            }

            return _isActive;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[EtwSession] ETW initialization failed - falling back to polling");
            _isActive = false;
            return false;
        }
    }

    /// <summary>
    /// Drain all process events collected since last call.
    /// Thread-safe - called from the monitoring loop.
    /// </summary>
    public List<EtwProcessEvent> DrainProcessEvents()
    {
        lock (_lock)
        {
            if (_processEvents.Count == 0)
                return new List<EtwProcessEvent>();

            var events = new List<EtwProcessEvent>(_processEvents);
            _processEvents.Clear();
            return events;
        }
    }

    // 
    // WMI-based process trace (primary implementation)
    // Win32_ProcessStartTrace and Win32_ProcessStopTrace are WMI intrinsic
    // events backed by the kernel's ETW process provider.
    // WQL class properties: ProcessID, ParentProcessID, ProcessName, SessionID
    // 

    [SupportedOSPlatform("windows")]
    private bool TryStartWmiSubscription()
    {
        try
        {
            // Win32_ProcessStartTrace - fires on every process creation
            // Properties: ProcessID (uint32), ParentProcessID (uint32),
            //             ProcessName (string), SessionID (uint32)
            var startQuery = new System.Management.WqlEventQuery(
                "SELECT * FROM Win32_ProcessStartTrace");
            _wmiProcessStart = new System.Management.ManagementEventWatcher(startQuery);
            _wmiProcessStart.EventArrived += OnWmiProcessStarted;
            _wmiProcessStart.Start();

            // Win32_ProcessStopTrace - fires on every process exit
            var stopQuery = new System.Management.WqlEventQuery(
                "SELECT * FROM Win32_ProcessStopTrace");
            _wmiProcessStop = new System.Management.ManagementEventWatcher(stopQuery);
            _wmiProcessStop.EventArrived += OnWmiProcessStopped;
            _wmiProcessStop.Start();

            return true;
        }
        catch (System.Management.ManagementException ex)
        {
            // Access denied (non-admin) or WMI service unavailable
            _logger.LogDebug(ex, "[EtwSession] WMI process trace subscription failed (likely needs admin)");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[EtwSession] WMI subscription failed");
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private void OnWmiProcessStarted(object sender, System.Management.EventArrivedEventArgs e)
    {
        try
        {
            // Win32_ProcessStartTrace property names are documented in MSDN:
            // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/krnlprov/win32-processstarttra
            var processName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? "";
            var processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
            var parentId = Convert.ToInt32(e.NewEvent.Properties["ParentProcessID"]?.Value ?? 0);

            var evt = new EtwProcessEvent
            {
                ProcessId = processId,
                ParentProcessId = parentId,
                ProcessName = processName,
                Timestamp = DateTime.UtcNow,
                EventType = ProcessEventType.Start
            };

            lock (_lock)
            {
                _processEvents.Add(evt);
                // Cap buffer to prevent unbounded memory growth
                if (_processEvents.Count > 10_000)
                    _processEvents.RemoveRange(0, 5_000);
            }
        }
        catch { /* Best-effort - don't crash on malformed events */ }
    }

    [SupportedOSPlatform("windows")]
    private void OnWmiProcessStopped(object sender, System.Management.EventArrivedEventArgs e)
    {
        try
        {
            var processName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? "";
            var processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
            var parentId = Convert.ToInt32(e.NewEvent.Properties["ParentProcessID"]?.Value ?? 0);

            var evt = new EtwProcessEvent
            {
                ProcessId = processId,
                ParentProcessId = parentId,
                ProcessName = processName,
                Timestamp = DateTime.UtcNow,
                EventType = ProcessEventType.Stop
            };

            lock (_lock)
            {
                _processEvents.Add(evt);
                if (_processEvents.Count > 10_000)
                    _processEvents.RemoveRange(0, 5_000);
            }
        }
        catch { }
    }

    private void ProcessEventsLoop()
    {
        // Background thread - future: host full ETW ProcessTrace blocking call here.
        // ProcessTrace blocks the calling thread until the trace is stopped,
        // delivering events via the EventRecordCallback.
        while (_cts is not null && !_cts.IsCancellationRequested)
        {
            Thread.Sleep(100);
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _isActive = false;

        if (OperatingSystem.IsWindows())
        {
            try { _wmiProcessStart?.Stop(); _wmiProcessStart?.Dispose(); } catch { }
            try { _wmiProcessStop?.Stop(); _wmiProcessStop?.Dispose(); } catch { }
        }

        _cts?.Dispose();
    }
}

// 
// P/Invoke declarations for future full native ETW implementation.
// These are the correct struct layouts per Windows SDK evntrace.h.
// Currently unused - WMI subscription handles process events adequately.
// When upgrading to full ETW: use StartTraceW -> EnableTraceEx2 -> OpenTraceW -> ProcessTrace
// 

// Reference: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
// [DllImport("advapi32.dll", EntryPoint = "StartTraceW", CharSet = CharSet.Unicode)]
// static extern uint StartTrace(out long sessionHandle, string sessionName, IntPtr properties);

// Reference: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
// [DllImport("advapi32.dll")]
// static extern uint EnableTraceEx2(long traceHandle, ref Guid providerId, uint controlCode,
//     byte level, ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

// Reference: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
// [DllImport("advapi32.dll", EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode)]
// static extern long OpenTrace(ref EVENT_TRACE_LOGFILEW logfile);

// Reference: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
// [DllImport("advapi32.dll")]
// static extern uint ProcessTrace(long[] handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

// Reference: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace
// [DllImport("advapi32.dll")]
// static extern uint CloseTrace(long traceHandle);

// Reference: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
// [DllImport("advapi32.dll", EntryPoint = "ControlTraceW", CharSet = CharSet.Unicode)]
// static extern uint ControlTrace(long sessionHandle, string? sessionName, IntPtr properties, uint controlCode);

/// <summary>
/// Represents a process event captured from ETW/WMI.
/// </summary>
public record EtwProcessEvent
{
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public string? CommandLine { get; init; }
    public string? ImagePath { get; init; }
    public DateTime Timestamp { get; init; }
    public ProcessEventType EventType { get; init; }
}

public enum ProcessEventType
{
    Start,
    Stop,
    ImageLoad
}
