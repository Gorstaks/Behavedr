namespace Behavedr.Core.Platform;

using Behavedr.Core.Monitors;

/// <summary>
/// Catalog of all Behavedr platform monitors (desktop + mobile).
/// v0.1.3: Shared NativeEtwSession and ProcessAncestryCache are created once
/// and injected into all monitors that need them (fixes C-2, H-4 from audit).
/// </summary>
public static class PlatformMonitors
{
    // Shared infrastructure instances - created once, shared across monitors.
    private static NativeEtwSession? _sharedEtwSession;
    private static ProcessAncestryCache? _sharedAncestryCache;

    /// <summary>Shared ETW session for all monitors that consume process/DNS events.</summary>
    public static NativeEtwSession? SharedEtwSession => _sharedEtwSession;

    /// <summary>Shared process ancestry cache for PPID spoof detection and chain tracing.</summary>
    public static ProcessAncestryCache SharedAncestryCache =>
        _sharedAncestryCache ??= new ProcessAncestryCache();

    /// <summary>Every known platform monitor (supported or not).</summary>
    public static IReadOnlyList<IPlatformMonitor> All { get; } = BuildMonitorList();

    private static List<IPlatformMonitor> BuildMonitorList()
    {
        var monitors = new List<IPlatformMonitor>
        {
            // Platform-specific process monitors
            new WindowsMonitor(),
            new LinuxMonitor(),
            new MacOSMonitor(),
            new AndroidMonitor(),

            // v0.0.7: Cross-platform monitors
            new FileActivityMonitor(),
            new ConnectivityCanaryMonitor(),
        };

        // Cross-platform monitors (beaconing works everywhere now)
        monitors.Add(new BeaconingDetector());
        monitors.Add(new UnixDataExfiltrationMonitor());
        monitors.Add(new UnixBehavioralMonitor());
        monitors.Add(new UnixDnsMonitor());
        monitors.Add(new UnixCredentialCanary());
        monitors.Add(new UnixGhostProcessMonitor());

        // v0.4.1: AI agent + supply-chain runtime + ransomware canaries (desktop)
        monitors.Add(new AgenticProcessMonitor());
        monitors.Add(new PackageRuntimeMonitor());
        monitors.Add(new CanaryFileMonitor());
        monitors.Add(new CloudSyncExfilMonitor());

        // v0.0.7+: Windows-only behavioral detection & anti-tamper monitors
        if (OperatingSystem.IsWindows())
        {
            // v0.1.3: Create shared ETW session and ancestry cache (C-2 fix)
            _sharedEtwSession = new NativeEtwSession();
            _sharedEtwSession.TryStart();

            _sharedAncestryCache = new ProcessAncestryCache();

            monitors.Add(new BehavioralMonitor(_sharedEtwSession));
            monitors.Add(new AntiTamperGuard());
            monitors.Add(new NetworkConnectionMonitor());
            monitors.Add(new MemoryAnalyzer());
            monitors.Add(new CredentialGuardMonitor());
            monitors.Add(new CredentialCanaryMonitor());
            monitors.Add(new RegistryPersistenceMonitor());

            // v0.0.9: Monitors from audit remediation
            monitors.Add(new DnsQueryMonitor(_sharedEtwSession));
            monitors.Add(new DataExfiltrationMonitor());

            // v0.1.1: P0 - Critical audit findings from Sentinel cross-reference
            monitors.Add(new LsassDumpMonitor());
            monitors.Add(new ParentPidSpoofDetector(_sharedAncestryCache));
            monitors.Add(new DllSideloadDetector());

            // v0.1.1: P1 - High-priority detection gaps
            monitors.Add(new GhostProcessMonitor());
            monitors.Add(new TokenIntegrityMonitor());
            monitors.Add(new EphemeralProcessMonitor());
            monitors.Add(new NetworkShareMonitor());
            monitors.Add(new RawDiskAccessMonitor());

            // v0.1.1: P2 - Medium-priority detection enhancements
            monitors.Add(new ThreadStartAddressScanner());
            monitors.Add(new WslMonitor());

            // v0.1.2: Scheduled task and WMI persistence monitoring (RT-10)
            monitors.Add(new ScheduledTaskMonitor());

            // v0.2.2: BYOVD / vulnerable driver load detection (from Sentinel)
            monitors.Add(new DriverLoadMonitor());

            // v0.4.1: Windows parity kill-chain monitors (from Sentinel threat brief)
            monitors.Add(new NamedPipeMonitor());
            monitors.Add(new LnkShortcutMonitor());
            monitors.Add(new ScriptExecutionMonitor());
        }

        // v0.1.5: Linux full detection suite (cross-platform parity)
        if (OperatingSystem.IsLinux())
        {
            monitors.Add(new LinuxNetworkMonitor());
            monitors.Add(new LinuxMemoryAnalyzer());
            monitors.Add(new LinuxCredentialMonitor());
            monitors.Add(new LinuxPersistenceMonitor());
            monitors.Add(new LinuxTokenMonitor());
            monitors.Add(new LinuxEphemeralProcessMonitor());
            monitors.Add(new UnixAntiTamperGuard());
            monitors.Add(new UnixSelfProtection());

            // v0.2.0: Real-time event sourcing (eliminates polling blind spots)
            monitors.Add(new LinuxProcessConnector());
            monitors.Add(new LinuxFanotifyMonitor());

            // v0.2.3: Kernel module + auth log coverage (Linux grade lift)
            monitors.Add(new LinuxKernelModuleMonitor());
            monitors.Add(new LinuxAuthMonitor());

            // v0.2.7-0.2.8: eBPF suite (exec + file + net depth; soft-fail)
            monitors.Add(new LinuxEbpfExecMonitor());
            monitors.Add(new LinuxEbpfFileMonitor());
            monitors.Add(new LinuxEbpfNetMonitor());
        }

        // v0.1.5: macOS full detection suite (cross-platform parity)
        if (OperatingSystem.IsMacOS())
        {
            monitors.Add(new MacOSNetworkMonitor());
            monitors.Add(new MacOSMemoryAnalyzer());
            monitors.Add(new MacOSPersistenceMonitor());
            monitors.Add(new MacOSCredentialMonitor());
            monitors.Add(new UnixAntiTamperGuard());
            monitors.Add(new UnixSelfProtection());

            // v0.1.6: Real-time process event monitoring via kqueue (RT-1 fix)
            monitors.Add(new MacOSKqueueMonitor());

            // v0.2.3: File VNODE events + codesign integrity (macOS grade lift)
            monitors.Add(new MacOSFileEventMonitor());
            monitors.Add(new MacOSCodeSignMonitor());

            // v0.2.7: EndpointSecurity epic (needs entitlement + libbehavedr_es.dylib)
            monitors.Add(new MacOSEndpointSecurityMonitor());
        }

        // v0.1.5: Android full detection suite
        if (OperatingSystem.IsAndroid())
        {
            monitors.Add(new AndroidNetworkMonitor());
            monitors.Add(new AndroidPersistenceMonitor());

            // v0.1.8: Android self-protection (anti-debug, Frida, repackaging, emulator)
            monitors.Add(new AndroidSelfProtection());

            // v0.2.0: Android audit fixes - real-time events, memory, credentials, anti-tamper
            monitors.Add(new AndroidProcessConnector());
            monitors.Add(new AndroidMemoryAnalyzer());
            monitors.Add(new AndroidCredentialMonitor());
            monitors.Add(new AndroidAntiTamperGuard());
        }

        return monitors;
    }

    /// <summary>Monitors whose <see cref="IPlatformMonitor.IsSupported"/> is true on this OS.</summary>
    public static IEnumerable<IPlatformMonitor> Supported() =>
        All.Where(m => m.IsSupported);

    public static string CurrentPlatformSummary()
    {
        if (OperatingSystem.IsWindows()) return "Windows";
        if (OperatingSystem.IsLinux()) return "Linux";
        if (OperatingSystem.IsMacOS()) return "macOS";
        if (OperatingSystem.IsAndroid()) return "Android";
        if (OperatingSystem.IsIOS()) return "iOS";
        if (OperatingSystem.IsMacCatalyst()) return "Mac Catalyst";
        return "Unknown";
    }
}
