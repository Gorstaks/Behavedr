using System.Runtime.InteropServices;

namespace Behavedr.Tests;

/// <summary>
/// Guards that epic source trees and production loaders remain present (0.4.0).
/// Does not require Linux/macOS attach success on Windows CI.
/// </summary>
public class EpicCompletenessTests
{
    [Fact]
    public void EbpfSuiteSource_ExistsAndDocumentsLayout()
    {
        var root = FindRepoRoot();
        var suite = Path.Combine(root, "native", "linux", "ebpf", "behavedr_suite.bpf.c");
        Assert.True(File.Exists(suite));
        Assert.True(File.Exists(Path.Combine(root, "native", "linux", "ebpf", "README.md")));
        Assert.True(File.Exists(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "LinuxEbpfLoader.cs")));
        Assert.True(File.Exists(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "LinuxEbpfSuite.cs")));

        var c = File.ReadAllText(suite);
        Assert.Contains("EV_EXEC", c, StringComparison.Ordinal);
        Assert.Contains("EV_OPEN", c, StringComparison.Ordinal);
        Assert.Contains("EV_CONNECT", c, StringComparison.Ordinal);
        Assert.Contains("handle_exec", c, StringComparison.Ordinal);
        Assert.Contains("handle_openat", c, StringComparison.Ordinal);
        Assert.Contains("handle_connect", c, StringComparison.Ordinal);
        Assert.Contains("struct behavedr_event", c, StringComparison.Ordinal);
    }

    [Fact]
    public void EndpointSecuritySystemExtension_IsRealHostNotStub()
    {
        var root = FindRepoRoot();
        var main = Path.Combine(root, "native", "macos", "SystemExtension", "main.m");
        Assert.True(File.Exists(main));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "SystemExtension", "entitlements.plist")));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "es_bridge", "behavedr_es_bridge.c")));

        var m = File.ReadAllText(main);
        Assert.Contains("es_new_client", m, StringComparison.Ordinal);
        Assert.Contains("es_subscribe", m, StringComparison.Ordinal);
        Assert.Contains("es_respond_auth_result", m, StringComparison.Ordinal);
        Assert.Contains("es.events", m, StringComparison.Ordinal);
        Assert.DoesNotContain("placeholder", m, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("TODO: implement", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EpicsStatusDoc_Exists()
    {
        var root = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(root, "docs", "EPICS_STATUS.md")));
        var doc = File.ReadAllText(Path.Combine(root, "docs", "EPICS_STATUS.md"));
        Assert.True(
            doc.Contains("0.4.3", StringComparison.Ordinal) || doc.Contains("0.4.", StringComparison.Ordinal),
            "EPICS_STATUS should reference the 0.4.x line");
        Assert.Contains("In-repo", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("complete", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("field activation", doc, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LinuxEbpfLoader_FindsNothingOnWindowsWithoutObject()
    {
        if (OperatingSystem.IsLinux()) return;
        var loader = new Behavedr.Core.Monitors.LinuxEbpfLoader();
        Assert.Null(loader.FindObject());
    }

    [Fact]
    public void EbpfEventLayout_MatchesDocumentedSize()
    {
        // kind+pid+tgid+pad = 16; comm = 16; path = 112 -> 144
        Assert.Equal(144, Behavedr.Core.Monitors.LinuxEbpfLoader.EventSize);
        Assert.Equal(256, Behavedr.Core.Monitors.LinuxEbpfLoader.MaxSlots);
    }

    [Fact]
    public void LinuxEbpfSuite_SharedIsSingleton()
    {
        var a = Behavedr.Core.Monitors.LinuxEbpfSuite.Shared();
        var b = Behavedr.Core.Monitors.LinuxEbpfSuite.Shared();
        Assert.Same(a, b);
        Assert.False(a.IsActive); // no object on this host typically
    }

    [Fact]
    public void WindowsFirewallEngine_Constructs()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fw = new Behavedr.Core.Response.WindowsFirewallEngine();
        // Availability depends on COM registration; construction must not throw
        _ = fw.IsAvailable;
    }

    [Fact]
    public void WindowsWfpEngine_Constructs()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var wfp = new Behavedr.Core.Response.WindowsWfpEngine();
        Assert.False(wfp.IsOpen); // not opened until first block
    }

    [Fact]
    public void WindowsNetworkIsolation_WiresComFirst()
    {
        var root = FindRepoRoot();
        var src = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Core", "Response", "WindowsNetworkIsolation.cs"));
        Assert.Contains("WindowsFirewallEngine", src, StringComparison.Ordinal);
        Assert.Contains("WindowsWfpEngine", src, StringComparison.Ordinal);
        // Order: COM then WFP then netsh
        var com = src.IndexOf("_fwCom", StringComparison.Ordinal);
        var wfp = src.IndexOf("_wfp.BlockRemoteAddress", StringComparison.Ordinal);
        var netsh = src.IndexOf("BlockIpNetshAsync", StringComparison.Ordinal);
        Assert.True(com > 0 && wfp > com && netsh > wfp);
    }

    [Fact]
    public void EsBridgeSource_ExportsPollApiAndAuthGate()
    {
        var root = FindRepoRoot();
        var c = File.ReadAllText(Path.Combine(root, "native", "macos", "es_bridge", "behavedr_es_bridge.c"));
        Assert.Contains("behavedr_es_poll", c, StringComparison.Ordinal);
        Assert.Contains("behavedr_es_create", c, StringComparison.Ordinal);
        Assert.Contains("behavedr_es_subscribe_default", c, StringComparison.Ordinal);
        Assert.Contains("behavedr_es_set_auth_mode", c, StringComparison.Ordinal);
        Assert.Contains("BEHAVEDR_ES_RING", c, StringComparison.Ordinal);
        Assert.Contains("memory_order_release", c, StringComparison.Ordinal);
        Assert.Contains("g_auth_mode", c, StringComparison.Ordinal);
        Assert.Contains("es_respond_flags_result", c, StringComparison.Ordinal);
        // Full ring: drop newest (fetch_add dropped), do not steal consumer tail
        Assert.Contains("drop newest", c, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("g_dropped", c, StringComparison.Ordinal);
    }

    [Fact]
    public void SystemdUnit_AllowsBpffsForEbpf()
    {
        var root = FindRepoRoot();
        var unit = File.ReadAllText(Path.Combine(root, "packaging", "unix", "behavedr.service"));
        Assert.Contains("bpf", unit, StringComparison.Ordinal);
        Assert.Contains("/sys/fs/bpf/behavedr", unit, StringComparison.Ordinal);
        Assert.Contains("ProtectKernelTunables=false", unit, StringComparison.Ordinal);
        Assert.Contains("CAP_BPF", unit, StringComparison.Ordinal);
    }

    [Fact]
    public void ManagedEsMonitor_PrefersSubscribeDefault()
    {
        var root = FindRepoRoot();
        var src = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "MacOSEndpointSecurityMonitor.cs"));
        Assert.Contains("behavedr_es_subscribe_default", src, StringComparison.Ordinal);
        Assert.DoesNotContain("ES_EVENT_TYPE_AUTH_EXEC = 8", src, StringComparison.Ordinal);
    }

    [Fact]
    public void EbpfSuite_FiltersOpenatAndUsesAtomicCursor()
    {
        var root = FindRepoRoot();
        var c = File.ReadAllText(Path.Combine(root, "native", "linux", "ebpf", "behavedr_suite.bpf.c"));
        Assert.Contains("__sync_fetch_and_add", c, StringComparison.Ordinal);
        Assert.Contains("path_is_interesting_open", c, StringComparison.Ordinal);
        Assert.Contains("AF_INET", c, StringComparison.Ordinal);
    }

    [Fact]
    public void LegacyExecTrace_IsHardErrorNotBuildable()
    {
        var root = FindRepoRoot();
        var c = File.ReadAllText(Path.Combine(root, "native", "linux", "ebpf", "exec_trace.bpf.c"));
        Assert.Contains("#error", c, StringComparison.Ordinal);
        Assert.Contains("LEGACY", c, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DebPackageScript_ShipsOptionalEbpfObject()
    {
        var root = FindRepoRoot();
        var sh = File.ReadAllText(Path.Combine(root, "packaging", "unix", "build-deb.sh"));
        Assert.Contains("behavedr_exec.bpf.o", sh, StringComparison.Ordinal);
        Assert.Contains("Recommends: bpftool", sh, StringComparison.Ordinal);
        Assert.Contains("/sys/fs/bpf/behavedr", sh, StringComparison.Ordinal);
    }

    [Fact]
    public void ManagedEsMonitor_HasJsonlFallback()
    {
        var root = FindRepoRoot();
        var src = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "MacOSEndpointSecurityMonitor.cs"));
        Assert.Contains("jsonl-host", src, StringComparison.Ordinal);
        Assert.Contains("es.events", src, StringComparison.Ordinal);
        Assert.Contains("TryStartJsonlFallback", src, StringComparison.Ordinal);
    }

    [Fact]
    public void LinuxSyscallNumbers_MatchKernelTables()
    {
        // Documented in docs/PLATFORM_ABI.md - fail if someone "simplifies" wrong
        Assert.Equal(1, Behavedr.Core.Platform.LinuxSyscallNumbers.BPF_MAP_LOOKUP_ELEM);
        Assert.Equal(7, Behavedr.Core.Platform.LinuxSyscallNumbers.BPF_OBJ_GET);
        if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
        {
            Assert.Equal(321, Behavedr.Core.Platform.LinuxSyscallNumbers.Bpf);
            Assert.Equal(434, Behavedr.Core.Platform.LinuxSyscallNumbers.PidfdOpen);
            Assert.Equal(424, Behavedr.Core.Platform.LinuxSyscallNumbers.PidfdSendSignal);
            Assert.Equal(444, Behavedr.Core.Platform.LinuxSyscallNumbers.LandlockCreateRuleset);
        }
        if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            Assert.Equal(280, Behavedr.Core.Platform.LinuxSyscallNumbers.Bpf);
            Assert.Equal(434, Behavedr.Core.Platform.LinuxSyscallNumbers.PidfdOpen);
            Assert.Equal(424, Behavedr.Core.Platform.LinuxSyscallNumbers.PidfdSendSignal);
        }
    }

    [Fact]
    public void AndroidSupplyChain_ZeroConfigSelfPin_NoUserSetup()
    {
        var root = FindRepoRoot();
        var src = File.ReadAllText(Path.Combine(root,
            "src", "Behavedr.Mobile", "Platforms", "Android", "PlatformInjection", "SupplyChainVerifier.cs"));
        Assert.DoesNotContain("PLACEHOLDER_RELEASE_KEY", src, StringComparison.Ordinal);
        Assert.Contains("Self-pinned", src, StringComparison.Ordinal);
        Assert.Contains("PersistSelfPin", src, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Contains(\"PLACEHOLDER_RELEASE_KEY_SHA256_FINGERPRINT_HERE\")",
            src, StringComparison.Ordinal);
        var pins = File.ReadAllText(Path.Combine(root,
            "src", "Behavedr.Mobile", "Platforms", "Android", "PlatformInjection", "AndroidCertPins.cs"));
        Assert.Contains("not</b> an end-user setting", pins, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IosSku_IsNotShipped()
    {
        var root = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(root, "docs", "IOS.md")));
        var iosDoc = File.ReadAllText(Path.Combine(root, "docs", "IOS.md"));
        Assert.Contains("not a Behavedr SKU", iosDoc, StringComparison.OrdinalIgnoreCase);

        Assert.False(File.Exists(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "IosMonitor.cs")));
        Assert.False(File.Exists(Path.Combine(root, "src", "Behavedr.Core", "Response", "IosResponseEngine.cs")));
        Assert.False(Directory.Exists(Path.Combine(root, "src", "Behavedr.Mobile", "Platforms", "iOS")));

        var monitors = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Core", "Platform", "PlatformMonitors.cs"));
        Assert.DoesNotContain("new IosMonitor", monitors, StringComparison.Ordinal);
        Assert.DoesNotContain("IosAppAttestMonitor", monitors, StringComparison.Ordinal);

        var agent = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Agent", "Program.cs"));
        Assert.DoesNotContain("IosResponseEngine", agent, StringComparison.Ordinal);

        var buildYml = File.ReadAllText(Path.Combine(root, ".github", "workflows", "build.yml"));
        Assert.DoesNotContain("maui-ios", buildYml, StringComparison.Ordinal);
        Assert.DoesNotContain("net10.0-ios", buildYml, StringComparison.Ordinal);
    }

    [Fact]
    public void LoaderSource_UsesBpfSyscallsNotMapDumpOnly()
    {
        var root = FindRepoRoot();
        var src = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "LinuxEbpfLoader.cs"));
        Assert.Contains("BPF_OBJ_GET", src, StringComparison.Ordinal);
        Assert.Contains("BPF_MAP_LOOKUP_ELEM", src, StringComparison.Ordinal);
        Assert.Contains("pinmaps", src, StringComparison.Ordinal);
        Assert.DoesNotContain("map dump name", src, StringComparison.OrdinalIgnoreCase);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Behavedr.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
    }
}
