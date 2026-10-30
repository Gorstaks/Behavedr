namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Production eBPF object lifecycle for Behavedr (0.3.3).
/// Loads CO-RE objects via bpftool, opens pinned maps with <c>bpf(BPF_OBJ_GET)</c>,
/// and reads the <c>events</c> array map with <c>BPF_MAP_LOOKUP_ELEM</c>.
/// Layout of events must match native/linux/ebpf/behavedr_suite.bpf.c (144 bytes).
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfLoader : IDisposable
{
    public const string DefaultPinDir = "/sys/fs/bpf/behavedr";
    public const string DefaultObjectName = "behavedr_exec.bpf.o";
    public const int MaxSlots = 256;
    public const int EventSize = 144; // 4*u32 + comm[16] + path[112]

    private readonly ILogger _logger;
    private int _eventsMapFd = -1;
    private int _cursorMapFd = -1;
    private uint _lastSeenCursor;
    private bool _cursorSeeded;
    private bool _loaded;

    public bool IsLoaded => _loaded;
    public string? LoadedObjectPath { get; private set; }
    public string PinDir { get; }

    public LinuxEbpfLoader(ILogger? logger = null, string? pinDir = null)
    {
        _logger = logger ?? NullLogger.Instance;
        PinDir = pinDir ?? DefaultPinDir;
    }

    public string? FindObject()
    {
        foreach (var dir in CandidateDirs())
        {
            foreach (var name in new[] { DefaultObjectName, "behavedr_suite.bpf.o" })
            {
                var p = Path.Combine(dir, name);
                if (File.Exists(p))
                    return Path.GetFullPath(p);
            }
        }
        return null;
    }

    /// <summary>
    /// Load object, pin under PinDir, open map FDs. Returns false on any hard failure.
    /// </summary>
    public bool TryLoad(string? objectPath = null)
    {
        if (_loaded)
            return true;

        objectPath ??= FindObject();
        if (objectPath is null)
        {
            _logger.LogWarning("[eBPF] No object file found (expected {Name} under agent dir or /opt/behavedr)", DefaultObjectName);
            return false;
        }

        if (!HasBpftool())
        {
            _logger.LogWarning("[eBPF] bpftool not found - cannot load object {Path}", objectPath);
            return false;
        }

        try
        {
            Directory.CreateDirectory(PinDir);
            ClearPinDir();

            // Prefer autoattach + pinmaps (libbpf / modern bpftool). Fall back stepwise.
            var rc = RunBpftool($"prog loadall \"{objectPath}\" {PinDir} autoattach pinmaps {PinDir}");
            if (rc != 0)
                rc = RunBpftool($"prog loadall \"{objectPath}\" {PinDir} pinmaps {PinDir}");
            if (rc != 0)
                rc = RunBpftool($"prog loadall \"{objectPath}\" {PinDir} type tracing pinmaps {PinDir}");
            if (rc != 0)
                rc = RunBpftool($"prog loadall \"{objectPath}\" {PinDir}");
            if (rc != 0)
            {
                _logger.LogError("[eBPF] bpftool prog loadall failed rc={Rc} for {Obj}", rc, objectPath);
                return false;
            }

            // Explicit attach when autoattach did not bind
            int attached = AttachPinnedPrograms();

            if (!OpenPinnedMaps())
                return false;

            if (_cursorMapFd < 0)
            {
                _logger.LogError("[eBPF] cursor map required but not pinned - refusing active mode");
                Dispose();
                return false;
            }

            if (attached == 0)
            {
                // autoattach may have bound programs without our explicit attach counting
                _logger.LogWarning(
                    "[eBPF] No explicit prog attach confirmed; relying on autoattach if loadall used it. " +
                    "If no events arrive, check bpftool prog show / pin dir.");
            }

            // Seed cursor so we only observe NEW events after attach (no stale scan flood)
            if (_cursorMapFd >= 0 && MapLookupU32(_cursorMapFd, 0, out var cur))
            {
                _lastSeenCursor = cur;
                _cursorSeeded = true;
            }

            _loaded = true;
            LoadedObjectPath = objectPath;
            _logger.LogInformation(
                "[eBPF] Loaded {Obj}; events_fd={Efd} cursor_fd={Cfd} pin={Pin} cursor={Cur}",
                objectPath, _eventsMapFd, _cursorMapFd, PinDir, _lastSeenCursor);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[eBPF] Load failed");
            Dispose();
            return false;
        }
    }

    /// <summary>
    /// Read new events since last poll by walking array slots from previous cursor.
    /// </summary>
    public IReadOnlyList<EbpfMapEvent> DrainNewEvents()
    {
        var list = new List<EbpfMapEvent>();
        if (!_loaded || _eventsMapFd < 0)
            return list;

        uint cursor = _lastSeenCursor;
        if (_cursorMapFd >= 0)
        {
            if (!MapLookupU32(_cursorMapFd, 0, out cursor))
                cursor = _lastSeenCursor;
        }

        if (!_cursorSeeded)
        {
            _lastSeenCursor = cursor;
            _cursorSeeded = true;
            return list;
        }

        uint start = _lastSeenCursor;
        uint end = cursor;
        if (end == start)
            return list;

        // Free-running cursor (uint wrap OK). Under pressure we may skip events.
        uint count = end - start;
        if (count > MaxSlots)
        {
            start = end - MaxSlots;
            count = MaxSlots;
        }

        for (uint i = 0; i < count; i++)
        {
            uint slot = (start + i) % MaxSlots;
            if (TryReadSlot(slot, out var ev) && ev.Pid != 0)
                list.Add(ev);
        }

        _lastSeenCursor = end;
        return list;
    }

    public void Dispose()
    {
        if (_eventsMapFd >= 0) { close(_eventsMapFd); _eventsMapFd = -1; }
        if (_cursorMapFd >= 0) { close(_cursorMapFd); _cursorMapFd = -1; }
        _loaded = false;
    }

    private bool OpenPinnedMaps()
    {
        var eventsPin = FindPinnedName(PinDir, "events") ?? Path.Combine(PinDir, "events");
        var cursorPin = FindPinnedName(PinDir, "cursor") ?? Path.Combine(PinDir, "cursor");

        _eventsMapFd = BpfObjGet(eventsPin);
        if (_eventsMapFd < 0)
            _eventsMapFd = BpfObjGet(Path.Combine(PinDir, "maps", "events"));
        if (_eventsMapFd < 0)
        {
            _logger.LogError("[eBPF] Cannot open pinned events map (errno {E}). Pins under {Pin}: {List}",
                Marshal.GetLastPInvokeError(), PinDir, ListPins(PinDir));
            return false;
        }

        _cursorMapFd = BpfObjGet(cursorPin);
        if (_cursorMapFd < 0)
            _cursorMapFd = BpfObjGet(Path.Combine(PinDir, "maps", "cursor"));
        // Missing cursor is a hard failure for DrainNewEvents - checked by caller.

        return true;
    }

    /// <summary>Returns number of successful explicit attaches.</summary>
    private int AttachPinnedPrograms()
    {
        if (!Directory.Exists(PinDir))
            return 0;

        var targets = new Dictionary<string, (string cat, string name)>(StringComparer.OrdinalIgnoreCase)
        {
            ["handle_exec"] = ("sched", "sched_process_exec"),
            ["handle_openat"] = ("syscalls", "sys_enter_openat"),
            ["handle_connect"] = ("syscalls", "sys_enter_connect"),
            ["tp_sched_sched_process_exec"] = ("sched", "sched_process_exec"),
            ["tp_syscalls_sys_enter_openat"] = ("syscalls", "sys_enter_openat"),
            ["tp_syscalls_sys_enter_connect"] = ("syscalls", "sys_enter_connect"),
        };

        int attached = 0;
        foreach (var entry in EnumeratePinFiles(PinDir))
        {
            var baseName = Path.GetFileName(entry);
            if (baseName is "events" or "cursor" or "maps")
                continue;
            if (!targets.TryGetValue(baseName, out var tp))
            {
                if (baseName.Contains("openat", StringComparison.OrdinalIgnoreCase))
                    tp = ("syscalls", "sys_enter_openat");
                else if (baseName.Contains("connect", StringComparison.OrdinalIgnoreCase))
                    tp = ("syscalls", "sys_enter_connect");
                else if (baseName.Contains("exec", StringComparison.OrdinalIgnoreCase) &&
                         !baseName.Contains("open", StringComparison.OrdinalIgnoreCase))
                    tp = ("sched", "sched_process_exec");
                else
                    continue;
            }

            var rc = RunBpftool($"prog attach pinned \"{entry}\" tracepoint {tp.cat} {tp.name}");
            if (rc == 0)
            {
                attached++;
                _logger.LogInformation("[eBPF] Attached {Prog} -> {Cat}/{Name}", baseName, tp.cat, tp.name);
            }
        }
        return attached;
    }

    private void ClearPinDir()
    {
        try
        {
            if (!Directory.Exists(PinDir))
                return;
            foreach (var f in Directory.EnumerateFileSystemEntries(PinDir))
            {
                try
                {
                    if (Directory.Exists(f))
                        Directory.Delete(f, recursive: true);
                    else
                        File.Delete(f);
                }
                catch
                {
                    // busy pin - continue; loadall may still work
                }
            }
        }
        catch
        {
            // empty / missing is fine
        }
    }

    private bool TryReadSlot(uint slot, out EbpfMapEvent ev)
    {
        ev = default;
        var keyBytes = BitConverter.GetBytes(slot);
        var val = new byte[EventSize];
        var keyPin = GCHandle.Alloc(keyBytes, GCHandleType.Pinned);
        var valPin = GCHandle.Alloc(val, GCHandleType.Pinned);
        try
        {
            var attr = new BpfAttrMapElem
            {
                map_fd = (uint)_eventsMapFd,
                key = (ulong)keyPin.AddrOfPinnedObject(),
                value = (ulong)valPin.AddrOfPinnedObject(),
                flags = 0,
            };
            if (Bpf(Platform.LinuxSyscallNumbers.BPF_MAP_LOOKUP_ELEM, ref attr) != 0)
                return false;

            // Layout: kind@0 pid@4 tgid@8 pad@12 comm@16 path@32
            var kind = BitConverter.ToUInt32(val, 0);
            var pid = BitConverter.ToUInt32(val, 4);
            var tgid = BitConverter.ToUInt32(val, 8);
            var comm = Encoding.ASCII.GetString(val, 16, 16).TrimEnd('\0');
            var path = Encoding.UTF8.GetString(val, 32, 112).TrimEnd('\0');
            ev = new EbpfMapEvent((int)kind, (int)pid, (int)tgid, comm, path, (int)slot);
            return true;
        }
        finally
        {
            keyPin.Free();
            valPin.Free();
        }
    }

    private static bool MapLookupU32(int mapFd, uint key, out uint value)
    {
        value = 0;
        var keyBytes = BitConverter.GetBytes(key);
        var valBytes = new byte[4];
        var keyPin = GCHandle.Alloc(keyBytes, GCHandleType.Pinned);
        var valPin = GCHandle.Alloc(valBytes, GCHandleType.Pinned);
        try
        {
            var attr = new BpfAttrMapElem
            {
                map_fd = (uint)mapFd,
                key = (ulong)keyPin.AddrOfPinnedObject(),
                value = (ulong)valPin.AddrOfPinnedObject(),
            };
            if (Bpf(Platform.LinuxSyscallNumbers.BPF_MAP_LOOKUP_ELEM, ref attr) != 0)
                return false;
            value = BitConverter.ToUInt32(valBytes, 0);
            return true;
        }
        finally
        {
            keyPin.Free();
            valPin.Free();
        }
    }

    private static IEnumerable<string> CandidateDirs()
    {
        yield return AppContext.BaseDirectory;
        yield return Path.Combine(AppContext.BaseDirectory, "ebpf");
        yield return "/opt/behavedr";
        yield return "/opt/behavedr/ebpf";
        yield return Directory.GetCurrentDirectory();
        yield return Path.Combine(Directory.GetCurrentDirectory(), "native", "linux", "ebpf");
    }

    private static string? FindPinnedName(string root, string name)
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if (string.Equals(Path.GetFileName(f), name, StringComparison.Ordinal))
                    return f;
            }
        }
        catch { /* ignore */ }
        return null;
    }

    private static IEnumerable<string> EnumeratePinFiles(string root)
    {
        if (!Directory.Exists(root))
            yield break;
        IEnumerable<string> entries;
        try { entries = Directory.EnumerateFileSystemEntries(root); }
        catch { yield break; }

        foreach (var e in entries)
        {
            if (Directory.Exists(e))
            {
                // nested maps/progs dirs
                IEnumerable<string> nested;
                try { nested = Directory.EnumerateFiles(e); }
                catch { continue; }
                foreach (var n in nested)
                    yield return n;
            }
            else
            {
                yield return e;
            }
        }
    }

    private static string ListPins(string root)
    {
        try
        {
            if (!Directory.Exists(root)) return "(missing)";
            return string.Join(", ", Directory.EnumerateFileSystemEntries(root).Select(Path.GetFileName).Take(20));
        }
        catch { return "(error)"; }
    }

    private static bool HasBpftool() =>
        File.Exists("/usr/sbin/bpftool") ||
        File.Exists("/usr/bin/bpftool") ||
        Run("which", "bpftool") == 0;

    private static int RunBpftool(string args)
    {
        if (File.Exists("/usr/sbin/bpftool"))
            return Run("/usr/sbin/bpftool", args);
        if (File.Exists("/usr/bin/bpftool"))
            return Run("/usr/bin/bpftool", args);
        return Run("bpftool", args);
    }

    private static int Run(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = file,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            });
            if (p is null) return -1;
            if (!p.WaitForExit(45000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return -1;
            }
            return p.ExitCode;
        }
        catch
        {
            // Fallback through shell when PATH resolution needed
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "/bin/sh",
                    Arguments = $"-c \"{Escape(file)} {args}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                });
                if (p is null) return -1;
                if (!p.WaitForExit(45000))
                {
                    try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                    return -1;
                }
                return p.ExitCode;
            }
            catch { return -1; }
        }
    }

    private static string Escape(string s) => s.Replace("\"", "\\\"");

    // --- bpf() syscalls: numbers from LinuxSyscallNumbers (kernel tables, not guessed) ---

    private static int SysBpfNumber
    {
        get
        {
            var n = Platform.LinuxSyscallNumbers.Bpf;
            return n > 0 ? (int)n : -1;
        }
    }

    private static int BpfObjGet(string path)
    {
        if (string.IsNullOrEmpty(path))
            return -1;
        if (SysBpfNumber < 0)
            return -1;
        // pinned BPF objects are special files; File.Exists is true for map pins
        var pathBytes = Encoding.UTF8.GetBytes(path + "\0");
        var pin = GCHandle.Alloc(pathBytes, GCHandleType.Pinned);
        try
        {
            var attr = new BpfAttrObj
            {
                pathname = (ulong)pin.AddrOfPinnedObject(),
                bpf_fd = 0,
                file_flags = 0,
            };
            var fd = (int)syscall(SysBpfNumber, Platform.LinuxSyscallNumbers.BPF_OBJ_GET, ref attr, (ulong)Marshal.SizeOf<BpfAttrObj>());
            return fd;
        }
        finally { pin.Free(); }
    }

    private static int Bpf(int cmd, ref BpfAttrMapElem attr)
    {
        if (SysBpfNumber < 0)
            return -1;
        return (int)syscall_map(SysBpfNumber, cmd, ref attr, (ulong)Marshal.SizeOf<BpfAttrMapElem>());
    }

    /// <summary>
    /// bpf_attr for MAP_*_ELEM: map_fd (u32) + pad + key/value/flags as aligned u64.
    /// Matches linux/bpf.h union bpf_attr layout for map commands.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct BpfAttrMapElem
    {
        public uint map_fd;
        public uint pad;
        public ulong key;
        public ulong value;
        public ulong flags;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct BpfAttrObj
    {
        public ulong pathname;
        public uint bpf_fd;
        public uint file_flags;
    }

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall(long n, int cmd, ref BpfAttrObj attr, ulong size);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall_map(long n, int cmd, ref BpfAttrMapElem attr, ulong size);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    public readonly record struct EbpfMapEvent(int Kind, int Pid, int Tgid, string Comm, string Path, int Slot);
}
