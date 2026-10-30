namespace Behavedr.Core.Security;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Optional Linux Landlock sandbox for the agent process (0.2.9).
/// When enabled, restricts the agent to read-only access outside its data dirs
/// after monitors that need broad visibility have started - or apply at install
/// time via packaging for a helper split.
///
/// Enable: env <c>BEHAVEDR_LANDLOCK=1</c> or call <see cref="TryApplyDefaultProfile"/>.
/// Requires kernel 5.13+ with Landlock; fails soft on older kernels.
/// </summary>
[SupportedOSPlatform("linux")]
public static class LinuxLandlock
{
    public static bool IsSupported => OperatingSystem.IsLinux();

    /// <summary>
    /// Apply a conservative profile: FS read everywhere, write only under agent roots.
    /// </summary>
    public static bool TryApplyDefaultProfile(ILogger? logger = null, params string[] writeRoots)
    {
        logger ??= NullLogger.Instance;
        if (!OperatingSystem.IsLinux())
            return false;

        try
        {
            // Only restrict *writes* so EDR can still read /proc, configs, binaries system-wide.
            var attr = new LandlockRulesetAttr { handled_access_fs = AccessFsWrite };
            int ruleset = SyscallLandlockCreate(ref attr);
            if (ruleset < 0)
            {
                logger.LogDebug("[Landlock] create_ruleset unavailable (errno {E})", Marshal.GetLastPInvokeError());
                return false;
            }

            var roots = new List<string>(writeRoots);
            if (roots.Count == 0)
            {
                roots.AddRange(new[]
                {
                    AppContext.BaseDirectory,
                    Path.Combine(AppContext.BaseDirectory, "logs"),
                    Path.Combine(AppContext.BaseDirectory, "quarantine"),
                    Path.Combine(AppContext.BaseDirectory, "buffer"),
                    "/var/lib/behavedr",
                    "/opt/behavedr",
                    Path.GetTempPath(),
                });
            }

            int allowed = 0;
            foreach (var root in roots.Distinct(StringComparer.Ordinal))
            {
                try
                {
                    Directory.CreateDirectory(root);
                    int fd = open(root, O_PATH | O_CLOEXEC);
                    if (fd < 0) continue;
                    try
                    {
                        var pathAttr = new LandlockPathBeneathAttr
                        {
                            allowed_access = AccessFsWrite,
                            parent_fd = fd,
                        };
                        if (SyscallLandlockAddRule(ruleset, ref pathAttr) == 0)
                            allowed++;
                    }
                    finally { close(fd); }
                }
                catch { /* skip root */ }
            }

            if (allowed == 0)
            {
                close(ruleset);
                logger.LogWarning("[Landlock] No writable roots could be allowed - skipping enforce");
                return false;
            }

            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            int rc = SyscallLandlockRestrictSelf(ruleset);
            close(ruleset);
            if (rc != 0)
            {
                logger.LogWarning("[Landlock] restrict_self failed errno {E}", Marshal.GetLastPInvokeError());
                return false;
            }

            logger.LogInformation("[Landlock] Write-restrict profile applied ({Count} roots)", allowed);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "[Landlock] not applied");
            return false;
        }
    }

    // Write-oriented FS rights only (agent retains unrestricted read of the host).
    private const ulong AccessFsWriteFile = 1UL << 1;
    private const ulong AccessFsRemoveDir = 1UL << 4;
    private const ulong AccessFsRemoveFile = 1UL << 5;
    private const ulong AccessFsMakeChar = 1UL << 6;
    private const ulong AccessFsMakeDir = 1UL << 7;
    private const ulong AccessFsMakeReg = 1UL << 8;
    private const ulong AccessFsMakeSock = 1UL << 9;
    private const ulong AccessFsMakeFifo = 1UL << 10;
    private const ulong AccessFsMakeBlock = 1UL << 11;
    private const ulong AccessFsMakeSym = 1UL << 12;
    private const ulong AccessFsRefer = 1UL << 13;
    private const ulong AccessFsTruncate = 1UL << 14;

    private const ulong AccessFsWrite = AccessFsWriteFile | AccessFsRemoveDir | AccessFsRemoveFile
        | AccessFsMakeChar | AccessFsMakeDir | AccessFsMakeReg | AccessFsMakeSock
        | AccessFsMakeFifo | AccessFsMakeBlock | AccessFsMakeSym | AccessFsRefer | AccessFsTruncate;

    private const int LandlockRuleTypePathBeneath = 1;
    // fcntl.h: O_PATH=010000000, O_CLOEXEC=02000000 (octal) on Linux
    private const int O_PATH = 0x200000;
    private const int O_CLOEXEC = 0x80000;
    private const int PR_SET_NO_NEW_PRIVS = 38;
    // Syscall NRs: Platform.LinuxSyscallNumbers (kernel tables; 444/445/446 on x86_64 + arm64)

    [StructLayout(LayoutKind.Sequential)]
    private struct LandlockRulesetAttr
    {
        public ulong handled_access_fs;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LandlockPathBeneathAttr
    {
        public ulong allowed_access;
        public int parent_fd;
    }

    private static int SyscallLandlockCreate(ref LandlockRulesetAttr attr)
    {
        var nr = Platform.LinuxSyscallNumbers.LandlockCreateRuleset;
        if (nr < 0) return -1;
        return (int)syscall3(nr, ref attr, (ulong)Marshal.SizeOf<LandlockRulesetAttr>(), 0);
    }

    private static int SyscallLandlockAddRule(int ruleset, ref LandlockPathBeneathAttr pathAttr)
    {
        var nr = Platform.LinuxSyscallNumbers.LandlockAddRule;
        if (nr < 0) return -1;
        return (int)syscall4(nr, ruleset, LandlockRuleTypePathBeneath, ref pathAttr, 0);
    }

    private static int SyscallLandlockRestrictSelf(int ruleset)
    {
        var nr = Platform.LinuxSyscallNumbers.LandlockRestrictSelf;
        if (nr < 0) return -1;
        return (int)syscall2(nr, ruleset, 0);
    }

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall3(long n, ref LandlockRulesetAttr a, ulong size, ulong flags);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall4(long n, int ruleset, int ruleType, ref LandlockPathBeneathAttr attr, ulong flags);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern long syscall2(long n, int ruleset, ulong flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int prctl(int option, ulong arg2, ulong arg3, ulong arg4, ulong arg5);

    [DllImport("libc", SetLastError = true)]
    private static extern int open(string pathname, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);
}
