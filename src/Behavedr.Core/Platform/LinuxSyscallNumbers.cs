namespace Behavedr.Core.Platform;

using System.Runtime.InteropServices;

/// <summary>
/// Linux syscall numbers from the upstream kernel tables - <b>not guessed</b>.
/// Sources (torvalds/linux):
/// - x86_64: arch/x86/entry/syscalls/syscall_64.tbl
/// - arm64 / generic: include/uapi/asm-generic/unistd.h
/// Verified 2026-07-25 against master.
/// </summary>
public static class LinuxSyscallNumbers
{
    // --- bpf(2) command enum (uapi/linux/bpf.h) - architecture independent ---
    public const int BPF_MAP_LOOKUP_ELEM = 1;
    public const int BPF_OBJ_GET = 7;

    /// <summary>
    /// __NR_bpf: x86_64 = 321 (syscall_64.tbl), arm64/generic = 280 (unistd.h).
    /// </summary>
    public static long Bpf =>
        RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => 280,
            Architecture.X64 => 321,
            // Other arches: refuse silent wrong numbers - callers should soft-fail
            _ => -1,
        };

    /// <summary>
    /// __NR_pidfd_open: 434 on both x86_64 and arm64/generic (synced high numbers).
    /// </summary>
    public static long PidfdOpen =>
        RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64
            ? 434
            : -1;

    /// <summary>
    /// __NR_pidfd_send_signal: 424 on both x86_64 and arm64/generic.
    /// </summary>
    public static long PidfdSendSignal =>
        RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64
            ? 424
            : -1;

    /// <summary>__NR_landlock_create_ruleset: 444 (x86_64 + generic).</summary>
    public static long LandlockCreateRuleset =>
        RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64
            ? 444
            : -1;

    /// <summary>__NR_landlock_add_rule: 445.</summary>
    public static long LandlockAddRule =>
        RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64
            ? 445
            : -1;

    /// <summary>__NR_landlock_restrict_self: 446.</summary>
    public static long LandlockRestrictSelf =>
        RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64
            ? 446
            : -1;

    public static bool SupportsBpfSyscall => Bpf > 0;
    public static bool SupportsPidfd => PidfdOpen > 0 && PidfdSendSignal > 0;
    public static bool SupportsLandlock => LandlockCreateRuleset > 0;
}
