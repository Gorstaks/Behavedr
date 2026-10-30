# Platform ABI constants - sources of truth

**Policy:** do not invent ETW flags, Linux syscall numbers, or ES event IDs.
Cite kernel headers / Microsoft docs. Last verified: **2026-07-25**.

## Linux syscalls

Central code: `src/Behavedr.Core/Platform/LinuxSyscallNumbers.cs`

| Symbol | x86_64 | arm64 / generic | Source |
|--------|--------|-----------------|--------|
| `bpf` | **321** | **280** | `arch/x86/entry/syscalls/syscall_64.tbl`; `include/uapi/asm-generic/unistd.h` |
| `pidfd_send_signal` | **424** | **424** | same tables |
| `pidfd_open` | **434** | **434** | same tables |
| `landlock_create_ruleset` | **444** | **444** | same tables |
| `landlock_add_rule` | **445** | **445** | same tables |
| `landlock_restrict_self` | **446** | **446** | same tables |

bpf commands (`uapi/linux/bpf.h`): `BPF_MAP_LOOKUP_ELEM = 1`, `BPF_OBJ_GET = 7`.

Unsupported architectures return `-1` (soft-fail) - **no silent wrong number**.

## Windows ETW

| Constant | Value | Source |
|----------|-------|--------|
| `EVENT_TRACE_REAL_TIME_MODE` | `0x00000100` | [Logging Mode Constants](https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants) |
| `EVENT_TRACE_FLAG_PROCESS` | `0x00000001` | [EVENT_TRACE_PROPERTIES / EnableFlags](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties) |
| Kernel-Process **ProcessStart** | Event ID **1** | Provider manifest `Microsoft-Windows-Kernel-Process` |

## macOS EndpointSecurity

Prefer **framework enums** in C (`behavedr_es_subscribe_default`) over hardcoded
managed integers. Apple enum order (10.15+): `AUTH_EXEC=0`, ..., `NOTIFY_EXEC=9`,
`NOTIFY_OPEN=10`, `NOTIFY_FORK=11`, ... (see SDK `ESTypes.h`).

## fanotify (uapi/linux/fanotify.h)

| Constant | Value | Verified |
|----------|-------|----------|
| `FAN_CLASS_NOTIF` | `0x00000000` | yes |
| `FAN_CLASS_CONTENT` | `0x00000004` | yes |
| `FAN_NONBLOCK` | `0x00000002` | yes |
| `FAN_OPEN_EXEC` | `0x00001000` | yes |
| `FAN_OPEN_EXEC_PERM` | `0x00040000` | yes |
| `FAN_MARK_ADD` | `0x00000001` | yes |
| `FAN_MARK_MOUNT` | `0x00000010` | yes |
| `FAN_ALLOW` / `FAN_DENY` | `0x01` / `0x02` | yes |

## cn_proc (uapi/linux/cn_proc.h)

| Constant | Value | Verified |
|----------|-------|----------|
| `PROC_EVENT_FORK` | `0x00000001` | yes |
| `PROC_EVENT_EXEC` | `0x00000002` | yes |
| `PROC_EVENT_EXIT` | `0x80000000` | yes |

## fcntl open flags (Linux, common)

| Constant | Value | Note |
|----------|-------|------|
| `O_CLOEXEC` | `0x80000` (02000000 octal) | glibc/bits/fcntl-linux.h |
| `O_PATH` | `0x200000` (010000000 octal) | same |

## How to re-verify

```bash
# Syscalls
curl -sL https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl | grep -E 'bpf|pidfd|landlock'
curl -sL https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h | grep -E 'NR_bpf|NR_pidfd|NR_landlock'

# fanotify / cn_proc
curl -sL https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/fanotify.h | head -80
curl -sL https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/cn_proc.h | grep PROC_EVENT
```
