# Behavedr Linux eBPF (production suite, 0.3.3)

## Object

Primary object name expected by the agent: **`behavedr_exec.bpf.o`**  
(built from `behavedr_suite.bpf.c`)

| Program | Tracepoint | Event kind | `path` field |
|---------|------------|------------|--------------|
| `handle_exec` | `sched/sched_process_exec` | 1 | executable filename (kernel) |
| `handle_openat` | `syscalls/sys_enter_openat` | 2 | user pathname |
| `handle_connect` | `syscalls/sys_enter_connect` | 3 | `a.b.c.d:port` or compact IPv6 |

Event record is **144 bytes** (`kind/pid/tgid/pad` + `comm[16]` + `path[112]`), matching
`LinuxEbpfLoader.EventSize`.

Maps (pinned under `/sys/fs/bpf/behavedr`):

- `events` - array[256] of event records  
- `cursor` - free-running write index  

## Build

```bash
# Root of repo
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common \
  linux-headers-$(uname -r)  # example
bpftool btf dump file /sys/kernel/btf/vmlinux format c > native/linux/ebpf/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I native/linux/ebpf \
  -c native/linux/ebpf/behavedr_suite.bpf.c \
  -o native/linux/ebpf/behavedr_exec.bpf.o
sudo mkdir -p /opt/behavedr
sudo cp native/linux/ebpf/behavedr_exec.bpf.o /opt/behavedr/
```

Or: `./native/build-native.sh dist/native`

## Runtime

`LinuxEbpfSuite` (shared) + `LinuxEbpfLoader` + monitors:

1. Finds `behavedr_exec.bpf.o` beside agent or `/opt/behavedr/`
2. `bpftool prog loadall ... autoattach pinmaps /sys/fs/bpf/behavedr` (with fallbacks)
3. Opens maps via **`bpf(BPF_OBJ_GET)`**
4. Polls **`BPF_MAP_LOOKUP_ELEM`** for new slots since cursor
5. Routes kinds to:
   - `LinuxEbpfExecMonitor` (exec)
   - `LinuxEbpfFileMonitor` (openat; /proc fd sample if suite inactive)
   - `LinuxEbpfNetMonitor` (connect; /proc/net if suite inactive)

Without object or CAP_BPF: soft-fail -> **cn_proc / fanotify /proc** remain primary.

## Capabilities

```
CapabilityBoundingSet=... CAP_BPF CAP_PERFMON CAP_SYS_ADMIN ...
```

See `packaging/unix/behavedr.service`.
