# Behavedr - Threat Model

Version: 0.4.3
Last updated: 2026-08-24
Classification: Public

---

## 1. System Overview

Behavedr is a userland behavioral endpoint detection and response (EDR) agent. It runs as a Windows Service (SYSTEM context), standalone daemon on Linux/macOS, or MAUI foreground service on Android. iOS is not a SKU. It collects telemetry from ETW providers, WMI, /proc, kqueue, and platform APIs, scores behavioral signals against correlation rules, and executes response actions (process termination, file quarantine, network isolation) when thresholds are exceeded.

### Components

| Component | Privilege | Function |
|-----------|-----------|----------|
| Behavedr.exe (Service) | SYSTEM | Detection engine, ETW session, response actions, self-protection |
| appsettings.json | SYSTEM-read | Configuration (thresholds, server URL, intervals) |
| Machine key (.behavedr-key) | SYSTEM-read | DPAPI-protected AES-256 key for local encryption |
| Offline buffer (buffer/) | SYSTEM-read/write | AES-256-GCM encrypted detection reports |
| Quarantine (quarantine/) | SYSTEM-read/write | Isolated malicious files with metadata |
| Communication channel | Outbound HTTPS | mTLS to management server (when configured) |

### Trust Boundaries

```

 Machine (Local)                                  
    
   SYSTEM Context                               
          
     Behavedr Agent      Machine Key        
     (Detection +        (DPAPI-wrapped)    
      Response)             
                           
              ETW / WMI / NtQuery*            
    
                                                 
    
   User Processes (monitored)                   
    

                        mTLS (HTTPS)

 Management Server (remote, optional)             
  - Receives detection reports                    
  - Issues signed policy updates                  
  - Pushes signed auto-updates                    

```

---

## 2. Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| Remote attacker (pre-compromise) | Network access, exploit delivery | Initial access, lateral movement |
| Local unprivileged attacker | Standard user execution | Privilege escalation, EDR evasion |
| Local privileged attacker (admin) | Admin rights, can install drivers | Disable/blind the agent, persist undetected |
| Kernel-level attacker | Loaded driver or rootkit | Complete invisibility, data exfiltration |
| Supply chain attacker | Compromise build pipeline or dependencies | Trojanize the agent binary |
| Insider (management server operator) | Server access, can push policies | Push malicious policy, exfiltrate telemetry |

---

## 3. Attack Surface

### 3.1 Local Attack Surface

| Surface | Entry Point | Mitigations |
|---------|-------------|-------------|
| Configuration file | appsettings.json on disk | HMAC integrity seal; pre-seal validation rejects out-of-bounds values; SYSTEM-only write ACL |
| Machine key file | .behavedr-key in ProgramData | DPAPI LocalMachine + per-install entropy; restricted ACL (SYSTEM + Admins only) |
| Service binary | Behavedr.exe on disk | Binary integrity SHA-256 check every 10s; Inno Setup sets restricted directory ACL |
| Service registration | HKLM\Services\Behavedr | Self-healing: AntiTamperGuard re-registers if key deleted |
| Process handle | Behavedr.exe process | DACL denies PROCESS_TERMINATE to Everyone; anti-debug FailFast |
| ETW session | BehavedrEtwSession | Liveness monitoring via QueryTraceW; tamper signal on session kill |
| Offline buffer | buffer/*.enc files | AES-256-GCM authenticated encryption; tampered files moved to dead-letter |
| Quarantine directory | quarantine/ | SYSTEM-only ACL; path traversal validation on all file operations |

### 3.2 Network Attack Surface

| Surface | Entry Point | Mitigations |
|---------|-------------|-------------|
| Outbound HTTPS | Agent -> Server | mTLS with client certificate; server cert pinned to CA; fail-closed (rejects all connections without CA cert) |
| Policy updates | Server -> Agent | RSA-4096 PSS signature verification; reject unsigned policies |
| Auto-updates | GitHub Releases -> Agent | RSA-4096 PSS signature on .zip; Zip Slip protection; minimum size validation |
| DNS (telemetry) | Agent reads DNS events | Read-only via ETW; no DNS requests initiated by agent |

### 3.3 Build/Supply Chain Surface

| Surface | Entry Point | Mitigations |
|---------|-------------|-------------|
| NuGet dependencies | Package restore | Lock files (packages.lock.json); deterministic builds; pinned versions |
| GitHub Actions | CI/CD pipeline | Pinned action SHAs; minimal permissions; SBOM generation |
| Inno Setup compiler | Installer build | Local discovery (no runtime download in production); ISCC from known paths only |
| Auto-update download | HTTPS from GitHub | RSA-PSS signature required; rejects unsigned packages |

---

## 4. Assumptions

1. The Windows kernel is not compromised. Behavedr operates in userland and cannot detect or resist kernel rootkits.
2. The .NET runtime is not compromised. A trojanized runtime could subvert all managed code.
3. The DPAPI master key (LSA secret) has not been extracted from the machine. If it has, the machine key can be unwrapped.
4. The management server (when configured) is operated by a trusted party. A compromised server could push malicious policies (mitigated by signature verification).
5. The RSA-4096 private signing key is not compromised. If it is, an attacker can sign malicious updates.

---

## 5. Threat Scenarios and Mitigations

### T-1: Attacker disables the agent

| Technique | MITRE | Mitigation |
|-----------|-------|------------|
| Kill the process | T1562.001 | Process DACL denies TERMINATE; SCM auto-restart (5s/10s/30s) |
| Suspend the process | T1562.001 | QPC timing detection (4s threshold); generates tamper signal |
| Stop the service via SCM | T1562.001 | Requires SYSTEM or admin + SeDebugPrivilege to bypass DACL |
| Delete service registry key | T1562.001 | AntiTamperGuard detects and re-registers within 10s |
| Kill ETW session | T1562.006 | QueryTraceW liveness check every 10s; generates high-confidence tamper signal |
| Patch ntdll!EtwEventWrite | T1562.001 | Function prologue integrity check every 10s (baseline comparison) |
| Patch amsi!AmsiScanBuffer | T1562.001 | Function prologue integrity check every 10s |
| Attach debugger | T1622 | Debugger.IsAttached check every 30s; FailFast in Release builds |
| Replace binary on disk | T1036 | SHA-256 binary integrity verification every 10s |
| Boot into Safe Mode | T1562.009 | Safe Mode registry persistence (v0.1.4); service starts in both Minimal and Network modes |
| Tamper config to weaken thresholds | T1562.001 | HMAC integrity seal; pre-seal validation rejects dangerous values; refuses to start on tamper |

### T-2: Attacker evades detection

| Technique | MITRE | Mitigation |
|-----------|-------|------------|
| Process name spoofing | T1036.005 | Path-verified system process list; WinVerifyTrust Authenticode check |
| Parent PID spoofing | T1134.004 | ProcessAncestryCache + NtQueryInformationProcess verification |
| DLL sideloading | T1574.002 | Generic heuristic: unsigned DLL from process dir when System32 copy exists |
| Living off the land (LOLBins) | T1218 | 8 LOLBin regex patterns; parent-child anomaly rules |
| Encoded PowerShell | T1059.001 | EncodedCommand detection; AMSI bypass pattern matching |
| Fileless execution | T1055 | RWX memory scanning; thread start address analysis |
| Command-line obfuscation | T1027 | Normalization engine (caret, env vars, tick removal) + entropy analysis |
| Short-lived processes (<5s) | T1059 | Native ETW with ~50ms latency captures process start events |
| Credential theft | T1003 | LSASS dump detection; browser credential file monitoring; credential canary |
| Network beaconing | T1071 | Statistical CV analysis of connection intervals per destination |
| Data exfiltration | T1048 | Upload/download ratio analysis; large outbound transfer detection |
| DNS tunneling | T1071.004 | DGA detection; query length analysis; entropy scoring |
| Scheduled task persistence | T1053.005 | Registry TaskCache monitoring; WMI subscription baselining |
| WSL abuse | T1202 | \\wsl$ filesystem scanning; bash_history analysis |
| Raw disk access | T1006 | NtQuerySystemInformation handle enumeration for direct disk handles |

### T-3: Attacker compromises the supply chain

| Technique | MITRE | Mitigation |
|-----------|-------|------------|
| Trojanize NuGet package | T1195.002 | Lock files committed (Agent/Core/Tests); `--locked-mode` CI; Dependabot; vulnerability audit gate |
| Compromise CI pipeline | T1195.002 | Pinned action SHAs; no secrets in build logs; SBOM generation (best-effort) |
| MITM auto-update | T1195.002 | RSA-4096 PSS signature required; optional SHA256SUMS second factor; fail-closed TLS 1.2+ |
| Downgrade to older agent | T1195.002 | Anti-downgrade version check before apply |
| Bad signed update breaks agent | T1195.002 | `.previous` backup + `.update-pending` health-check rollback |
| Tamper with installer / release zip | T1195.002 | Per-asset `.sig` + `SHA256SUMS` on release; optional Authenticode/codesign/keystore when secrets configured (see docs/SUPPLY_CHAIN.md) |
| Inject malicious policy | T1195.002 | RSA-PSS policy verification via `PolicySignatureVerifier` (distinct path; key dual-use until rotation) |

### T-4b: Weaponize response / rename tools (0.3.6)

| Attack | Mitigation |
|--------|------------|
| Rename malware to `explorer` / `lsass` to gain kill immunity | Protection only if **image path is OS system directory** - Temp spoof is killable |
| Path contains `Behavedr` under Temp to fake agent | Agent image check is install-root + binary name only, not substring anywhere |
| Force agent to kill itself / quarantine itself | `ResponseSafety` refuses own PID, parent PID, agent install binaries |
| Force agent to firewall-block itself | App network block refuses agent + OS system images |
| Flood kills via low signed-policy thresholds | Active policy requires ResponseThreshold >= 40; MaxKillsPerMinute <= 60 |
| Rely on tool name lists after reading source | Name-only signals are low weight; staging paths (`/tmp`, Temp, Downloads) remain high weight |

### T-4: Attacker exploits the agent itself

| Technique | MITRE | Mitigation |
|-----------|-------|------------|
| Path traversal in quarantine | T1059 | SecurityValidation.IsPathWithinDirectory(); reject ../ and null bytes |
| Replay detection reports | T1557 | Boot nonce + monotonic sequence + unique nonce per report |
| Inject false offline buffer | T1565 | AES-256-GCM authenticated encryption; tampered reports -> dead-letter |
| Poison config on first run | T1562 | Pre-seal validation checks all critical values before sealing |
| Exploit PID reuse in process kill | T1055 | Process name re-verification before kill; documented TOCTOU residual risk |

---

## 6. Accepted Risks

| Risk | Rationale | Residual Impact |
|------|-----------|-----------------|
| No kernel driver | Deployment simplicity; no WHQL signing requirement; broader OS compatibility | Kernel rootkits are invisible |
| TOCTOU in ProcessKillAction | Inherent to userland process management; sub-millisecond race window | Theoretically possible PID reuse kill of wrong process |
| Single-process architecture | Simplicity; single binary deployment; SCM recovery provides restart | One successful kill terminates all protection until SCM restart |
| Offline buffer sequence gaps | Server must accept out-of-order reports within a boot session | Theoretical window for undetected report suppression |
| Fixed entropy fallback | Allows operation when filesystem is unwritable (containers) | Degraded DPAPI binding when fallback activates |

---

## 7. Security Controls Summary

| Control | Implementation | Verification |
|---------|---------------|--------------|
| Authenticated encryption at rest | AES-256-GCM via SecureEnvelope | Key derived per-purpose via HKDF |
| Key protection | DPAPI LocalMachine + per-install random entropy | Restricted ACL on key file |
| Transport security | mTLS with CA pinning; fail-closed | Rejects all connections without valid CA |
| Update integrity | RSA-4096 PSS signatures + optional SHA256SUMS | Baked-in public key; rejects unsigned |
| Update anti-downgrade | Semantic version compare before apply | Rejects non-newer packages |
| Post-update rollback | `.previous` + health-check marker | Restores prior binaries on crypto health failure |
| Policy integrity | RSA-PSS via PolicySignatureVerifier | Fail-closed when signature missing/invalid |
| Config integrity | HMAC-SHA256 seal + pre-seal validation | Refuses to start on tamper detection |
| Binary integrity | SHA-256 baseline at startup; periodic verification | Tamper signal on mismatch |
| Anti-tamper (process) | DACL + anti-debug + QPC suspension detection | Multiple independent checks |
| Anti-tamper (ETW) | QueryTraceW liveness + function prologue verification | 10s check interval |
| Driver / BYOVD monitoring | DriverLoadMonitor (registry, services, name/hash heuristics) | Userland only; not a kernel filter driver |
| Input validation | Centralized SecurityValidation class | Path traversal, injection prevention |
| Replay prevention | Boot nonce + sequence number + per-report nonce | Server validates monotonicity |
| Response safety | `ResponseSafety`: refuse self/parent/agent image; OS protected names only if system path; no `Temp\Behavedr_*` immunity; quarantine/net block rails; kill budget cap <=60/min | Unit tests + path verification |
| Rename-resistant heuristics | `ThreatHeuristics`: name-only = low weight; staging path + executable = high weight | Rename alone does not clear path risk |

---

## 8. Future Considerations

**Shipped in 0.3.x code (field-gated):** Linux eBPF suite, macOS ES bridge + AUTH_EXEC denylist, dual update/policy keys, Android release pin + CI sign.

**Still future / external:**

- Kernel-level visibility (minifilter / callout) - out of userland EDR scope  
- Protected Process Light (PPL) for anti-tamper  
- Out-of-process watchdog for mutual monitoring  
- TPM hardware attestation  
- Full System Extension install product (Apple enrollment)  
- macOS notarization staple / continuous SLSA provenance  
- External penetration test
