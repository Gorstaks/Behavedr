# Behavedr MITRE ATT&CK Coverage (Userland)

**Version:** 0.4.3
**Scope:** Techniques addressed by monitors/response in this tree. Not a claim of 100% ATT&CK completeness.

| Technique | ID | Primary implementation |
|-----------|-----|------------------------|
| Process execution (real-time) | T1059 | Windows ETW; Linux cn_proc + **eBPF** (`LinuxEbpfExecMonitor`); macOS kqueue + **EndpointSecurity** (`MacOSEndpointSecurityMonitor`); **ScriptExecutionMonitor** (encoded PS/AMSI) |
| Agentic / automated tool abuse | T1059 / T1106 | **AgenticProcessMonitor** (AI agents -> shell/LOLBin/cred tools) |
| Supply chain runtime | T1195 | **PackageRuntimeMonitor** (pkg mgr children, package-tree drops, AI config poison) |
| Ransomware canary | T1486 | **CanaryFileMonitor** + FileActivity rename/write bursts |
| Cloud exfil staging | T1567 | **CloudSyncExfilMonitor** |
| Named pipe C2 | T1559.001 | **NamedPipeMonitor** (Windows) |
| Malicious shortcut | T1204.002 / T1566.002 | **LnkShortcutMonitor** (Windows) |
| Process injection / hollow | T1055 | MemoryAnalyzer, ThreadStartAddressScanner, BehavioralMonitor |
| Credential dump (LSASS) | T1003.001 | LsassDumpMonitor, CredentialGuardMonitor |
| Token impersonation | T1134 | TokenIntegrityMonitor, LinuxTokenMonitor |
| PPID spoof | T1505 / T1036 | ParentPidSpoofDetector, ProcessAncestryCache |
| DLL side-load | T1574.002 | DllSideloadDetector |
| Scheduled task / WMI persist | T1053 / T1546 | ScheduledTaskMonitor, RegistryPersistenceMonitor |
| Registry run keys | T1547.001 | RegistryPersistenceMonitor |
| Service / driver install | T1543 / T1068 | DriverLoadMonitor (BYOVD) |
| Network C2 / beacon | T1071 | BeaconingDetector, NetworkConnectionMonitor, DnsQueryMonitor |
| DNS tunneling / DGA | T1071.004 | DnsQueryMonitor, UnixDnsMonitor, BehavedrVpnService |
| Data exfil | T1041 | DataExfiltrationMonitor, UnixDataExfiltrationMonitor |
| SMB / share lateral | T1021.002 | NetworkShareMonitor |
| Raw disk | T1006 | RawDiskAccessMonitor |
| WSL abuse | T1202 | WslMonitor |
| Ghost / unlinked binary | T1036 | GhostProcessMonitor, UnixGhostProcessMonitor |
| Ephemeral process | T1059 | EphemeralProcessMonitor, LinuxEphemeralProcessMonitor, MacOSKqueue |
| Kernel module rootkit | T1014 / T1547 | LinuxKernelModuleMonitor |
| Brute force / auth abuse | T1110 | LinuxAuthMonitor |
| LaunchAgent/Daemon | T1543.001/004 | MacOSPersistenceMonitor, MacOSFileEventMonitor |
| Codesign / SIP weaken | T1553 | MacOSCodeSignMonitor |
| Anti-debug / tamper EDR | T1562 | AntiTamperGuard, UnixAntiTamper, AndroidSelfProtection |
| Disable firewall / silence | T1562.004 | ConnectivityCanaryMonitor, AntiTamper firewall check |
| Safe Mode abuse | T1562 | SafeBoot keys (install + AntiTamper check) |
| Supply chain update | T1195.002 | UpdateSignatureVerifier, AutoUpdater, SHA256SUMS |
| ISO / container isolate | T1553.005 | IsolationResponseEngine |
| Mobile sideload / overlay | T1406 / T1411* | AndroidPlatformSignalProvider, AndroidAntiTamper |
| Mobile integrity | - | PlayIntegrityAttestor (reflection; server verify recommended) |

\* Mobile technique IDs vary by ATT&CK Mobile matrix version.

## Response coverage

| Action | Platforms |
|--------|-----------|
| Process kill (path-verified) | Windows, Linux (pidfd), macOS (proc_pidpath) |
| File quarantine | Desktop |
| Network isolate | Windows **WFP** + advfirewall fallback, Linux nftables, macOS route/pf, Android iptables/VPN |
| ISO/Docker/VM containment | IsolationResponseEngine |
| Device Owner disable app | Android (when enrolled) |

## Explicit gaps (not covered)

- Kernel rootkits that fully hide from userland / eBPF
- EndpointSecurity **AUTH** (blocking) mode - NOTIFY only in 0.3.0
- eBPF without CAP_BPF or without built `behavedr_exec.bpf.o` (falls back to cn_proc)
- iOS (not a Behavedr SKU; Apple sandbox - use MDM)
- OS code-signing trust without commercial certs
- WFP **callout driver** (user-mode filters only)
