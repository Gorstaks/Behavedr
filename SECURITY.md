# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4.0 | No        |

Only the latest release receives security patches. Upgrade promptly when a new version is published.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: **security@croatiasecurity.com**
2. Or use [GitHub Security Advisories](https://github.com/CroatiaSecurity/Behavedr/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Affected version(s)
- Potential impact assessment
- Suggested fix (if you have one)

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix (critical) | 30 days |
| Fix (other) | 90 days |
| Disclosure | Coordinated with reporter after fix ships |

We will credit reporters in release notes unless anonymity is preferred. We do not take legal action against researchers who follow responsible disclosure.

## Scope

**In scope:**
- Agent binary (Windows, Linux, macOS)
- Detection and scoring engines
- Self-protection mechanisms
- Cryptographic operations and key management
- Communication layer (mTLS, policy, updates)
- Build pipeline and supply chain
- Installer and packaging scripts
- Configuration handling and integrity verification
- Android agent (MAUI) detection and response path

**Out of scope:**
- Third-party dependency vulnerabilities (report upstream; notify us for tracking)
- Social engineering against CroatiaSecurity personnel
- Denial of service against CI/CD infrastructure
- iOS (not a Behavedr SKU; see [docs/IOS.md](docs/IOS.md))

## Security Architecture

### Design Principles

- **Userland operation.** No kernel driver requirement. Reduces attack surface and deployment complexity at the cost of kernel rootkit visibility. Full behavioral detection on Windows (ETW + P/Invoke), Linux (cn_proc, fanotify, /proc, auth logs, kernel modules), and macOS (kqueue process + VNODE file watches, codesign checks).
- **Least privilege where possible.** SYSTEM context is required for ETW, process inspection, and response actions. File permissions are restricted to SYSTEM and Administrators on Windows; systemd hardening applies on Linux.
- **Defense in depth.** Multiple independent self-protection mechanisms. No single bypass disables all detection.
- **Fail-closed communication.** TLS connections are rejected without a valid pinned CA certificate. No fallback to insecure transport.
- **Cryptographic integrity.** All local storage uses authenticated encryption (AES-256-GCM). Configuration files are HMAC-sealed. Updates require RSA-4096 PSS signatures. Policy verification uses a dedicated verifier path (key may still be dual-use until rotated - see [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md)).
- **Minimal attack surface.** Single-file deployment. No temp extraction for the running agent image. Deterministic builds. Pinned dependencies with lock files on desktop projects.

### Cryptographic Inventory

| Operation | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Machine key protection | DPAPI (LocalMachine) + entropy | 256-bit | Per-install random entropy prevents cross-machine unwrap |
| Local encryption | AES-256-GCM | 256-bit | Purpose-specific keys derived via HKDF-SHA256 |
| Config integrity | HMAC-SHA256 | 256-bit | Key derived from machine key via HKDF |
| Update signing | RSA-PSS SHA-256 | 4096-bit | Private key offline; public key baked into binary |
| Policy signing | RSA-PSS SHA-256 | 4096-bit | Separate `PolicySignatureVerifier` path; may share material until rotation |
| Transport | TLS 1.3 (mTLS) | 2048-bit client cert | CA-pinned; fail-closed |
| Config value encryption | AES-256-GCM (cross-platform) / DPAPI (Windows) | 256-bit | DPAPI uses LocalMachine scope |
| macOS key storage | Keychain Services (System Keychain) | 256-bit | Via `security` CLI; Secure Enclave-backed on Apple Silicon when available |
| Android key storage | Android Keystore (TEE/StrongBox preferred) | 256-bit | Hardware-backed when device supports it |

### Self-Protection Mechanisms (desktop, current)

| Mechanism | Check Interval | Description |
|-----------|---------------|-------------|
| Process DACL | Startup | Denies PROCESS_TERMINATE to Everyone except SYSTEM/Admins |
| Anti-debug | 30s | FailFast on Debugger.IsAttached in Release builds |
| Binary integrity | 10s | SHA-256 of running executable vs startup baseline |
| QPC suspension detection | ~2s | Detects NtSuspendProcess via performance counter gap |
| Service registry self-healing | 10s | Re-registers service if registry key deleted |
| ETW session liveness | 10s | QueryTraceW verifies session not killed externally |
| ntdll!EtwEventWrite integrity | 10s | Prologue byte comparison against startup baseline |
| amsi!AmsiScanBuffer integrity | 10s | Prologue byte comparison against startup baseline |
| Safe Mode persistence | Install-time | Registry entries for Minimal and Network Safe Boot |
| SCM failure recovery | Service-level | Restart at 5s, 10s, 30s after unexpected stop |
| Config HMAC seal | Startup | Refuses to start if config has been tampered |
| Connectivity canary | ~45s (jittered) | Detects network isolation/firewall silencing |
| Watchdog heartbeat | 3s | Detects monitoring loop suspension or deadlock |
| Driver load / BYOVD monitoring | Continuous / event | Registry, service installs, LOLDrivers-oriented heuristics |
| Startup self-test | Startup | Crypto, keys, monitors, response actions, directories |
| Post-update health rollback | Startup after update | Restores `.previous` if crypto health fails |
| macOS kqueue process monitor | Real-time (500ms discovery) | Detects process exec/fork/exit via kernel events |
| macOS VNODE file watches | Real-time | LaunchDaemons/Agents, helpers, sensitive paths |
| macOS codesign self-check | Periodic | `codesign -v`, SIP status, unsigned LaunchDaemon binaries |
| macOS Keychain key storage | Startup | Machine key in System Keychain (not on filesystem) |
| macOS proc_pidpath kill verify | On response | Verifies process identity before termination |
| Linux ProtectProc=invisible | Service-level | Hides agent from /proc enumeration |
| Linux syscall filtering | Service-level | Blocks mount/reboot/swap/obsolete syscalls |
| Linux kernel module monitor | Periodic | New module loads, known rootkit names, lockdown soft signal |
| Linux auth monitor | Tailing | Failure bursts, root sessions, root SSH |
| Linux nftables rate limiting | On response | Max 100 isolation rules (prevents DoS) |
| Memory secret zeroing | On use | CryptographicOperations.ZeroMemory after key derivation |

### Android Self-Protection Mechanisms

| Mechanism | Check Interval | Description |
|-----------|---------------|-------------|
| Debugger detection | Each cycle | TracerPid + managed Debugger.IsAttached |
| Frida/instrumentation | Each cycle | Maps scanning, port check, thread names, timing analysis |
| APK integrity | Each cycle | SHA-256 baseline comparison |
| Emulator detection | Each cycle | Build.prop, QEMU files, cpuinfo analysis |
| Root cloaking bypass | Each cycle | Magisk Hide/DenyList detection |
| Native hook detection | Each cycle | /proc/self/maps suspicious .so analysis |
| Suspension detection | Each cycle | Monotonic clock gap (TickCount64) |
| Process connector | Real-time | inotify /proc for immediate process spawn detection |
| Memory analysis | 10s | RWX regions, memfd, suspicious library loading |
| Credential monitoring | 10s | Accessibility abuse, banking trojans, clipboard |
| Anti-tamper guard | 10s | OOM adj, binary integrity, data directory health |
| Response engine | On detection | kill -9 (root), isolation, Device Owner actions when enrolled |
| Key protection | Startup | Android Keystore TEE/StrongBox hardware-backed encryption |
| Shared detection runtime | Process lifetime | Foreground service and UI share one DetectionEngine (fixed in 0.2.2) |

### Supply Chain Controls

Documented in full in [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md). Summary:

- Deterministic builds (`Directory.Build.props`)
- Package lock files for Agent, Core, Tests; CI `--locked-mode`
- Pinned CI action SHAs (no floating tags)
- SBOM generation on Linux release builds (best-effort tool install)
- Signed auto-updates with RSA-4096 PSS verification
- Release `SHA256SUMS` (+ `.sig` when `UPDATE_SIGNING_KEY` is configured)
- Android APK hard-required for release workflow
- Vulnerability audit in CI (`dotnet list package --vulnerable`)
- Dependabot for NuGet and GitHub Actions
- Optional Authenticode / codesign / Android keystore when secrets are present
- Local build capability via `installer/build.ps1` (no CI dependency for Windows portable/installer builds)

## Known Limitations

These are current, intentional, or residual limits - not a backlog disguised as features.

- **No kernel-level visibility.** Kernel rootkits can hide from userland monitors. Operational "10/10" is defined as best-in-class userland + supply chain, not omnipotence against ring-0 adversaries.
- **Native ETW requires elevation** (SYSTEM/admin). Falls back to WMI polling without it.
- **macOS real-time:** EndpointSecurity client is implemented (`MacOSEndpointSecurityMonitor` + `libbehavedr_es.dylib`). Without Apple ES entitlement the client fails soft and **kqueue** remains active. Optional AUTH denylist via `BEHAVEDR_ES_AUTH=1`.
- **Linux real-time:** eBPF exec path is implemented (`LinuxEbpfExecMonitor` + `native/linux/ebpf`). Without CAP_BPF / object file, **cn_proc** remains primary.
- **Single-process agent architecture.** A successful privileged kill terminates protection until SCM/systemd/watchdog restart (seconds, not continuous multiproc resilience).
- **Health-check auto-rollback** restores from `.previous` when post-update crypto health fails. It does **not** cover every possible failure mode (e.g. partial file locks on Windows may require manual recovery or reinstall).
- **DPAPI entropy fallback** to a fixed value when the filesystem is unwritable (containers). Logged as CRITICAL.
- **WFP user-mode filters** via `WindowsWfpEngine` (fwpuclnt); advfirewall fallback. **No callout driver** / deep packet inspection.
- **OS code-signing is optional** and depends on repository secrets. Releases without Authenticode/codesign/keystore must not be described as OS-trusted. Agent-enforced RSA-PSS is independent of OS trust.
- **Policy and update keys are distinct as of 0.3.0** (separate RSA-4096 pairs). Server must sign policies with `policy-signing-key.pem`.
- **Play Integrity** may degrade if the official dependency / cloud project number is not fully wired for a given build; treat attestation quality as deployment-specific.
- **iOS is not a Behavedr SKU.** Apple's sandbox cannot host device EDR. Phones belong in MDM. See [docs/IOS.md](docs/IOS.md).
- **Default response mode is AlertOnly.** Active kill/isolate is an operator decision with legal and operational consequences.

## Further Reading

| Document | Contents |
|----------|----------|
| [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) | Release trust, secrets, operator verification |
| [docs/RELEASE.md](docs/RELEASE.md) | Release runbook |
| [THREAT_MODEL.md](THREAT_MODEL.md) | System threat model |
| [docs/](docs/) | Architecture notes and red/blue audits |
