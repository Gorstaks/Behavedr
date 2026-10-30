---
inclusion: auto
---

# Behavedr Project Constraints

## Signing and Certification Status

This project operates WITHOUT any of the following:

- **No code signing certificates** - binaries are unsigned. No Authenticode, no Apple Developer ID, no GPG binary signing.
- **No WHQL (Windows Hardware Quality Labs) approval** - no kernel-mode drivers, no certified filter drivers.
- **No Apple notarization** - no System Extensions (which require notarization). No kext signing.
- **No kernel modules** - Linux kernel modules require signing on SecureBoot systems. We don't have signing keys for this.

## Architecture Constraint: Userland Only

All detection, protection, and response mechanisms MUST operate in userland (user-space).

This means:
- **Linux:** Use /proc, netlink sockets (cn_proc), fanotify, eBPF (where available without signing), nftables, audit subsystem. NO kernel modules.
- **macOS:** Use Process APIs, lsof/ps, libproc P/Invoke, FSEvents. NO System Extensions, NO EndpointSecurity.framework (requires notarization), NO kexts.
- **Windows:** Use ETW, WMI, Win32 APIs, DACL manipulation. NO kernel drivers, NO WFP callout drivers, NO minifilter drivers.

## Implications for Security Posture

Because we operate in userland only:
1. **Kill protection is limited** - on Unix, SIGKILL cannot be blocked without a kernel module. We mitigate with rapid service restart (systemd RestartSec=1, launchd KeepAlive+ThrottleInterval=1) and forensic logging.
2. **Rootkit detection is best-effort** - a kernel rootkit can hide from userland monitors. We detect SYMPTOMS (bind mounts over /proc, binary integrity changes) but cannot prevent VFS-layer hiding.
3. **Real-time events on macOS are polling-based** - EndpointSecurity.framework would provide real-time but requires notarization. We use Process.GetProcesses() and lsof polling.
4. **Network filtering uses nftables/iptables rules** - no WFP callout driver or pf kernel hooks.

## Key Storage

- **Windows:** DPAPI (DataProtectionScope.LocalMachine) - hardware-backed where TPM available.
- **Linux:** Kernel keyring (add_key/request_key syscalls) - key lives in kernel memory, not on filesystem. Falls back to chmod 600 files in containers.
- **macOS:** File-permission based (chmod 600). Keychain Services integration is a future goal but requires Apple Developer account for proper ACL binding.

## Update Signing

- The RSA-4096 public key is baked into the binary for update signature verification.
- Updates are signed offline with the private key (kept secure, never committed).
- If `IsProductionKeyConfigured()` returns false, signature verification is SKIPPED (dev mode only).

## Git Workflow

- **Always push directly to `main`.** Do not create feature branches, do not push to any branch other than `main`.
- No pull requests, no branch-based workflow. Commit and push to main.

## When Implementing New Features

1. Never introduce dependencies on kernel drivers, System Extensions, or signed components.
2. Always provide graceful fallback when a capability requires elevated permissions (CAP_SYS_ADMIN, etc.).
3. Document which Linux capabilities are needed (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, CAP_NET_ADMIN, CAP_AUDIT_READ).
4. Use P/Invoke for platform-specific syscalls rather than external binaries where possible (reduces attack surface from PATH manipulation).
5. All self-protection is detection + forensic logging + rapid restart, NOT prevention (since we can't prevent SIGKILL without kernel support).
