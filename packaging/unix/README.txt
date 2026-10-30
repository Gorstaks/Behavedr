Behavedr Agent - Unix packaging
================================

Self-contained single-file binary (no .NET runtime install required).

Quick start
-----------
  chmod +x Behavedr
  sudo ./Behavedr

Linux (systemd) - production
----------------------------
  sudo useradd -r -s /usr/sbin/nologin behavedr 2>/dev/null || true
  sudo mkdir -p /opt/behavedr/{logs,quarantine,buffer,run} /var/lib/behavedr
  sudo cp Behavedr /opt/behavedr/
  sudo cp behavedr.service /etc/systemd/system/
  sudo chown -R behavedr:behavedr /opt/behavedr /var/lib/behavedr
  sudo systemctl daemon-reload
  sudo systemctl enable --now behavedr

  Optional: set IPAddressAllow in the unit to lock egress to your management server.

macOS (launchd) - production
----------------------------
  sudo mkdir -p /opt/behavedr/logs
  sudo cp Behavedr /opt/behavedr/
  sudo cp com.croatiasecurity.behavedr.plist /Library/LaunchDaemons/
  sudo chown root:wheel /Library/LaunchDaemons/com.croatiasecurity.behavedr.plist
  sudo launchctl bootstrap system /Library/LaunchDaemons/com.croatiasecurity.behavedr.plist

  Grant Full Disk Access to /opt/behavedr/Behavedr in System Settings -> Privacy.
  Prefer a Developer ID signed + notarized build for Gatekeeper.

v0.3.5 platform coverage
-------------------------
  Linux: cn_proc, fanotify (+ optional PERM), eBPF suite, Landlock (opt-in),
         nftables, hardened systemd (bpffs pin path), deb/rpm with optional
         behavedr_exec.bpf.o + Recommends: bpftool.
  macOS: kqueue, EndpointSecurity bridge (opt), JSONL host fallback,
         VNODE, codesign, pf/route.
  Optional artifacts when CI produces them:
    behavedr_exec.bpf.o, libbehavedr_es.dylib, pf-behavedr-block.conf

  eBPF field notes:
    - Package installs object to /opt/behavedr/ when present at build time.
    - Runtime needs bpftool + CAP_BPF (unit already grants).
    - Rebuild object on target kernel major when BTF differs.

  Native soft-build: native/build-native.sh

GitHub: https://github.com/CroatiaSecurity/Behavedr
