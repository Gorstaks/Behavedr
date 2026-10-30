#!/usr/bin/env bash
# Build a Debian package for Behavedr (0.3.5+).
# Usage: ./packaging/unix/build-deb.sh <version> <path-to-linux-x64-publish-dir>
# Optional: third arg = native artifact dir (behavedr_exec.bpf.o)
set -euo pipefail

VERSION="${1:?version e.g. 0.3.5}"
PUBLISH="${2:?publish dir containing Behavedr binary}"
NATIVE="${3:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

PKG="behavedr_${VERSION}_amd64"
mkdir -p "$STAGE/$PKG/DEBIAN" \
         "$STAGE/$PKG/opt/behavedr/ebpf" \
         "$STAGE/$PKG/etc/systemd/system" \
         "$STAGE/$PKG/usr/share/doc/behavedr"

install -m 0755 "$PUBLISH/Behavedr" "$STAGE/$PKG/opt/behavedr/Behavedr"
install -m 0644 "$ROOT/packaging/unix/behavedr.service" "$STAGE/$PKG/etc/systemd/system/behavedr.service"
install -m 0644 "$ROOT/packaging/unix/README.txt" "$STAGE/$PKG/usr/share/doc/behavedr/README"
if [[ -f "$ROOT/packaging/unix/pf-behavedr-block.conf" ]]; then
  install -m 0644 "$ROOT/packaging/unix/pf-behavedr-block.conf" "$STAGE/$PKG/opt/behavedr/"
fi

# Ship eBPF object when present (CI soft-build or operator pre-built)
pick_obj() {
  local c
  for c in \
    "${NATIVE}/behavedr_exec.bpf.o" \
    "${PUBLISH}/behavedr_exec.bpf.o" \
    "${ROOT}/dist/native/behavedr_exec.bpf.o" \
    "${ROOT}/native/linux/ebpf/behavedr_exec.bpf.o"
  do
    if [[ -n "$c" && -f "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

HAS_EBPF=0
if OBJ="$(pick_obj)"; then
  install -m 0644 "$OBJ" "$STAGE/$PKG/opt/behavedr/behavedr_exec.bpf.o"
  install -m 0644 "$OBJ" "$STAGE/$PKG/opt/behavedr/ebpf/behavedr_exec.bpf.o"
  HAS_EBPF=1
  echo "Packaging eBPF object from $OBJ"
else
  echo "NOTE: no behavedr_exec.bpf.o - package will soft-fail eBPF (cn_proc remains primary)"
fi

# Recommends bpftool; hard Depends only systemd so package installs on minimal images
cat > "$STAGE/$PKG/DEBIAN/control" <<EOF
Package: behavedr
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: CroatiaSecurity <security@croatiasecurity.com>
Depends: systemd
Recommends: bpftool | linux-tools-common
Description: Behavedr behavioral EDR agent (Linux)
 Userland endpoint detection and response agent.
 Includes hardened systemd unit with CAP_BPF and bpffs pin path.
 eBPF object included: ${HAS_EBPF} (1=yes). Build object on target kernel when 0.
EOF

cat > "$STAGE/$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
getent group behavedr >/dev/null || groupadd --system behavedr
getent passwd behavedr >/dev/null || useradd --system --gid behavedr --home /var/lib/behavedr --shell /usr/sbin/nologin behavedr
mkdir -p /var/lib/behavedr /opt/behavedr/logs /opt/behavedr/quarantine /opt/behavedr/buffer /opt/behavedr/run /opt/behavedr/ebpf
# bpffs pin directory for LinuxEbpfLoader (unit also ExecStartPre=+)
if [ -d /sys/fs/bpf ]; then
  mkdir -p /sys/fs/bpf/behavedr || true
fi
chown -R behavedr:behavedr /var/lib/behavedr /opt/behavedr
systemctl daemon-reload || true
if [ -f /opt/behavedr/behavedr_exec.bpf.o ]; then
  echo "Behavedr: eBPF object present. Ensure bpftool is installed for suite load."
else
  echo "Behavedr: no eBPF object - cn_proc/fanotify remain primary. See native/linux/ebpf/README.md"
fi
echo "Enable with: systemctl enable --now behavedr"
EOF
chmod 0755 "$STAGE/$PKG/DEBIAN/postinst"

dpkg-deb --build "$STAGE/$PKG" "behavedr_${VERSION}_amd64.deb"
echo "Built behavedr_${VERSION}_amd64.deb"
