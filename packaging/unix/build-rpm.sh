#!/usr/bin/env bash
# Build an RPM for Behavedr (0.3.5+).
# Usage: ./packaging/unix/build-rpm.sh <version> <path-to-linux-x64-publish-dir> [native-dir]
set -euo pipefail

VERSION="${1:?version e.g. 0.3.5}"
PUBLISH="${2:?publish dir containing Behavedr binary}"
NATIVE="${3:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT

mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
STAGE="$TOP/behavedr-${VERSION}"
mkdir -p "$STAGE/opt/behavedr/ebpf" "$STAGE/etc/systemd/system" "$STAGE/usr/share/doc/behavedr"
install -m 0755 "$PUBLISH/Behavedr" "$STAGE/opt/behavedr/Behavedr"
install -m 0644 "$ROOT/packaging/unix/behavedr.service" "$STAGE/etc/systemd/system/behavedr.service"
install -m 0644 "$ROOT/packaging/unix/README.txt" "$STAGE/usr/share/doc/behavedr/README"
[[ -f "$ROOT/packaging/unix/pf-behavedr-block.conf" ]] && \
  install -m 0644 "$ROOT/packaging/unix/pf-behavedr-block.conf" "$STAGE/opt/behavedr/" || true

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
  install -m 0644 "$OBJ" "$STAGE/opt/behavedr/behavedr_exec.bpf.o"
  install -m 0644 "$OBJ" "$STAGE/opt/behavedr/ebpf/behavedr_exec.bpf.o"
  HAS_EBPF=1
  echo "Packaging eBPF object from $OBJ"
fi

tar -C "$TOP" -czf "$TOP/SOURCES/behavedr-${VERSION}.tar.gz" "behavedr-${VERSION}"

cat > "$TOP/SPECS/behavedr.spec" <<EOF
Name:           behavedr
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        Behavedr behavioral EDR agent
License:        Proprietary
URL:            https://github.com/CroatiaSecurity/Behavedr
Source0:        behavedr-%{version}.tar.gz
BuildArch:      x86_64
Requires:       systemd
Recommends:     bpftool

%description
Userland endpoint detection and response agent for Linux.
eBPF object packaged: ${HAS_EBPF} (1=yes).

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}/

%files
%defattr(-,root,root,-)
/opt/behavedr
/etc/systemd/system/behavedr.service
/usr/share/doc/behavedr

%post
getent group behavedr >/dev/null || groupadd -r behavedr
getent passwd behavedr >/dev/null || useradd -r -g behavedr -d /var/lib/behavedr -s /sbin/nologin behavedr
mkdir -p /var/lib/behavedr /opt/behavedr/{logs,quarantine,buffer,run,ebpf}
[ -d /sys/fs/bpf ] && mkdir -p /sys/fs/bpf/behavedr || true
chown -R behavedr:behavedr /var/lib/behavedr /opt/behavedr
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Enable with: systemctl enable --now behavedr"

%changelog
* $(date '+%a %b %d %Y') CroatiaSecurity <security@croatiasecurity.com> - ${VERSION}-1
- Packaging for Behavedr ${VERSION}
EOF

rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/behavedr.spec"
cp "$TOP"/RPMS/*/*.rpm .
ls -la ./*.rpm
echo "RPM build complete."
