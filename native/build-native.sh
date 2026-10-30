#!/usr/bin/env bash
# Best-effort native artifact build for release packaging (0.2.10+).
# Soft-fails individual targets so CI remains usable without full toolchains.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/native}"
mkdir -p "$OUT"
status=0

echo "==> Linux eBPF suite object (clang + BTF)"
if command -v clang >/dev/null 2>&1 && [[ "$(uname -s)" == Linux ]]; then
  EBPF_DIR="$ROOT/native/linux/ebpf"
  if [[ -f /sys/kernel/btf/vmlinux ]] && command -v bpftool >/dev/null 2>&1; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$EBPF_DIR/vmlinux.h" || true
  fi
  SRC="$EBPF_DIR/behavedr_suite.bpf.c"
  if [[ ! -f "$SRC" ]]; then
    echo "WARN: behavedr_suite.bpf.c missing - skip eBPF (legacy exec_trace.bpf.c is incompatible with loader)"
    status=1
  elif [[ -f "$EBPF_DIR/vmlinux.h" ]]; then
    ARCH_DEF="__TARGET_ARCH_x86"
    case "$(uname -m)" in
      aarch64|arm64) ARCH_DEF="__TARGET_ARCH_arm64" ;;
      armv7*|armhf) ARCH_DEF="__TARGET_ARCH_arm" ;;
    esac
    if clang -O2 -g -target bpf -D"$ARCH_DEF" -I "$EBPF_DIR" \
        -c "$SRC" -o "$OUT/behavedr_exec.bpf.o" 2>"$OUT/ebpf-build.log"; then
      echo "Built $OUT/behavedr_exec.bpf.o from $(basename "$SRC") ($ARCH_DEF)"
      cp -f "$OUT/behavedr_exec.bpf.o" "$EBPF_DIR/behavedr_exec.bpf.o" 2>/dev/null || true
    else
      echo "WARN: eBPF compile failed (see ebpf-build.log)"
      status=1
    fi
  else
    echo "WARN: vmlinux.h missing - skip eBPF object"
    status=1
  fi
else
  echo "SKIP: eBPF build (not Linux or no clang)"
fi

echo "==> macOS EndpointSecurity bridge dylib + System Extension"
if [[ "$(uname -s)" == Darwin ]]; then
  if clang -dynamiclib -o "$OUT/libbehavedr_es.dylib" \
      "$ROOT/native/macos/es_bridge/behavedr_es_bridge.c" \
      -framework EndpointSecurity -framework CoreFoundation 2>"$OUT/es-build.log"; then
    echo "Built $OUT/libbehavedr_es.dylib"
  else
    echo "WARN: ES bridge build failed (see es-build.log)"
    status=1
  fi
  if [[ -x "$ROOT/native/macos/SystemExtension/build.sh" ]]; then
    chmod +x "$ROOT/native/macos/SystemExtension/build.sh"
    (cd "$ROOT/native/macos/SystemExtension" && ./build.sh) \
      && cp -a "$ROOT/native/macos/SystemExtension/dist/." "$OUT/" 2>/dev/null \
      || echo "WARN: System Extension build skipped/failed"
  fi
else
  echo "SKIP: ES dylib / System Extension (not macOS)"
fi

echo "Native build finished with soft-status=$status (0=all ok)"
exit 0  # never fail the pipeline; artifacts optional
