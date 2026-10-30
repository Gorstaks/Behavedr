#!/usr/bin/env bash
# Build Behavedr Endpoint Security System Extension host bundle (0.3.3).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${ROOT}/dist"
BUNDLE="$OUT/com.croatiasecurity.behavedr.es.systemextension"
BIN="$BUNDLE/Contents/MacOS/BehavedrES"

rm -rf "$OUT"
mkdir -p "$BUNDLE/Contents/MacOS"
cp "$ROOT/Info.plist" "$BUNDLE/Contents/"

# Bump version stamp in Info.plist if sed available
if command -v plutil >/dev/null 2>&1; then
  plutil -replace CFBundleVersion -string "0.3.3" "$BUNDLE/Contents/Info.plist" 2>/dev/null || true
  plutil -replace CFBundleShortVersionString -string "0.3.3" "$BUNDLE/Contents/Info.plist" 2>/dev/null || true
fi

clang -O2 -fobjc-arc -Wall -Wextra \
  -o "$BIN" \
  "$ROOT/main.m" \
  -framework EndpointSecurity \
  -framework Foundation

# Optional codesign when identity present
if [[ -n "${MACOS_CODESIGN_IDENTITY:-}" ]]; then
  codesign --force --options runtime --sign "$MACOS_CODESIGN_IDENTITY" \
    --entitlements "$ROOT/entitlements.plist" \
    "$BIN"
  codesign --force --options runtime --sign "$MACOS_CODESIGN_IDENTITY" \
    --entitlements "$ROOT/entitlements.plist" \
    "$BUNDLE" 2>/dev/null || true
  echo "Signed with \$MACOS_CODESIGN_IDENTITY"
else
  echo "WARN: MACOS_CODESIGN_IDENTITY unset - unsigned (es_new_client will fail without entitlement)"
fi

echo "Built $BUNDLE"
echo "Events path default: /var/run/behavedr/es.events"
echo "AUTH: set BEHAVEDR_ES_AUTH=1 on the extension host"
