#!/usr/bin/env bash
# Sign Behavedr release assets with RSA-4096 PSS (SHA-256) and emit SHA256SUMS.
# Matches UpdateSignatureVerifier: RSA-PSS SHA-256, salt length = digest.
#
# Usage:
#   ./tools/sign-release.sh <assets-dir> [private-key.pem]
#   SKIP_IF_MISSING_KEY=1 ./tools/sign-release.sh release-assets
set -euo pipefail

ASSETS_DIR="${1:-}"
KEY_PATH="${2:-update-signing-key.pem}"

if [[ -z "${ASSETS_DIR}" || ! -d "${ASSETS_DIR}" ]]; then
  echo "Usage: $0 <assets-dir> [private-key.pem]" >&2
  exit 2
fi

if [[ ! -f "${KEY_PATH}" ]]; then
  if [[ "${SKIP_IF_MISSING_KEY:-0}" == "1" ]]; then
    echo "WARNING: Private key not found at ${KEY_PATH} - skipping RSA-PSS signing" >&2
    exit 0
  fi
  echo "ERROR: Private key not found: ${KEY_PATH}" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl not found on PATH" >&2
  exit 1
fi

shopt -s nullglob
mapfile -t FILES < <(find "${ASSETS_DIR}" -maxdepth 1 -type f ! -name '*.sig' ! -name 'SHA256SUMS' ! -name 'SHA256SUMS.sig' | sort)
if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "ERROR: No assets to sign in ${ASSETS_DIR}" >&2
  exit 1
fi

echo "Signing ${#FILES[@]} asset(s) with RSA-PSS SHA-256..."
for f in "${FILES[@]}"; do
  base="$(basename "$f")"
  openssl dgst -sha256 \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:digest \
    -sign "${KEY_PATH}" \
    -out "${f}.sig" \
    "${f}"
  echo "  signed ${base} -> ${base}.sig"
done

SUMS="${ASSETS_DIR}/SHA256SUMS"
: > "${SUMS}"
for f in "${FILES[@]}"; do
  # Portable SHA-256 (Linux sha256sum or macOS shasum)
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${ASSETS_DIR}" && sha256sum "$(basename "$f")") >> "${SUMS}"
  else
    h="$(shasum -a 256 "$f" | awk '{print $1}')"
    echo "${h}  $(basename "$f")" >> "${SUMS}"
  fi
done
echo "Wrote ${SUMS}"

openssl dgst -sha256 \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest \
  -sign "${KEY_PATH}" \
  -out "${SUMS}.sig" \
  "${SUMS}"
echo "  signed SHA256SUMS -> SHA256SUMS.sig"
echo "Done."
