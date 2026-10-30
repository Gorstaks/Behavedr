#!/usr/bin/env bash
# Behavedr mTLS Certificate Generation Script (Linux/macOS)
# Generates a self-signed CA, server cert, and client cert for agent-server mTLS.
#
# Usage:
#   ./tools/generate-certs.sh
#   ./tools/generate-certs.sh --output ./my-certs --server-dns my-server.local
#
# Requires: openssl

set -euo pipefail

OUTPUT_DIR="${1:-./certs}"
SERVER_DNS="${2:-localhost}"
VALID_DAYS=730
PASSWORD="${BEHAVEDR_CERT_PASSWORD:-}"

if [ -z "$PASSWORD" ]; then
    echo -n "Enter PFX password (or set BEHAVEDR_CERT_PASSWORD env var): "
    read -rs PASSWORD
    echo ""
fi

if [ -z "$PASSWORD" ]; then
    echo "ERROR: Password is required. Set BEHAVEDR_CERT_PASSWORD or provide at prompt." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "=== Behavedr mTLS Certificate Generation ==="
echo "Output: $OUTPUT_DIR"
echo "Server DNS: $SERVER_DNS"
echo "Valid for: $VALID_DAYS days"
echo ""

# --- CA ---
echo "[1/3] Generating CA..."
openssl req -x509 -new -nodes \
  -keyout "$OUTPUT_DIR/ca.key" \
  -out "$OUTPUT_DIR/ca.crt" \
  -days "$VALID_DAYS" \
  -subj "/CN=Behavedr CA/O=CroatiaSecurity/C=HR" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  2>/dev/null

echo "  CA: $OUTPUT_DIR/ca.crt"

# --- Server cert ---
echo "[2/3] Generating server certificate..."
openssl req -new -nodes \
  -keyout "$OUTPUT_DIR/server.key" \
  -out "$OUTPUT_DIR/server.csr" \
  -subj "/CN=$SERVER_DNS/O=CroatiaSecurity/C=HR" \
  2>/dev/null

cat > "$OUTPUT_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$SERVER_DNS,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req \
  -in "$OUTPUT_DIR/server.csr" \
  -CA "$OUTPUT_DIR/ca.crt" \
  -CAkey "$OUTPUT_DIR/ca.key" \
  -CAcreateserial \
  -out "$OUTPUT_DIR/server.crt" \
  -days "$VALID_DAYS" \
  -extfile "$OUTPUT_DIR/server.ext" \
  2>/dev/null

# Create PFX for .NET consumption
openssl pkcs12 -export \
  -in "$OUTPUT_DIR/server.crt" \
  -inkey "$OUTPUT_DIR/server.key" \
  -certfile "$OUTPUT_DIR/ca.crt" \
  -out "$OUTPUT_DIR/server.pfx" \
  -passout "pass:$PASSWORD" \
  2>/dev/null

echo "  Server: $OUTPUT_DIR/server.pfx"

# --- Client cert ---
echo "[3/3] Generating client certificate..."
openssl req -new -nodes \
  -keyout "$OUTPUT_DIR/client.key" \
  -out "$OUTPUT_DIR/client.csr" \
  -subj "/CN=Behavedr Agent/O=CroatiaSecurity/C=HR" \
  2>/dev/null

cat > "$OUTPUT_DIR/client.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl x509 -req \
  -in "$OUTPUT_DIR/client.csr" \
  -CA "$OUTPUT_DIR/ca.crt" \
  -CAkey "$OUTPUT_DIR/ca.key" \
  -CAcreateserial \
  -out "$OUTPUT_DIR/client.crt" \
  -days "$VALID_DAYS" \
  -extfile "$OUTPUT_DIR/client.ext" \
  2>/dev/null

openssl pkcs12 -export \
  -in "$OUTPUT_DIR/client.crt" \
  -inkey "$OUTPUT_DIR/client.key" \
  -certfile "$OUTPUT_DIR/ca.crt" \
  -out "$OUTPUT_DIR/client.pfx" \
  -passout "pass:$PASSWORD" \
  2>/dev/null

echo "  Client: $OUTPUT_DIR/client.pfx"

# Cleanup intermediate files
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/*.ext "$OUTPUT_DIR"/*.srl

echo ""
echo "Done! Files:"
echo "  $OUTPUT_DIR/ca.crt       - CA certificate (distribute to agents)"
echo "  $OUTPUT_DIR/ca.key       - CA private key (keep secure!)"
echo "  $OUTPUT_DIR/server.pfx   - Server TLS cert"
echo "  $OUTPUT_DIR/client.pfx   - Agent mTLS client cert"
echo ""
echo "PFX password: $PASSWORD"
echo ""
echo "Configure appsettings.json:"
echo '  "Communication": {'
echo '    "CaCertPath": "certs/ca.crt",'
echo '    "ClientCertPath": "certs/client.pfx",'
echo '    "ClientCertPassword": "behavedr-dev"'
echo '  }'
