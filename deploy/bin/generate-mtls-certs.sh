#!/bin/bash
# generate-mtls-certs.sh — Generate self-signed mTLS certificates for internal components.
# Creates a CA and per-component certificates for gateway and proxy.
# Certificates are short-lived (30 days) and regenerated on each service start.
set -euo pipefail

CERT_DIR=/opt/lobsec/config/tls
CA_KEY="$CERT_DIR/ca.key"
CA_CERT="$CERT_DIR/ca.crt"
DAYS=30

mkdir -p "$CERT_DIR"

# ── Generate CA (if not exists or expired within 7 days) ─────────────────────

REGEN_CA=false
if [ ! -f "$CA_CERT" ] || [ ! -f "$CA_KEY" ]; then
  REGEN_CA=true
elif ! openssl x509 -checkend 604800 -noout -in "$CA_CERT" 2>/dev/null; then
  REGEN_CA=true
fi

if [ "$REGEN_CA" = true ]; then
  echo "[mtls] Generating new CA certificate"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CA_KEY" -out "$CA_CERT" \
    -days "$DAYS" -nodes \
    -subj "/O=lobsec/CN=lobsec Internal CA" 2>/dev/null
fi

# ── Generate component certificates ─────────────────────────────────────────

generate_cert() {
  local name="$1"
  local cn="$2"
  local san="$3"
  local key="$CERT_DIR/$name.key"
  local csr="$CERT_DIR/$name.csr"
  local cert="$CERT_DIR/$name.crt"

  # Skip if certificate is still valid for 7+ days
  if [ -f "$cert" ] && openssl x509 -checkend 604800 -noout -in "$cert" 2>/dev/null; then
    echo "[mtls] $name certificate still valid"
    return
  fi

  echo "[mtls] Generating certificate for $name"

  # Generate key + CSR
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$key" -out "$csr" -nodes \
    -subj "/O=lobsec/CN=$cn" 2>/dev/null

  # Sign with CA
  openssl x509 -req -in "$csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$cert" -days "$DAYS" \
    -extfile <(echo "subjectAltName=$san
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth") 2>/dev/null

  rm -f "$csr"
}

generate_cert "gateway" "lobsec-gateway" "IP:127.0.0.1,DNS:localhost"
generate_cert "proxy" "lobsec-proxy" "IP:127.0.0.1,DNS:localhost"

# ── Set permissions ──────────────────────────────────────────────────────────

chmod 600 "$CERT_DIR"/ca.key "$CERT_DIR"/gateway.key
chmod 640 "$CERT_DIR"/proxy.key   # group-readable for lobsec-proxy user
chmod 644 "$CERT_DIR"/*.crt
chown -R lobsec:lobsec "$CERT_DIR"

echo "[mtls] Certificates ready at $CERT_DIR"
ls -la "$CERT_DIR"
