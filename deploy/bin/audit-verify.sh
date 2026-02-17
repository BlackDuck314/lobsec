#!/bin/bash
# audit-verify.sh — Verify the signed audit log chain.
# Checks each batch signature and hash chain integrity.
set -euo pipefail

export SOFTHSM2_CONF="${SOFTHSM2_CONF:-/opt/lobsec/boot/softhsm2.conf}"
SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so
TOKEN_LABEL=lobsec
KEY_LABEL=lobsec-audit-signing
HSM_PIN="${LOBSEC_HSM_PIN:?LOBSEC_HSM_PIN not set}"

AUDIT_LOG=/opt/lobsec/logs/audit.jsonl
SIGNED_LOG=/opt/lobsec/logs/audit-signed.jsonl

if [ ! -f "$SIGNED_LOG" ]; then
  echo "No signed audit log found"
  exit 1
fi

PREV_HASH=$(printf '0%.0s' {1..64})
BATCH_COUNT=0
ERRORS=0

while IFS= read -r line; do
  BATCH_COUNT=$((BATCH_COUNT + 1))

  # Parse batch record
  EXPECTED_PREV=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin)['prevHash'])")
  BATCH_HASH=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin)['batchHash'])")
  SIG_B64=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin)['hsmSignature'])")
  LINE_START=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin)['lineStart'])")
  LINE_END=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin)['lineEnd'])")
  ENTRY_COUNT=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin)['entryCount'])")

  # 1. Check chain linkage
  if [ "$EXPECTED_PREV" != "$PREV_HASH" ]; then
    echo "FAIL: batch $BATCH_COUNT — prevHash mismatch (expected $PREV_HASH, got $EXPECTED_PREV)"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # 2. Recompute batch hash from audit log lines
  BATCH_FILE=$(mktemp /tmp/audit-verify.XXXXXX)
  sed -n "${LINE_START},${LINE_END}p" "$AUDIT_LOG" > "$BATCH_FILE"
  COMPUTED_HASH=$(cat "$BATCH_FILE" <(echo "$PREV_HASH") | sha256sum | cut -d' ' -f1)
  rm -f "$BATCH_FILE"

  if [ "$COMPUTED_HASH" != "$BATCH_HASH" ]; then
    echo "FAIL: batch $BATCH_COUNT — hash mismatch (audit log lines $LINE_START-$LINE_END tampered)"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # 3. Verify HSM signature
  HASH_FILE=$(mktemp /tmp/audit-hash.XXXXXX)
  SIG_FILE=$(mktemp /tmp/audit-sig.XXXXXX)
  echo -n "$BATCH_HASH" | xxd -r -p > "$HASH_FILE"
  echo -n "$SIG_B64" | base64 -d > "$SIG_FILE"

  if pkcs11-tool --module "$SOFTHSM_LIB" \
    --token-label "$TOKEN_LABEL" \
    --login --pin "$HSM_PIN" \
    --verify --mechanism RSA-PKCS \
    --label "$KEY_LABEL" \
    --input-file "$HASH_FILE" \
    --signature-file "$SIG_FILE" 2>/dev/null | grep -q "Signature is valid"; then
    echo "OK: batch $BATCH_COUNT — $ENTRY_COUNT entries (lines $LINE_START-$LINE_END)"
  else
    echo "FAIL: batch $BATCH_COUNT — signature invalid"
    ERRORS=$((ERRORS + 1))
  fi

  rm -f "$HASH_FILE" "$SIG_FILE"
  PREV_HASH="$BATCH_HASH"

done < "$SIGNED_LOG"

echo ""
echo "Verified $BATCH_COUNT batches, $ERRORS errors"
[ "$ERRORS" -eq 0 ] && echo "CHAIN INTACT" || echo "CHAIN BROKEN"
exit "$ERRORS"
