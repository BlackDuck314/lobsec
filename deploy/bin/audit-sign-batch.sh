#!/bin/bash
# audit-sign-batch.sh — Batch sign audit log entries with HSM RSA key.
# Reads unsigned entries from the audit log, computes a hash chain, and
# signs each batch with the HSM private key. Appends signed batches to
# a separate signed audit log for tamper-evidence verification.
#
# Run periodically via systemd timer or cron.
set -euo pipefail

export SOFTHSM2_CONF="${SOFTHSM2_CONF:-/opt/lobsec/boot/softhsm2.conf}"
SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so
TOKEN_LABEL=lobsec
KEY_LABEL=lobsec-audit-signing
HSM_PIN="${LOBSEC_HSM_PIN:?LOBSEC_HSM_PIN not set}"

AUDIT_LOG=/opt/lobsec/logs/audit.jsonl
SIGNED_LOG=/opt/lobsec/logs/audit-signed.jsonl
STATE_FILE=/opt/lobsec/logs/.audit-sign-state
LOCK_FILE=/opt/lobsec/run/audit-sign.lock

# ── Locking ─────────────────────────────────────────────────────────────────

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "Another audit-sign-batch is running, skipping"
  exit 0
fi

# ── State management ────────────────────────────────────────────────────────

# Track the last signed line number
if [ -f "$STATE_FILE" ]; then
  LAST_SIGNED=$(cat "$STATE_FILE")
else
  LAST_SIGNED=0
fi

# Count total lines in audit log
if [ ! -f "$AUDIT_LOG" ]; then
  echo "No audit log found at $AUDIT_LOG"
  exit 0
fi

TOTAL_LINES=$(wc -l < "$AUDIT_LOG")
if [ "$TOTAL_LINES" -le "$LAST_SIGNED" ]; then
  exit 0  # Nothing new to sign
fi

NEW_LINES=$((TOTAL_LINES - LAST_SIGNED))
echo "[audit-sign] ${NEW_LINES} new entries to sign (lines $((LAST_SIGNED + 1))-${TOTAL_LINES})"

# ── Read last chain hash ─────────────────────────────────────────────────────

if [ -f "$SIGNED_LOG" ] && [ -s "$SIGNED_LOG" ]; then
  PREV_HASH=$(tail -1 "$SIGNED_LOG" | python3 -c "import json,sys; print(json.load(sys.stdin).get('batchHash','0'*64))" 2>/dev/null || echo "$(printf '0%.0s' {1..64})")
else
  PREV_HASH=$(printf '0%.0s' {1..64})
fi

# ── Extract new entries and compute batch hash ───────────────────────────────

BATCH_FILE=$(mktemp /tmp/audit-batch.XXXXXX)
tail -n "$NEW_LINES" "$AUDIT_LOG" > "$BATCH_FILE"

# Compute SHA-256 hash of batch content + prevHash
BATCH_HASH=$(cat "$BATCH_FILE" <(echo "$PREV_HASH") | sha256sum | cut -d' ' -f1)

# ── Sign batch hash with HSM ─────────────────────────────────────────────────

HASH_FILE=$(mktemp /tmp/audit-hash.XXXXXX)
SIG_FILE=$(mktemp /tmp/audit-sig.XXXXXX)

echo -n "$BATCH_HASH" | xxd -r -p > "$HASH_FILE"

pkcs11-tool --module "$SOFTHSM_LIB" \
  --token-label "$TOKEN_LABEL" \
  --login --pin "$HSM_PIN" \
  --sign --mechanism RSA-PKCS \
  --label "$KEY_LABEL" \
  --input-file "$HASH_FILE" \
  --output-file "$SIG_FILE" 2>/dev/null

SIG_B64=$(base64 -w0 < "$SIG_FILE")

# ── Write signed batch record ─────────────────────────────────────────────────

ENTRY_COUNT=$(wc -l < "$BATCH_FILE")
TIMESTAMP=$(date -Iseconds)

python3 -c "
import json
batch = {
    'ts': '$TIMESTAMP',
    'type': 'signed_batch',
    'lineStart': $((LAST_SIGNED + 1)),
    'lineEnd': $TOTAL_LINES,
    'entryCount': $ENTRY_COUNT,
    'prevHash': '$PREV_HASH',
    'batchHash': '$BATCH_HASH',
    'hsmSignature': '$SIG_B64',
    'keyLabel': '$KEY_LABEL',
    'mechanism': 'RSA-PKCS'
}
print(json.dumps(batch, separators=(',', ':')))
" >> "$SIGNED_LOG"

# ── Update state ──────────────────────────────────────────────────────────────

echo "$TOTAL_LINES" > "$STATE_FILE"

# ── Cleanup ───────────────────────────────────────────────────────────────────

rm -f "$BATCH_FILE" "$HASH_FILE" "$SIG_FILE"
echo "[audit-sign] Signed batch of $ENTRY_COUNT entries (lines $((LAST_SIGNED + 1))-$TOTAL_LINES), hash=$BATCH_HASH"
