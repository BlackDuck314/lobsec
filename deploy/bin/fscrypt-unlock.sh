#!/bin/bash
# Unlock all fscrypt-encrypted lobsec directories at service startup.
# The fscrypt wrapping key lives in /opt/lobsec/boot/ (root:600, unencrypted).
# This is secure against offline disk theft since the boot dir permissions
# prevent unprivileged access, and the encrypted dirs use AES-256-XTS.
set -euo pipefail

KEY_FILE=/opt/lobsec/boot/fscrypt-key.bin

DIRS=(
  /opt/lobsec/hsm
  /opt/lobsec/config
  /opt/lobsec/logs
  /opt/lobsec/.openclaw
)

if [ ! -f "$KEY_FILE" ]; then
  echo "[fscrypt] ERROR: Key file not found at $KEY_FILE"
  exit 1
fi

unlocked=0
for dir in "${DIRS[@]}"; do
  status=$(fscrypt status "$dir" 2>/dev/null || echo "not encrypted")
  if echo "$status" | grep -q "Unlocked: No"; then
    echo "[fscrypt] Unlocking $dir"
    fscrypt unlock "$dir" --key="$KEY_FILE" --quiet 2>/dev/null || {
      echo "[fscrypt] ERROR: failed to unlock $dir"
      exit 1
    }
    unlocked=$((unlocked + 1))
  elif echo "$status" | grep -q "Unlocked: Yes"; then
    echo "[fscrypt] $dir already unlocked"
  else
    echo "[fscrypt] WARNING: $dir does not appear to be encrypted"
  fi
done

echo "[fscrypt] $unlocked directories unlocked"
