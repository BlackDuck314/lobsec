#!/bin/bash
# Lock all fscrypt-encrypted lobsec directories at service shutdown.
set -euo pipefail

DIRS=(
  /opt/lobsec/.openclaw
  /opt/lobsec/logs
  /opt/lobsec/config
  /opt/lobsec/hsm
)

for dir in "${DIRS[@]}"; do
  if fscrypt status "$dir" 2>/dev/null | grep -q "Unlocked: Yes"; then
    echo "[fscrypt] Locking $dir"
    fscrypt lock "$dir" 2>/dev/null || \
      echo "[fscrypt] WARNING: failed to lock $dir (files may still be open)"
  fi
done

# Ensure key is wiped from tmpfs
rm -f /run/lobsec/fscrypt-key.bin
echo "[fscrypt] Lock complete"
