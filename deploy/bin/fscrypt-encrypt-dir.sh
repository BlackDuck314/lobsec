#!/bin/bash
# Encrypt an existing directory in-place using fscrypt
# Usage: fscrypt-encrypt-dir.sh <DIR> <KEY_FILE> <PROTECTOR_NAME>
set -euo pipefail

DIR="$1"
KEY_FILE="$2"
PROT_NAME="${3:-lobsec-hsm}"
PARENT=$(dirname "$DIR")
BASE=$(basename "$DIR")
TMP_DIR="${PARENT}/.${BASE}.encrypt-tmp"
BACKUP_DIR="${PARENT}/.${BASE}.encrypt-backup"

if [ ! -d "$DIR" ]; then
  echo "ERROR: $DIR does not exist"
  exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
  echo "ERROR: Key file $KEY_FILE does not exist"
  exit 1
fi

echo "==> Encrypting $DIR"
echo "    Tmp:    $TMP_DIR"
echo "    Backup: $BACKUP_DIR"

# Step 1: Create empty directory for encryption
rm -rf "$TMP_DIR"
mkdir -m 700 "$TMP_DIR"

# Step 2: Encrypt the empty directory with raw_key protector
echo "    Setting up fscrypt encryption..."
echo | fscrypt encrypt "$TMP_DIR" --source=raw_key --name="$PROT_NAME" --key="$KEY_FILE" --no-recovery --quiet 2>&1 || {
  # If protector already exists, reuse it
  echo "    Trying with existing protector..."
  PROT_ID=$(fscrypt status / 2>/dev/null | grep "$PROT_NAME" | awk '{print $1}')
  if [ -n "$PROT_ID" ]; then
    fscrypt encrypt "$TMP_DIR" --protector="/:$PROT_ID" --key="$KEY_FILE" --no-recovery --quiet 2>&1
  else
    echo "ERROR: Failed to set up encryption"
    rm -rf "$TMP_DIR"
    exit 1
  fi
}

# Step 3: Copy data into encrypted directory
echo "    Copying data..."
cp -a "$DIR"/. "$TMP_DIR"/ 2>/dev/null || true

# Step 4: Swap directories
echo "    Swapping directories..."
mv "$DIR" "$BACKUP_DIR"
mv "$TMP_DIR" "$DIR"

# Preserve ownership
chown lobsec:lobsec "$DIR"

echo "    Done. Backup at $BACKUP_DIR"
echo "    Verify, then remove: rm -rf $BACKUP_DIR"
