#!/bin/bash
set -euo pipefail

# LUKS2 Encryption Setup for /opt/lobsec
# This script documents the steps used to create the encrypted volume.
# It was executed on 2026-03-31 and is retained for reference/recovery.
#
# Volume: /dev/mapper/lobsec-crypt (15G, LUKS2, aes-xts-plain64)
# Mount:  /opt/lobsec (ext4, noatime)
# Unlock: Auto via keyfile at /root/.luks/lobsec.key
# Backup: Passphrase stored at /root/.luks/backup-passphrase.txt
#
# To manually unlock and mount:
#   cryptsetup open --type luks2 --key-file /root/.luks/lobsec.key \
#     /dev/ubuntu-vg/lobsec-data lobsec-crypt
#   mount /dev/mapper/lobsec-crypt /opt/lobsec
#
# Recovery from backup:
#   cryptsetup open --type luks2 /dev/ubuntu-vg/lobsec-data lobsec-crypt
#   (enter backup passphrase from /root/.luks/backup-passphrase.txt)

LV_SIZE="15G"
VG_NAME="ubuntu-vg"
LV_NAME="lobsec-data"
DM_NAME="lobsec-crypt"
MOUNT_POINT="/opt/lobsec"
KEY_DIR="/root/.luks"
KEY_FILE="${KEY_DIR}/lobsec.key"
BACKUP_DIR="/opt/lobsec.backup"

echo "=== LUKS2 Setup for ${MOUNT_POINT} ==="
echo ""

# Step 0: Create keyfile for auto-unlock
echo "[0/7] Creating keyfile..."
mkdir -p "${KEY_DIR}"
chmod 700 "${KEY_DIR}"
if [[ ! -f "${KEY_FILE}" ]]; then
  dd if=/dev/urandom of="${KEY_FILE}" bs=4096 count=1 2>/dev/null
  chmod 400 "${KEY_FILE}"
  echo "  Keyfile created at ${KEY_FILE}"
else
  echo "  Keyfile already exists at ${KEY_FILE}"
fi

# Step 1: Stop all lobsec services
echo "[1/7] Stopping lobsec services..."
TIMERS=(lobsec-weekly-digest lobsec-monthly-report lobsec-alerts
        lobsec-collect-daily lobsec-collect-weekly lobsec-collect-monthly
        lobsec-collect-quarterly lobsec-uae-analyze lobsec-health
        lobsec-backup lobsec-examy-test lobsec-examy-cleanup)
for timer in "${TIMERS[@]}"; do
  systemctl stop "${timer}.timer" 2>/dev/null || true
done
systemctl stop lobsec-scraper lobsec-proxy lobsec 2>/dev/null || true
echo "  All services stopped"

# Step 2: Backup current data
echo "[2/7] Backing up ${MOUNT_POINT} to ${BACKUP_DIR}..."
if [[ -d "${BACKUP_DIR}" ]]; then
  echo "  Backup directory already exists -- skipping"
else
  cp -a "${MOUNT_POINT}" "${BACKUP_DIR}"
  echo "  Backup complete: $(du -sh "${BACKUP_DIR}" | cut -f1)"
fi

# Step 3: Create LVM logical volume
echo "[3/7] Creating LV ${VG_NAME}/${LV_NAME} (${LV_SIZE})..."
if lvs "${VG_NAME}/${LV_NAME}" &>/dev/null; then
  echo "  LV already exists -- skipping"
else
  lvcreate -L "${LV_SIZE}" -n "${LV_NAME}" "${VG_NAME}"
  echo "  LV created"
fi

# Step 4: LUKS2 format with keyfile
echo "[4/7] Formatting with LUKS2..."
if cryptsetup isLuks "/dev/${VG_NAME}/${LV_NAME}" 2>/dev/null; then
  echo "  Already LUKS formatted -- skipping"
else
  cryptsetup luksFormat --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha256 \
    --key-file "${KEY_FILE}" \
    --batch-mode \
    "/dev/${VG_NAME}/${LV_NAME}"
  echo "  LUKS2 formatted"

  # Add backup passphrase
  echo "  Adding backup passphrase..."
  PASSPHRASE=$(openssl rand -base64 32)
  echo "${PASSPHRASE}" | cryptsetup luksAddKey \
    --key-file "${KEY_FILE}" \
    "/dev/${VG_NAME}/${LV_NAME}"
  echo "${PASSPHRASE}" > /root/.luks/backup-passphrase.txt
  chmod 400 /root/.luks/backup-passphrase.txt
  echo "  Backup passphrase saved to /root/.luks/backup-passphrase.txt"
fi

# Step 5: Open and format ext4
echo "[5/7] Opening LUKS volume and formatting ext4..."
if [[ -e "/dev/mapper/${DM_NAME}" ]]; then
  echo "  Already open"
else
  cryptsetup open --type luks2 --key-file "${KEY_FILE}" \
    "/dev/${VG_NAME}/${LV_NAME}" "${DM_NAME}"
fi

if ! blkid "/dev/mapper/${DM_NAME}" | grep -q ext4; then
  mkfs.ext4 -L lobsec-data "/dev/mapper/${DM_NAME}"
  echo "  ext4 formatted"
else
  echo "  Already ext4"
fi

# Step 6: Mount and migrate data
echo "[6/7] Migrating data..."
TEMP_MOUNT="/mnt/lobsec-crypt"
mkdir -p "${TEMP_MOUNT}"
mount "/dev/mapper/${DM_NAME}" "${TEMP_MOUNT}"

rsync -aHAX "${MOUNT_POINT}/" "${TEMP_MOUNT}/"

umount "${TEMP_MOUNT}"
mv "${MOUNT_POINT}" "${MOUNT_POINT}.old"
mkdir -p "${MOUNT_POINT}"
mount "/dev/mapper/${DM_NAME}" "${MOUNT_POINT}"

echo "  Data migrated: $(du -sh "${MOUNT_POINT}" | cut -f1)"
chown lobsec:lobsec "${MOUNT_POINT}"

# Step 7: Configure auto-unlock at boot
echo "[7/7] Configuring auto-unlock..."

UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/${LV_NAME}")
if ! grep -q "${DM_NAME}" /etc/crypttab 2>/dev/null; then
  echo "${DM_NAME} UUID=${UUID} ${KEY_FILE} luks" >> /etc/crypttab
  echo "  Added to /etc/crypttab"
fi

if ! grep -q "${MOUNT_POINT}" /etc/fstab; then
  echo "/dev/mapper/${DM_NAME} ${MOUNT_POINT} ext4 defaults,noatime 0 2" >> /etc/fstab
  echo "  Added to /etc/fstab"
fi

echo ""
echo "=== LUKS2 Setup Complete ==="
echo ""
echo "Encrypted volume: /dev/mapper/${DM_NAME}"
echo "Mount point: ${MOUNT_POINT}"
echo "Auto-unlock: via ${KEY_FILE}"
echo "Backup passphrase: /root/.luks/backup-passphrase.txt"
echo ""
echo "Next steps:"
echo "  1. Verify: sudo cryptsetup status ${DM_NAME}"
echo "  2. Start services: sudo systemctl start lobsec-proxy lobsec lobsec-scraper"
echo "  3. Enable timers"
echo "  4. Test: send a Telegram message to verify bot works"
echo "  5. Clean up: sudo rm -rf ${MOUNT_POINT}.old ${BACKUP_DIR}"
echo "     (Only after thorough verification!)"
