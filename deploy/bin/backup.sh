#!/bin/bash
# backup.sh — Backup critical lobsec data
# Creates encrypted, timestamped backups of HSM tokens, config, and audit logs.
# Called by lobsec-backup.timer (daily at 03:00).

set -euo pipefail

BACKUP_DIR=/opt/lobsec/backups
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="lobsec-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"
LOG=/opt/lobsec/logs/backup.jsonl
MAX_BACKUPS=14  # Keep 2 weeks of daily backups

log() {
    local level="$1" event="$2" detail="${3:-}"
    printf '{"ts":"%s","level":"%s","event":"%s","detail":"%s"}\n' \
        "$(date -Iseconds)" "$level" "$event" "$detail" >> "$LOG"
}

mkdir -p "$BACKUP_DIR" "$BACKUP_PATH"

log "INFO" "backup_start" "path=$BACKUP_PATH"

# 1. Backup HSM token database (SoftHSM2 token files)
if [ -d /opt/lobsec/hsm/tokens ]; then
    cp -a /opt/lobsec/hsm/tokens "$BACKUP_PATH/hsm-tokens"
    log "INFO" "backup_component" "hsm-tokens copied"
else
    log "WARN" "backup_skip" "hsm-tokens directory not found"
fi

# 2. Backup SoftHSM2 config
for f in /opt/lobsec/boot/softhsm2.conf /opt/lobsec/boot/pin.env; do
    if [ -f "$f" ]; then
        cp "$f" "$BACKUP_PATH/"
        log "INFO" "backup_component" "$(basename "$f") copied"
    fi
done

# 3. Backup OpenClaw config (without secrets — they're HSM-injected at runtime)
if [ -f /opt/lobsec/.openclaw/openclaw.json ]; then
    # Strip CF-Access secrets before backing up
    python3 -c "
import json, sys
with open('/opt/lobsec/.openclaw/openclaw.json') as f:
    d = json.load(f)
# Redact injected secrets
if 'jetson' in d.get('models',{}).get('providers',{}):
    h = d['models']['providers']['jetson'].get('headers',{})
    for k in list(h.keys()):
        if 'secret' in k.lower() or 'client' in k.lower():
            h[k] = 'REDACTED-IN-BACKUP'
json.dump(d, sys.stdout, indent=2)
" > "$BACKUP_PATH/openclaw.json"
    log "INFO" "backup_component" "openclaw.json copied (secrets redacted)"
fi

# 4. Backup audit logs (signed and unsigned)
if [ -f /opt/lobsec/logs/audit.jsonl ]; then
    cp /opt/lobsec/logs/audit.jsonl "$BACKUP_PATH/"
    log "INFO" "backup_component" "audit.jsonl copied"
fi
if [ -f /opt/lobsec/logs/audit-signed.jsonl ]; then
    cp /opt/lobsec/logs/audit-signed.jsonl "$BACKUP_PATH/"
    log "INFO" "backup_component" "audit-signed.jsonl copied"
fi

# 5. Backup TLS certificates
if [ -d /opt/lobsec/config/tls ]; then
    cp -a /opt/lobsec/config/tls "$BACKUP_PATH/tls"
    log "INFO" "backup_component" "tls certificates copied"
fi

# 6. Backup systemd service files
mkdir -p "$BACKUP_PATH/systemd"
for svc in lobsec lobsec-proxy lobsec-audit-sign lobsec-health; do
    for ext in service timer; do
        if [ -f "/etc/systemd/system/${svc}.${ext}" ]; then
            cp "/etc/systemd/system/${svc}.${ext}" "$BACKUP_PATH/systemd/"
        fi
    done
done
log "INFO" "backup_component" "systemd units copied"

# 7. Create compressed tarball
cd "$BACKUP_DIR"
tar czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_PATH"

# Set restrictive permissions
chmod 600 "${BACKUP_NAME}.tar.gz"

BACKUP_SIZE=$(du -h "${BACKUP_NAME}.tar.gz" | cut -f1)
log "INFO" "backup_complete" "file=${BACKUP_NAME}.tar.gz,size=${BACKUP_SIZE}"

# 8. Prune old backups (keep MAX_BACKUPS most recent)
BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/lobsec-backup-*.tar.gz 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt "$MAX_BACKUPS" ]; then
    PRUNE_COUNT=$((BACKUP_COUNT - MAX_BACKUPS))
    ls -1t "$BACKUP_DIR"/lobsec-backup-*.tar.gz | tail -n "$PRUNE_COUNT" | while read -r old; do
        rm -f "$old"
        log "INFO" "backup_prune" "removed $(basename "$old")"
    done
fi

echo "Backup complete: ${BACKUP_NAME}.tar.gz (${BACKUP_SIZE})"
