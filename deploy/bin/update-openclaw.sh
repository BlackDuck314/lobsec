#!/bin/bash
# update-openclaw.sh — Safely update OpenClaw upstream
# Pre-flight checks, backup, pull, build, test, restart.
# Run as root (needs systemctl). OpenClaw repo owned by lobsec user.

set -euo pipefail

OPENCLAW_DIR=/opt/lobsec/openclaw
DATA_DIR=/opt/lobsec/.openclaw
CONFIG=$DATA_DIR/openclaw.json
LOG=/opt/lobsec/logs/update.jsonl
BACKUP_SCRIPT=/opt/lobsec/bin/backup.sh

log() {
    local level="$1" event="$2" detail="${3:-}"
    printf '{"ts":"%s","level":"%s","component":"update","event":"%s","detail":"%s"}\n' \
        "$(date -Iseconds)" "$level" "$event" "$detail" >> "$LOG"
}

die() {
    log "ERROR" "update_failed" "$1"
    echo "FATAL: $1" >&2
    exit 1
}

# Must run as root (for systemctl)
[[ $EUID -eq 0 ]] || die "Must run as root"

echo "=== OpenClaw Update ==="
echo ""

# 1. Record current version
CURRENT_VERSION=$(cd "$OPENCLAW_DIR" && sudo -u lobsec git describe --tags --always 2>/dev/null || echo "unknown")
echo "[1/8] Current version: $CURRENT_VERSION"
log "INFO" "update_start" "from=$CURRENT_VERSION"

# 2. Pre-flight: check services are healthy
echo "[2/8] Pre-flight health check..."
if ! systemctl is-active --quiet lobsec; then
    die "lobsec service is not running — fix before updating"
fi
if ! systemctl is-active --quiet lobsec-proxy; then
    die "lobsec-proxy service is not running — fix before updating"
fi
echo "       Services healthy."

# 3. Backup before update
echo "[3/8] Running backup..."
if [ -x "$BACKUP_SCRIPT" ]; then
    sudo -u lobsec "$BACKUP_SCRIPT" || die "Backup failed — aborting update"
    echo "       Backup complete."
else
    echo "       WARNING: Backup script not found, skipping."
    log "WARN" "update_backup_skip" "backup script not found"
fi

# 4. Save config snapshot (in case upstream changes schema)
CONFIG_SNAPSHOT="/tmp/openclaw-config-pre-update.json"
cp "$CONFIG" "$CONFIG_SNAPSHOT"
echo "[4/8] Config snapshot saved."

# 5. Fetch and check for updates
echo "[5/8] Fetching upstream..."
cd "$OPENCLAW_DIR"
sudo -u lobsec git fetch origin 2>&1 | head -5

LOCAL=$(sudo -u lobsec git rev-parse HEAD)
REMOTE=$(sudo -u lobsec git rev-parse origin/main 2>/dev/null || sudo -u lobsec git rev-parse origin/master)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "       Already up to date ($CURRENT_VERSION)."
    log "INFO" "update_noop" "already at $CURRENT_VERSION"
    rm -f "$CONFIG_SNAPSHOT"
    exit 0
fi

NEW_VERSION=$(sudo -u lobsec git describe --tags --always "$REMOTE" 2>/dev/null || echo "$REMOTE")
echo "       Update available: $CURRENT_VERSION -> $NEW_VERSION"

# 6. Stop services gracefully
echo "[6/8] Stopping services..."
systemctl stop lobsec-caddy 2>/dev/null || true
systemctl stop lobsec-proxy
systemctl stop lobsec
echo "       Services stopped."
log "INFO" "update_services_stopped" ""

# 7. Pull and rebuild
echo "[7/8] Pulling and building..."
cd "$OPENCLAW_DIR"
sudo -u lobsec git pull origin main --ff-only 2>&1 || {
    echo "       ERROR: Fast-forward merge failed. Manual intervention needed."
    echo "       Restarting services with old version..."
    systemctl start lobsec
    systemctl start lobsec-proxy
    systemctl start lobsec-caddy 2>/dev/null || true
    die "git pull --ff-only failed (possible local changes)"
}

# Install dependencies if package.json changed
if sudo -u lobsec git diff HEAD~1 --name-only | grep -q "package.json"; then
    echo "       package.json changed, installing dependencies..."
    sudo -u lobsec npm install --production 2>&1 | tail -3
fi

# Build if build script exists
if [ -f "$OPENCLAW_DIR/package.json" ] && grep -q '"build"' "$OPENCLAW_DIR/package.json"; then
    echo "       Building..."
    sudo -u lobsec npm run build 2>&1 | tail -5
fi

UPDATED_VERSION=$(sudo -u lobsec git describe --tags --always 2>/dev/null || echo "unknown")
echo "       Updated to: $UPDATED_VERSION"

# 8. Restart services
echo "[8/8] Restarting services..."
systemctl start lobsec
sleep 3

# Verify gateway is responding
if ! systemctl is-active --quiet lobsec; then
    echo "       ERROR: lobsec failed to start after update!"
    echo "       Rolling back..."
    sudo -u lobsec git checkout "$LOCAL"
    systemctl start lobsec
    systemctl start lobsec-proxy
    systemctl start lobsec-caddy 2>/dev/null || true
    die "Gateway failed to start with new version, rolled back to $CURRENT_VERSION"
fi

systemctl start lobsec-proxy
systemctl start lobsec-caddy 2>/dev/null || true
sleep 2

# Verify proxy is responding
if ! systemctl is-active --quiet lobsec-proxy; then
    echo "       WARNING: lobsec-proxy not running after update — check manually"
    log "WARN" "update_proxy_fail" "proxy not running after update"
fi

echo ""
echo "=== Update complete ==="
echo "  From: $CURRENT_VERSION"
echo "  To:   $UPDATED_VERSION"
echo ""
echo "  Config snapshot saved to: $CONFIG_SNAPSHOT"
echo "  Review upstream changelog: $OPENCLAW_DIR/CHANGELOG.md"
echo "  If issues arise, restore config: cp $CONFIG_SNAPSHOT $CONFIG"
echo ""
log "INFO" "update_complete" "from=$CURRENT_VERSION to=$UPDATED_VERSION"
