#!/bin/bash
# hsm-wipe-credentials.sh — Wipe runtime credentials on service stop
# Called by systemd ExecStopPost to remove secrets from disk.

set -euo pipefail

ENV_FILE=/opt/lobsec/.openclaw/.env
CONFIG_FILE=/opt/lobsec/.openclaw/openclaw.json
HSM_LOG=/opt/lobsec/logs/hsm-access.log

hsm_log() {
    local level="$1" event="$2" detail="${3:-}"
    local ts
    ts=$(date -Iseconds)
    printf '{"ts":"%s","level":"%s","event":"%s","detail":"%s"}\n' \
        "$ts" "$level" "$event" "$detail" >> "$HSM_LOG" 2>/dev/null || true
}

hsm_log "INFO" "wipe_start" "pid=$$"

# Wipe .env files containing extracted credentials
rm -f "$ENV_FILE"
rm -f /opt/lobsec/.openclaw/.env.proxy

# CF-Access headers are now in .env.proxy (wiped above), not in openclaw.json

# Wipe Radicale htpasswd (regenerated at startup from HSM)
rm -f /opt/lobsec/config/radicale-users

hsm_log "INFO" "wipe_complete" "env_removed=true,headers_cleared=true,htpasswd_removed=true"
echo "Runtime credentials wiped ($(date -Iseconds))"
