#!/bin/bash
# Weekly intelligence digest — sends via Telegram
# Triggered by lobsec-weekly-digest.timer (Monday 04:00 UTC / 08:00 GST)

LOG_DIR="/opt/lobsec/logs"
NODE_BIN="/opt/lobsec/plugins/lobsec-uae-re/dist/cli.js"

if [[ -f /opt/lobsec/.env ]]; then
    set -a
    source /opt/lobsec/.env
    set +a
fi

echo "[$(date -Iseconds)] Starting weekly digest" | tee -a "$LOG_DIR/digest.log"
node "$NODE_BIN" weekly-digest 2>&1 | tee -a "$LOG_DIR/digest.log"
EXIT_CODE=${PIPESTATUS[0]}
echo "[$(date -Iseconds)] Weekly digest finished (exit=$EXIT_CODE)" | tee -a "$LOG_DIR/digest.log"
exit $EXIT_CODE
