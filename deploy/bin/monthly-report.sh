#!/bin/bash
# Monthly intelligence report — sends via Telegram
# Triggered by lobsec-monthly-report.timer (26th 03:00 UTC / 07:00 GST)

LOG_DIR="/opt/lobsec/logs"
NODE_BIN="/opt/lobsec/plugins/lobsec-uae-re/dist/cli.js"

if [[ -f /opt/lobsec/.env ]]; then
    set -a
    source /opt/lobsec/.env
    set +a
fi

echo "[$(date -Iseconds)] Starting monthly report" | tee -a "$LOG_DIR/digest.log"
node "$NODE_BIN" monthly-report 2>&1 | tee -a "$LOG_DIR/digest.log"
EXIT_CODE=${PIPESTATUS[0]}
echo "[$(date -Iseconds)] Monthly report finished (exit=$EXIT_CODE)" | tee -a "$LOG_DIR/digest.log"
exit $EXIT_CODE
