#!/bin/bash
# Proactive anomaly and failure alerting
# Triggered by lobsec-alerts.timer (daily 20:00 UTC / 00:00 GST)

LOG_DIR="/opt/lobsec/logs"
NODE_BIN="/opt/lobsec/plugins/lobsec-uae-re/dist/cli.js"

if [[ -f /opt/lobsec/.env ]]; then
    set -a
    source /opt/lobsec/.env
    set +a
fi

echo "[$(date -Iseconds)] Starting alert check" | tee -a "$LOG_DIR/alerts.log"
node "$NODE_BIN" check-alerts 2>&1 | tee -a "$LOG_DIR/alerts.log"
EXIT_CODE=${PIPESTATUS[0]}
echo "[$(date -Iseconds)] Alert check finished (exit=$EXIT_CODE)" | tee -a "$LOG_DIR/alerts.log"
exit $EXIT_CODE
