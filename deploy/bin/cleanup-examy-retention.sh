#!/bin/bash
# cleanup-examy-retention.sh -- Delete Examy screenshots and results older than 30 days.
# Baselines directory is exempt (visual regression references must persist).
# Run weekly via lobsec-examy-cleanup.timer.
set -euo pipefail

EXAMY_DIR=/opt/lobsec/logs/examy
RETENTION_DAYS=30
LOG_PREFIX="[examy-cleanup]"

echo "$LOG_PREFIX Starting retention cleanup (${RETENTION_DAYS}-day threshold)"

# Ensure directory exists
if [ ! -d "$EXAMY_DIR" ]; then
    echo "$LOG_PREFIX Directory $EXAMY_DIR does not exist, nothing to clean"
    exit 0
fi

# Count files before cleanup
BEFORE=$(find "$EXAMY_DIR" -maxdepth 1 \( -name "*.png" -o -name "result-*.json" \) -type f -mtime +${RETENTION_DAYS} | wc -l)

# Delete screenshots and result JSONs older than 30 days
# -maxdepth 1 ensures baselines/ subdirectory is NOT touched
find "$EXAMY_DIR" -maxdepth 1 \( -name "*.png" -o -name "result-*.json" \) -type f -mtime +${RETENTION_DAYS} -delete

# Count files remaining
REMAINING=$(find "$EXAMY_DIR" -maxdepth 1 \( -name "*.png" -o -name "result-*.json" \) -type f | wc -l)

echo "$LOG_PREFIX Deleted ${BEFORE} files older than ${RETENTION_DAYS} days, ${REMAINING} files remaining"
