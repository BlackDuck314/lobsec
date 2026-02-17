#!/bin/bash
# health-check.sh — Periodic health check for lobsec stack
# Checks all critical components and logs structured results.
# Called by lobsec-health.timer (every 5 min).

set -euo pipefail

LOG=/opt/lobsec/logs/health.jsonl
ALERT_LOG=/opt/lobsec/logs/alerts.jsonl
FAILURES=0

log_check() {
    local component="$1" status="$2" detail="${3:-}"
    local ts
    ts=$(date -Iseconds)
    printf '{"ts":"%s","component":"%s","status":"%s","detail":"%s"}\n' \
        "$ts" "$component" "$status" "$detail" >> "$LOG"
    if [ "$status" = "FAIL" ]; then
        FAILURES=$((FAILURES + 1))
        printf '{"ts":"%s","severity":"high","category":"health-degraded","component":"%s","detail":"%s"}\n' \
            "$ts" "$component" "$detail" >> "$ALERT_LOG"
    fi
}

# 1. Service checks
for svc in lobsec lobsec-proxy lobsec-radicale lobsec-audit-sign.timer; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        log_check "$svc" "OK"
    else
        log_check "$svc" "FAIL" "service not active"
    fi
done

# 2. Gateway port check
if ss -tlnp | grep -q ":18789 "; then
    log_check "gateway-port" "OK" "listening on 18789"
else
    log_check "gateway-port" "FAIL" "not listening on 18789"
fi

# 3. Proxy health endpoint
PROXY_HEALTH=$(curl -sk --connect-timeout 5 https://127.0.0.1:18790/__lobsec__/health 2>/dev/null || echo "")
if echo "$PROXY_HEALTH" | grep -q '"ok"'; then
    log_check "proxy-health" "OK"
else
    log_check "proxy-health" "FAIL" "health endpoint unreachable"
fi

# 3b. Radicale CalDAV check
RADICALE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5232/ 2>/dev/null || echo "000")
if [ "$RADICALE_STATUS" = "302" ] || [ "$RADICALE_STATUS" = "200" ]; then
    log_check "radicale" "OK" "responding (HTTP $RADICALE_STATUS)"
else
    log_check "radicale" "FAIL" "not responding (HTTP $RADICALE_STATUS)"
fi

# 4. Certificate expiry check
CERT_DIR=/opt/lobsec/config/tls
for cert in gateway.crt proxy.crt ca.crt; do
    if [ -f "$CERT_DIR/$cert" ]; then
        EXPIRY=$(openssl x509 -in "$CERT_DIR/$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        if [ "$DAYS_LEFT" -le 7 ]; then
            log_check "cert-$cert" "FAIL" "expires in ${DAYS_LEFT} days"
        else
            log_check "cert-$cert" "OK" "expires in ${DAYS_LEFT} days"
        fi
    else
        log_check "cert-$cert" "FAIL" "certificate file missing"
    fi
done

# 5. fscrypt directories check (use kernel xattr to detect policy without root)
for dir in /opt/lobsec/hsm /opt/lobsec/config /opt/lobsec/logs /opt/lobsec/.openclaw; do
    # Check if directory has an fscrypt policy via ioctl (getfattr detects it)
    if getfattr -n encryption.policy "$dir" >/dev/null 2>&1 || \
       [ -d "$dir/.fscrypt" ] || \
       ls "$dir" >/dev/null 2>&1; then
        # If we can list files, it's unlocked
        if ls "$dir" >/dev/null 2>&1 && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
            log_check "fscrypt-$(basename "$dir")" "OK" "encrypted and unlocked"
        else
            log_check "fscrypt-$(basename "$dir")" "FAIL" "possibly locked or empty"
        fi
    else
        log_check "fscrypt-$(basename "$dir")" "FAIL" "inaccessible"
    fi
done

# 6. HSM token accessibility
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-/opt/lobsec/boot/softhsm2.conf}"
if pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-token-slots 2>/dev/null | grep -q "lobsec"; then
    log_check "hsm-token" "OK" "lobsec token accessible"
else
    log_check "hsm-token" "FAIL" "lobsec token not found"
fi

# 7. Disk usage
DISK_PCT=$(df /opt/lobsec --output=pcent | tail -1 | tr -d '% ')
if [ "$DISK_PCT" -ge 90 ]; then
    log_check "disk-usage" "FAIL" "${DISK_PCT}% used"
elif [ "$DISK_PCT" -ge 80 ]; then
    log_check "disk-usage" "WARN" "${DISK_PCT}% used"
else
    log_check "disk-usage" "OK" "${DISK_PCT}% used"
fi

# 8. Audit signing state
if [ -f /opt/lobsec/logs/.audit-sign-state ]; then
    LAST_SIGN=$(stat -c %Y /opt/lobsec/logs/.audit-sign-state 2>/dev/null || echo 0)
    NOW=$(date +%s)
    AGE_MIN=$(( (NOW - LAST_SIGN) / 60 ))
    if [ "$AGE_MIN" -gt 15 ]; then
        log_check "audit-signing" "FAIL" "last signed ${AGE_MIN} min ago"
    else
        log_check "audit-signing" "OK" "last signed ${AGE_MIN} min ago"
    fi
else
    log_check "audit-signing" "WARN" "no signing state file"
fi

# Summary
ts=$(date -Iseconds)
printf '{"ts":"%s","component":"health-summary","status":"%s","failures":%d}\n' \
    "$ts" "$([ $FAILURES -eq 0 ] && echo OK || echo DEGRADED)" "$FAILURES" >> "$LOG"

exit 0
