#!/bin/bash
# watchdog.sh — Service watchdog for the lobsec stack
# Checks critical services every 30s and restarts any that are down.
# Runs as root via lobsec-watchdog.timer.

set -uo pipefail

ALERT_LOG=/opt/lobsec/logs/alerts.jsonl
SERVICES=(lobsec lobsec-proxy lobsec-radicale)
TIMERS=(lobsec-audit-sign.timer lobsec-health.timer lobsec-watchdog.timer)
GRACE_SECONDS=120  # Don't check ports until service has been active this long
RESTARTED=0

alert() {
    local ts component detail
    ts=$(date -Iseconds)
    component="$1"
    detail="$2"
    printf '{"ts":"%s","severity":"high","category":"watchdog","component":"%s","detail":"%s"}\n' \
        "$ts" "$component" "$detail" >> "$ALERT_LOG" 2>/dev/null
}

# How long has a service been active (seconds)? Returns 0 if not active.
uptime_seconds() {
    local svc="$1"
    local since
    since=$(systemctl show -p ActiveEnterTimestamp --value "$svc" 2>/dev/null)
    [ -z "$since" ] && echo 0 && return
    local since_epoch now_epoch
    since_epoch=$(date -d "$since" +%s 2>/dev/null) || { echo 0; return; }
    now_epoch=$(date +%s)
    echo $(( now_epoch - since_epoch ))
}

# Check services
for svc in "${SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        if systemctl list-unit-files "$svc.service" --no-pager 2>/dev/null | grep -q "$svc"; then
            alert "$svc" "service down — restarting"
            systemctl start "$svc" 2>/dev/null
            RESTARTED=$((RESTARTED + 1))
        fi
    fi
done

# Check timers
for tmr in "${TIMERS[@]}"; do
    if ! systemctl is-active --quiet "$tmr" 2>/dev/null; then
        if systemctl list-unit-files "$tmr" --no-pager 2>/dev/null | grep -q "$tmr"; then
            alert "$tmr" "timer inactive — restarting"
            systemctl start "$tmr" 2>/dev/null
            RESTARTED=$((RESTARTED + 1))
        fi
    fi
done

# Port checks — only after the service has been active for GRACE_SECONDS
# (gateway takes ~90s to fully initialize: plugins, Telegram, etc.)
if systemctl is-active --quiet lobsec 2>/dev/null; then
    age=$(uptime_seconds lobsec)
    if [ "$age" -ge "$GRACE_SECONDS" ]; then
        if ! ss -tlnp 2>/dev/null | grep -q ":18789 "; then
            alert "lobsec" "service active ${age}s but not listening on 18789 — restarting"
            systemctl restart lobsec 2>/dev/null
            RESTARTED=$((RESTARTED + 1))
        fi
    fi
fi

if systemctl is-active --quiet lobsec-proxy 2>/dev/null; then
    age=$(uptime_seconds lobsec-proxy)
    if [ "$age" -ge "$GRACE_SECONDS" ]; then
        if ! ss -tlnp 2>/dev/null | grep -q ":18790 "; then
            alert "lobsec-proxy" "service active ${age}s but not listening on 18790 — restarting"
            systemctl restart lobsec-proxy 2>/dev/null
            RESTARTED=$((RESTARTED + 1))
        fi
    fi
fi

exit 0
