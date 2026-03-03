#!/bin/bash
# ╔═══════════════════════════════════════════════════════════════════╗
# ║  lobsec Security Claims Acid Test                               ║
# ║  Verifies 17 security claims with concrete PASS/FAIL evidence   ║
# ║  Usage: sudo bash security-audit.sh [--destructive]             ║
# ╚═══════════════════════════════════════════════════════════════════╝
set -uo pipefail

DESTRUCTIVE=false
[[ "${1:-}" == "--destructive" ]] && DESTRUCTIVE=true

# ── Counters & results ──────────────────────────────────────────────
PASS=0 FAIL=0 SKIP=0
declare -a results=()

pass() { ((PASS++)); results+=("PASS|$1|"); printf "  \e[32mPASS\e[0m  %s\n" "$1"; }
fail() { ((FAIL++)); results+=("FAIL|$1|$2"); printf "  \e[31mFAIL\e[0m  %s — %s\n" "$1" "$2"; }
skip() { ((SKIP++)); results+=("SKIP|$1|$2"); printf "  \e[33mSKIP\e[0m  %s — %s\n" "$1" "$2"; }

# ── Shared constants ────────────────────────────────────────────────
SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so
SOFTHSM2_CONF=/opt/lobsec/boot/softhsm2.conf
TOKEN_LABEL=lobsec
ENV_FILE=/opt/lobsec/.openclaw/.env
PROXY_ENV_FILE=/opt/lobsec/.openclaw/.env.proxy
AUTH_PROFILES=/opt/lobsec/.openclaw/agents/main/agent/auth-profiles.json
OPENCLAW_JSON=/opt/lobsec/.openclaw/openclaw.json
AUDIT_LOG=/opt/lobsec/logs/audit.jsonl
REDACTOR_JS=/opt/lobsec/plugins/lobsec-security/dist/credential-redactor.js
EGRESS_JS=/opt/lobsec/proxy/egress-firewall.js

# Load HSM PIN (needed for HSM tests)
if [[ -f /opt/lobsec/boot/pin.env ]]; then
    source /opt/lobsec/boot/pin.env
fi
HSM_PIN="${LOBSEC_HSM_PIN:-}"

printf "\n\e[1m══════════════════════════════════════════════════════════════\e[0m\n"
printf "\e[1m  lobsec Security Claims Acid Test\e[0m\n"
printf "\e[1m  %s  destructive=%s\e[0m\n" "$(date -Iseconds)" "$DESTRUCTIVE"
printf "\e[1m══════════════════════════════════════════════════════════════\e[0m\n\n"

# ════════════════════════════════════════════════════════════════════
# Test 1: HSM stores all 11 data objects + 1 keypair
# ════════════════════════════════════════════════════════════════════
test_hsm_objects() {
    local claim="HSM stores 11 data objects + 1 keypair"
    if [[ -z "$HSM_PIN" ]]; then
        fail "$claim" "LOBSEC_HSM_PIN not available"
        return
    fi

    local hsm_output
    hsm_output=$(sudo -u lobsec \
        SOFTHSM2_CONF="$SOFTHSM2_CONF" \
        pkcs11-tool --module "$SOFTHSM_LIB" \
        --token-label "$TOKEN_LABEL" \
        --login --pin "$HSM_PIN" \
        --list-objects 2>&1) || true

    local data_count priv_count
    data_count=$(echo "$hsm_output" | grep -c "^Data object" || true)
    priv_count=$(echo "$hsm_output" | grep -c "^Private Key Object" || true)

    if [[ "$data_count" -eq 11 && "$priv_count" -eq 1 ]]; then
        pass "$claim"
    else
        fail "$claim" "data=$data_count (want 11), privkey=$priv_count (want 1)"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 2: OpenClaw never sees real Anthropic key
# ════════════════════════════════════════════════════════════════════
test_no_real_keys() {
    local claim="OpenClaw config has no real Anthropic key"

    if [[ ! -f "$PROXY_ENV_FILE" ]]; then
        skip "$claim" "proxy .env not present (service stopped?)"
        return
    fi

    # Get real key prefix from proxy .env (first 30 chars, strip quotes)
    local real_key
    real_key=$(grep '^ANTHROPIC_API_KEY=' "$PROXY_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"' | cut -c1-30)
    if [[ -z "$real_key" || ! "$real_key" =~ ^sk-ant- ]]; then
        skip "$claim" "proxy .env has no sk-ant-* key to test against"
        return
    fi

    local found=0
    for f in "$AUTH_PROFILES" "$OPENCLAW_JSON" "$ENV_FILE"; do
        if [[ -f "$f" ]] && grep -qF "$real_key" "$f"; then
            ((found++))
        fi
    done

    if [[ "$found" -eq 0 ]]; then
        pass "$claim"
    else
        fail "$claim" "real key prefix found in $found gateway config file(s)"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 3: Gateway gets proxy token, proxy gets real key
# ════════════════════════════════════════════════════════════════════
test_token_isolation() {
    local claim="Gateway has proxy token, proxy has real key"

    if [[ ! -f "$ENV_FILE" || ! -f "$PROXY_ENV_FILE" ]]; then
        skip "$claim" ".env files not present (service stopped?)"
        return
    fi

    local gw_key proxy_key
    gw_key=$(grep '^ANTHROPIC_API_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"')
    proxy_key=$(grep '^ANTHROPIC_API_KEY=' "$PROXY_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"')

    local ok=true reason=""
    if [[ "$gw_key" =~ ^sk-ant- ]]; then
        ok=false
        reason="gateway .env has real sk-ant-* key"
    fi
    if [[ ! "$proxy_key" =~ ^sk-ant- ]]; then
        ok=false
        reason="${reason:+$reason; }proxy .env does NOT have sk-ant-* key"
    fi

    if $ok; then
        pass "$claim"
    else
        fail "$claim" "$reason"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 4: Credential .env files wiped on service stop (destructive)
# ════════════════════════════════════════════════════════════════════
test_wipe_on_stop() {
    local claim="Credential .env files wiped on service stop"

    if ! $DESTRUCTIVE; then
        skip "$claim" "requires --destructive flag"
        return
    fi

    # Stop service
    systemctl stop lobsec lobsec-proxy 2>/dev/null
    sleep 2

    local ok=true reason=""
    if [[ -f "$ENV_FILE" ]]; then
        ok=false
        reason="$ENV_FILE still exists after stop"
    fi
    if [[ -f "$PROXY_ENV_FILE" ]]; then
        ok=false
        reason="${reason:+$reason; }$PROXY_ENV_FILE still exists after stop"
    fi

    # Restart services
    systemctl start lobsec 2>/dev/null
    # Wait for gateway to come up
    local tries=0
    while ! ss -tlnp | grep -q ':18789' && [[ $tries -lt 30 ]]; do
        sleep 1
        ((tries++))
    done

    if $ok; then
        pass "$claim"
    else
        fail "$claim" "$reason"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 5: fscrypt encrypts 4 directories
# ════════════════════════════════════════════════════════════════════
test_fscrypt() {
    local claim="fscrypt encrypts .openclaw, hsm, config, logs"
    local dirs=(.openclaw hsm config logs)
    local missing=()

    for d in "${dirs[@]}"; do
        local path="/opt/lobsec/$d"
        local fout
        fout=$(fscrypt status "$path" 2>&1 || true)
        if ! echo "$fout" | grep -q "encrypted with fscrypt"; then
            missing+=("$d")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        pass "$claim"
    else
        fail "$claim" "not encrypted: ${missing[*]}"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 6: Credential redactor catches API key patterns
# ════════════════════════════════════════════════════════════════════
test_redactor() {
    local claim="Credential redactor catches sk-ant-* pattern"

    if [[ ! -f "$REDACTOR_JS" ]]; then
        fail "$claim" "redactor not found at $REDACTOR_JS"
        return
    fi

    local output
    output=$(node -e "
        const { CREDENTIAL_PATTERNS } = require('$REDACTOR_JS');
        const fake = 'key is sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAA here';
        let result = fake;
        for (const p of CREDENTIAL_PATTERNS) {
            result = result.replace(p.pattern, p.replacement);
        }
        process.stdout.write(result);
    " 2>&1)

    if [[ "$output" == *"[ANTHROPIC-KEY-REDACTED]"* && "$output" != *"sk-ant-api03"* ]]; then
        pass "$claim"
    else
        fail "$claim" "output: $output"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 7: Egress firewall blocks unauthorized ports
# ════════════════════════════════════════════════════════════════════
test_egress_firewall() {
    local claim="Egress firewall blocks unauthorized ports"

    # Verify nftables rule exists for uid 995
    local nft_bin
    nft_bin=$(command -v nft 2>/dev/null || echo /usr/sbin/nft)
    local nft_out
    nft_out=$("$nft_bin" list ruleset 2>/dev/null || true)
    if ! echo "$nft_out" | grep -q 'skuid.*995'; then
        fail "$claim" "no nftables rule for uid 995 (lobsec)"
        return
    fi

    # Test 1: port 443 should work (allowed)
    local ok443
    ok443=$(sudo -u lobsec curl -sk --connect-timeout 5 -o /dev/null -w '%{http_code}' \
        https://api.anthropic.com/v1/models 2>&1) || true

    # Test 2: port 8080 should be blocked
    local blocked
    blocked=true
    if sudo -u lobsec curl --connect-timeout 3 -s http://93.184.216.34:8080/ 2>&1 >/dev/null; then
        blocked=false
    fi

    if [[ "$ok443" =~ ^[0-9]+$ && "$blocked" == "true" ]]; then
        pass "$claim"
    else
        fail "$claim" "443 status=$ok443, port 8080 blocked=$blocked"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 8: Gateway binds loopback only
# ════════════════════════════════════════════════════════════════════
test_gateway_loopback() {
    local claim="Gateway binds loopback only (18789)"
    local listen
    listen=$(ss -tlnp | grep ':18789')

    if [[ -z "$listen" ]]; then
        fail "$claim" "port 18789 not listening"
        return
    fi

    if echo "$listen" | grep -qE '0\.0\.0\.0:18789|\*:18789'; then
        fail "$claim" "bound to 0.0.0.0 or wildcard"
    elif echo "$listen" | grep -qE '127\.0\.0\.1:18789|\[::1\]:18789'; then
        pass "$claim"
    else
        fail "$claim" "unexpected bind: $listen"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 9: Proxy binds loopback only
# ════════════════════════════════════════════════════════════════════
test_proxy_loopback() {
    local claim="Proxy binds loopback only (18790)"
    local listen
    listen=$(ss -tlnp | grep ':18790')

    if [[ -z "$listen" ]]; then
        fail "$claim" "port 18790 not listening"
        return
    fi

    if echo "$listen" | grep -qE '0\.0\.0\.0:18790|\*:18790'; then
        fail "$claim" "bound to 0.0.0.0 or wildcard"
    elif echo "$listen" | grep -q '127\.0\.0\.1:18790'; then
        pass "$claim"
    else
        fail "$claim" "unexpected bind: $listen"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 10: Proxy rejects unauthenticated requests
# ════════════════════════════════════════════════════════════════════
test_proxy_auth() {
    local claim="Proxy rejects unauthenticated requests"

    # Without token → should get 401 or 403
    local no_auth_code
    no_auth_code=$(curl -sk -X POST https://127.0.0.1:18790/v1/messages \
        -H 'Content-Type: application/json' \
        -d '{"model":"test","messages":[]}' \
        -o /dev/null -w '%{http_code}' 2>&1)

    # With valid token → should NOT get 401/403
    local token=""
    if [[ -f "$ENV_FILE" ]]; then
        token=$(grep '^OPENCLAW_GATEWAY_TOKEN=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"')
    fi

    if [[ "$no_auth_code" == "401" || "$no_auth_code" == "403" ]]; then
        if [[ -n "$token" ]]; then
            local auth_code
            auth_code=$(curl -sk -X POST https://127.0.0.1:18790/v1/messages \
                -H 'Content-Type: application/json' \
                -H "x-api-key: $token" \
                -d '{"model":"test","messages":[]}' \
                -o /dev/null -w '%{http_code}' 2>&1)
            if [[ "$auth_code" != "401" && "$auth_code" != "403" ]]; then
                pass "$claim"
            else
                fail "$claim" "rejected even with valid token (status=$auth_code)"
            fi
        else
            pass "$claim"  # At least unauthenticated is blocked
        fi
    else
        fail "$claim" "unauthenticated request got status=$no_auth_code (expected 401/403)"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 11: systemd hardening directives active
# ════════════════════════════════════════════════════════════════════
test_systemd_hardening() {
    local claim="systemd hardening: NoNewPriv, ProtectSystem, CapBound"
    local issues=()

    for svc in lobsec lobsec-proxy; do
        local nnp prot cap
        nnp=$(systemctl show "$svc" -p NoNewPrivileges --value 2>/dev/null)
        prot=$(systemctl show "$svc" -p ProtectSystem --value 2>/dev/null)
        cap=$(systemctl show "$svc" -p CapabilityBoundingSet --value 2>/dev/null)

        [[ "$nnp" != "yes" ]] && issues+=("$svc: NoNewPrivileges=$nnp")
        [[ "$prot" != "strict" ]] && issues+=("$svc: ProtectSystem=$prot")
        # CapabilityBoundingSet should be empty when no capabilities are granted
        [[ -n "$cap" ]] && issues+=("$svc: CapabilityBoundingSet=$cap")
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        pass "$claim"
    else
        fail "$claim" "${issues[*]}"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 12: Audit log records LLM requests
# ════════════════════════════════════════════════════════════════════
test_audit_logging() {
    local claim="Audit log records LLM requests"

    if [[ ! -f "$AUDIT_LOG" ]]; then
        fail "$claim" "audit log not found at $AUDIT_LOG"
        return
    fi

    # Check that audit log has llm_request entries from today
    local today
    today=$(date -u +%Y-%m-%d)
    local recent
    recent=$(tail -20 "$AUDIT_LOG" | grep -c "\"event\":\"llm_request\"" || true)
    local today_entries
    today_entries=$(grep -c "$today" "$AUDIT_LOG" || true)

    if [[ "$recent" -gt 0 && "$today_entries" -gt 0 ]]; then
        pass "$claim"
    elif [[ "$recent" -gt 0 ]]; then
        pass "$claim"  # Has llm_request entries, just not from today
    else
        fail "$claim" "no llm_request entries found (recent=$recent, today=$today_entries)"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 13: Audit signing timer is active
# ════════════════════════════════════════════════════════════════════
test_audit_timer() {
    local claim="Audit signing timer is active"
    local status
    status=$(systemctl is-active lobsec-audit-sign.timer 2>/dev/null)

    if [[ "$status" == "active" ]]; then
        pass "$claim"
    else
        fail "$claim" "timer status: $status"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 14: File permissions — secrets mode 600, HSM dir 700
# ════════════════════════════════════════════════════════════════════
test_file_permissions() {
    local claim="Secret files mode 600, HSM tokens dir 700"
    local issues=()

    # Files that should be 600
    local -A expect600=(
        ["$ENV_FILE"]="gateway .env"
        ["$PROXY_ENV_FILE"]="proxy .env"
        ["/opt/lobsec/boot/pin.env"]="HSM PIN"
        ["/opt/lobsec/boot/fscrypt-key.bin"]="fscrypt key"
    )

    for path in "${!expect600[@]}"; do
        if [[ -f "$path" ]]; then
            local mode
            mode=$(stat -c '%a' "$path")
            if [[ "$mode" != "600" ]]; then
                issues+=("${expect600[$path]}=$mode (want 600)")
            fi
        fi
        # Skip if file doesn't exist (e.g. .env wiped)
    done

    # HSM tokens directory should be 700
    local hsm_dir=/opt/lobsec/hsm/tokens
    if [[ -d "$hsm_dir" ]]; then
        local dmode
        dmode=$(stat -c '%a' "$hsm_dir")
        if [[ "$dmode" != "700" ]]; then
            issues+=("hsm/tokens=$dmode (want 700)")
        fi
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        pass "$claim"
    else
        fail "$claim" "${issues[*]}"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 15: HSM audit signing key is non-extractable
# ════════════════════════════════════════════════════════════════════
test_nonextractable_key() {
    local claim="HSM audit signing key is non-extractable"

    if [[ -z "$HSM_PIN" ]]; then
        fail "$claim" "LOBSEC_HSM_PIN not available"
        return
    fi

    local output
    output=$(sudo -u lobsec \
        SOFTHSM2_CONF="$SOFTHSM2_CONF" \
        pkcs11-tool --module "$SOFTHSM_LIB" \
        --token-label "$TOKEN_LABEL" \
        --login --pin "$HSM_PIN" \
        --list-objects --type privkey 2>&1) || true

    if echo "$output" | grep -q "never extractable"; then
        pass "$claim"
    else
        fail "$claim" "private key missing 'never extractable' flag"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 16: Radicale binds loopback only
# ════════════════════════════════════════════════════════════════════
test_radicale_loopback() {
    local claim="Radicale binds loopback only (5232)"
    local listen
    listen=$(ss -tlnp | grep ':5232')

    if [[ -z "$listen" ]]; then
        fail "$claim" "port 5232 not listening"
        return
    fi

    if echo "$listen" | grep -qE '0\.0\.0\.0:5232|\*:5232'; then
        fail "$claim" "bound to 0.0.0.0 or wildcard"
    elif echo "$listen" | grep -q '127\.0\.0\.1:5232'; then
        pass "$claim"
    else
        fail "$claim" "unexpected bind: $listen"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Test 17: Proxy has SSRF protection
# ════════════════════════════════════════════════════════════════════
test_ssrf_protection() {
    local claim="Proxy SSRF protection blocks metadata IP"

    if [[ ! -f "$EGRESS_JS" ]]; then
        fail "$claim" "egress-firewall.js not found"
        return
    fi

    local output
    output=$(node -e "
        const { checkEgress, DEFAULT_ALLOWLIST, isMetadataIp, isPrivateIp } = require('$EGRESS_JS');
        // Test 1: metadata IP blocked by isMetadataIp
        const m = isMetadataIp('169.254.169.254');
        // Test 2: full checkEgress with resolved IP
        const r = checkEgress('evil.com', 443, '169.254.169.254', DEFAULT_ALLOWLIST);
        // Test 3: private IP blocked
        const p = isPrivateIp('10.0.0.1');
        process.stdout.write(JSON.stringify({ metadata_blocked: m, egress_blocked: !r.allowed, private_blocked: p }));
    " 2>&1)

    if echo "$output" | grep -q '"metadata_blocked":true' && \
       echo "$output" | grep -q '"egress_blocked":true' && \
       echo "$output" | grep -q '"private_blocked":true'; then
        pass "$claim"
    else
        fail "$claim" "output: $output"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Run all tests
# ════════════════════════════════════════════════════════════════════
test_hsm_objects
test_no_real_keys
test_token_isolation
test_wipe_on_stop
test_fscrypt
test_redactor
test_egress_firewall
test_gateway_loopback
test_proxy_loopback
test_proxy_auth
test_systemd_hardening
test_audit_logging
test_audit_timer
test_file_permissions
test_nonextractable_key
test_radicale_loopback
test_ssrf_protection

# ════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════
printf "\n\e[1m══════════════════════════════════════════════════════════════\e[0m\n"
printf "\e[1m  Summary: \e[32m%d PASS\e[0m  \e[31m%d FAIL\e[0m  \e[33m%d SKIP\e[0m  (of 17)\e[0m\n" "$PASS" "$FAIL" "$SKIP"
printf "\e[1m══════════════════════════════════════════════════════════════\e[0m\n\n"

# Detailed table
printf "  %-6s  %-50s  %s\n" "STATUS" "CLAIM" "DETAIL"
printf "  %-6s  %-50s  %s\n" "------" "$(printf '%0.s-' {1..50})" "$(printf '%0.s-' {1..30})"
for r in "${results[@]}"; do
    IFS='|' read -r status claim detail <<< "$r"
    case "$status" in
        PASS) printf "  \e[32m%-6s\e[0m  %-50s\n" "$status" "$claim" ;;
        FAIL) printf "  \e[31m%-6s\e[0m  %-50s  %s\n" "$status" "$claim" "$detail" ;;
        SKIP) printf "  \e[33m%-6s\e[0m  %-50s  %s\n" "$status" "$claim" "$detail" ;;
    esac
done

printf "\n"

# Exit code: 0 if no failures, 1 if any fail
[[ "$FAIL" -eq 0 ]]
