# HSM Key Inventory

SoftHSM2 v2.6.1 PKCS#11 token used for credential storage.

**Token**: `lobsec` (serial `<redacted>`)
**Config**: `/opt/lobsec/hsm/softhsm2.conf`
**Token store**: `/opt/lobsec/hsm/tokens/` (mode 700, lobsec:lobsec)
**Last audited**: 2026-02-25

## Active Keys (6 data objects)

| # | HSM Label | Type | Extracted By | Destination | Purpose |
|---|-----------|------|-------------|-------------|---------|
| 1 | `telegram-bot-token` | Data | `hsm-extract-credentials.sh` | `TELEGRAM_BOT_TOKEN` in `.env` | Telegram Bot API long-polling auth |
| 2 | `ollama-api-key` | Data | `hsm-extract-credentials.sh` | `OLLAMA_API_KEY` in `.env` | Remote GPU API key (qwen2.5:32b) |
| 3 | `gateway-auth-token` | Data | `hsm-extract-credentials.sh` | `OPENCLAW_GATEWAY_TOKEN` in `.env` | Gateway WebSocket challenge-response |
| 4 | `anthropic-api-key` | Data | `hsm-extract-credentials.sh` | `ANTHROPIC_API_KEY` in `.env` | Claude API (public cloud) |
| 5 | `jetson-cf-client-id` | Data | `hsm-extract-credentials.sh` | `CF-Access-Client-Id` in `openclaw.json` | Cloudflare Access service token ID |
| 6 | `jetson-cf-client-secret` | Data | `hsm-extract-credentials.sh` | `CF-Access-Client-Secret` in `openclaw.json` | Cloudflare Access service token secret |

## Reserved Keys (1 keypair)

| # | HSM Label | Type | Status | Purpose |
|---|-----------|------|--------|---------|
| 7 | `lobsec-audit-signing` | RSA 2048 (public) | Reserved | Future: sign audit log entries |
| 8 | `lobsec-audit-signing` | RSA 2048 (private) | Reserved | Future: sign audit log entries |

The RSA keypair was provisioned for cryptographic signing of audit log entries.
The private key is marked `never extractable` — signing must happen via PKCS#11 calls.
This feature is not yet implemented; the keypair is retained for future use.

## Credential Lifecycle

```
Service Start (ExecStartPre)
    |
    v
hsm-extract-credentials.sh
    |-- pkcs11-tool reads each data object
    |-- Writes .env (mode 600) with 4 env vars
    |-- Patches openclaw.json headers via jq (2 CF-Access values)
    |-- Logs each extraction to /opt/lobsec/logs/hsm-access.log
    v
Gateway runs with live credentials in memory + .env + config

Service Stop (ExecStopPost)
    |
    v
hsm-wipe-credentials.sh
    |-- Deletes .env
    |-- Replaces CF-Access headers with "HSM-INJECTED-AT-STARTUP" placeholders
    |-- Logs wipe event to /opt/lobsec/logs/hsm-access.log
    v
Disk is clean — no credentials at rest
```

## Removed Keys

| Date | Label | Reason |
|------|-------|--------|
| 2026-02-25 | `ollama-api-key-2` | Orphaned — stored but never referenced by extraction script |

## Rotation Procedure

To rotate a credential:
1. Store the new value: `pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label lobsec --login --pin $PIN --write-object /dev/stdin --type data --label "label-name"`
2. Restart service: `systemctl restart lobsec`
3. Verify extraction: `journalctl -u lobsec --since "1 min ago" | grep "extract_ok"`
4. Verify in HSM log: `tail /opt/lobsec/logs/hsm-access.log`
