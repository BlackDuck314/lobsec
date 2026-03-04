# Project State

## Current Position

Phase: v1.1 Tool Reliability — CREDENTIAL REDACTOR FIXED
Last activity: 2026-03-04

## User Direction

**"Stop trying to change how OpenClaw works."** lobsec = transparent security layer only.

## Fixes Applied This Session

### Credential Redactor False Positives (ROOT CAUSE of "SMTP password" complaints)

**Problem 1: `gmail-app-password` regex too broad**
- Old pattern: `/[a-z]{4}\s[a-z]{4}\s[a-z]{4}\s[a-z]{4}/g` — matched ANY four groups of 4-letter lowercase words
- "sent your test mail", "this will send from" — all matched as "Gmail app passwords"
- Fix: Now requires context: `/(?:password|GMAIL_APP_PASSWORD|app[_\s-]?pass(?:word)?|smtp[_\s-]?pass(?:word)?)\s*[=:"']+\s*[a-z]{4}\s[a-z]{4}\s[a-z]{4}\s[a-z]{4}/gi`

**Problem 2: All hooks used ALL_PATTERNS (credentials + PII)**
- `message_sending`, `tool_result_persist`, `before_message_write` all redacted email addresses
- Bot response "I sent email from <user>@gmail.com" → became "[EMAIL-REDACTED]"
- This broke the bot's own context — it "forgot" which email address to use
- Fix: Changed to `new CredentialRedactor(CREDENTIAL_PATTERNS)` — only redacts actual secrets (API keys, tokens, passwords), NOT email addresses/IPs/phones

### HEARTBEAT.md Restored
- Was overwritten by bot with research_scout project notes
- Restored from sandbox template copy

## Verification

- 767 tests pass (35 test files), including 3 new false-positive prevention tests
- Both plugins load: 9 security hooks + 8 tools
- No `BLOCKED outbound credential leak` entries after restart
- Proxy routes Anthropic API correctly
- Telegram bot connected

## Current Config

- sandbox.mode: "off"
- skills: enabled (no override)
- workspaceAccess: "rw"
- tools.sandbox.tools.allow: includes group:plugins
- Both plugins: 9 security hooks + 8 tools
- Services: active, Telegram connected

## Remaining

- Test email_send via Telegram to confirm end-to-end
- Consider restoring sandbox.mode to "all" (OpenClaw native) now that core issues are fixed
- CLI `gateway-chat.sh` has connection issues (WebSocket closes before embedded agent completes) — Telegram channel works fine
