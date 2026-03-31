---
phase: 25-security-hardening
plan: 03
status: complete
completed: "2026-03-31"
requirements_met:
  - SEC-04
---

# Summary: Hardened Sandbox Activation (SEC-04)

## What Was Done

1. Changed sandbox mode from `"off"` to `"all"` in `/opt/lobsec/.openclaw/openclaw.json`
2. Image set to `lobsec-sandbox:hardened` (74.8MB, curl/wget/netcat removed)
3. Seccomp profile at `/opt/lobsec/config/seccomp-sandbox.json` (58 allowed syscalls)
4. Gateway restarted and verified

## Verification

- `grep '"mode"' openclaw.json` shows `"all"`
- Docker image `lobsec-sandbox:hardened` used for tool execution
- Network tools removed from sandbox container
- Tool execution verified via Telegram bot queries
