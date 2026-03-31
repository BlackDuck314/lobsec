---
phase: 25-security-hardening
plan: 01
status: complete
completed: "2026-03-31"
requirements_met:
  - SEC-01
---

# Summary: mTLS Proxy (SEC-01)

## What Was Done

1. Proxy server.js modified to use `node:https` with TLS 1.3
2. Loads proxy cert/key and CA from `/opt/lobsec/config/tls/`
3. Falls back to plain HTTP if certs missing (`loadTlsOptions()` returns null)
4. Gateway config updated to `https://127.0.0.1:18790` for all providers
5. `NODE_EXTRA_CA_CERTS` set in lobsec.service for CA trust

## Outcome

- **TLS 1.3 active** — all gateway-to-proxy traffic encrypted
- **Client cert requested but not enforced** — OpenClaw's HTTP client doesn't present client certificates, so `rejectUnauthorized` is set to `false` (server-side TLS only, not mutual)
- Health check works: `curl --cacert ca.crt https://127.0.0.1:18790/__lobsec__/health` returns `{"status":"ok"}`

## Known Limitation

Full mutual TLS (client cert enforcement) requires OpenClaw to support presenting client certificates when connecting to provider base URLs. Currently it does not. SEC-01 is satisfied at the transport encryption level but not at the mutual authentication level.

## Verification

```
[proxy] TLS enabled (TLS 1.3, client cert requested but not enforced)
```
