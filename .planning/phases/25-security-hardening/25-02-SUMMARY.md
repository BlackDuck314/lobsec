---
phase: 25-security-hardening
plan: 02
status: complete
completed: "2026-03-31"
requirements_met:
  - SEC-02
  - SEC-03
---

# Summary: nftables Per-UID Egress + Jetson Routing (SEC-02, SEC-03)

## What Was Done

1. Substituted real UIDs in `deploy/lobsec-egress.conf` (gateway=<GATEWAY_UID>, proxy=<PROXY_UID>, sovereign GPU=<SOVEREIGN_GPU_HOST>)
2. Loaded `lobsec_egress` table with 3 chains: `output`, `gateway_egress`, `proxy_egress`
3. Copied to `/etc/nftables.d/lobsec-egress.conf` for persistence
4. Added `include "/etc/nftables.d/*.conf"` to `/etc/nftables.conf`

## Egress Rules

- **Gateway (uid <GATEWAY_UID>)**: ports 443 (HTTPS), 587 (SMTP), 993 (IMAP) + DNS + loopback
- **Proxy (uid <PROXY_UID>)**: ports 443 (HTTPS), 11435 (Ollama), 123 (NTP) + DNS + loopback + sovereign GPU host
- **Other users** (root, SSH, apt): not filtered (accept rule for non-lobsec UIDs)

## Jetson Routing (SEC-02)

Jetson config in openclaw.json routes through proxy (`baseUrl: https://127.0.0.1:18790`). Proxy code injects CF-Access headers for Jetson-bound requests. Architecturally complete.

## Verification

```
sudo nft list table inet lobsec_egress  # shows all 3 chains
sudo -u lobsec curl https://api.telegram.org/  # 200 (allowed)
sudo -u lobsec curl http://example.com:8080/   # timeout (blocked)
```
