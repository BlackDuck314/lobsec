# lobsec

## What This Is

A security wrapper around OpenClaw (224K+ stars, TypeScript/Node.js) that hardens AI agent deployments through 9 defense-in-depth layers: credential isolation via HSM, sovereign inference routing, tool gating, credential redaction, config drift detection, signed audit logging, sandboxed execution, network perimeter control, and filesystem encryption. Deployed in production as a Telegram-accessible AI assistant on Ubuntu 25.04.

## Core Value

No credential or sensitive data ever reaches an LLM provider — all secrets are isolated in HSM, redacted from message streams, and API keys are injected only at the proxy layer outside the agent's reach.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- [x] **CRED-01**: All API keys stored in SoftHSM2, never in plaintext config
- [x] **CRED-02**: Proxy injects real API keys; gateway only sees proxy token
- [x] **CRED-03**: Credential redactor strips 9+ secret patterns from message streams
- [x] **PROXY-01**: LLM proxy with token auth, provider detection, key injection
- [x] **PROXY-02**: Ollama routed through proxy (Portullama sovereign backend)
- [x] **PROXY-03**: Anthropic routed through proxy (Claude Haiku 4.5 default)
- [x] **PROXY-04**: Egress firewall with DNS resolution and SSRF protection
- [x] **PROXY-05**: Configurable extra hosts via environment variable
- [x] **ROUTE-01**: Sovereign routing (auto/sovereign/public modes)
- [x] **ROUTE-02**: Memory search embeddings route through proxy to Portullama
- [x] **SAND-01**: Docker sandbox with hardened image (74.8MB, seccomp whitelist)
- [x] **SAND-02**: Sandbox mode=all enforced in config
- [x] **NET-01**: Gateway and proxy bind loopback only (127.0.0.1)
- [x] **NET-02**: nftables egress rules (443, 587, 993, 11435, 53, 123)
- [x] **AUDIT-01**: Structured JSONL audit logging
- [x] **AUDIT-02**: HSM RSA-2048 batch signing every 5 min with hash chain
- [x] **CRYPT-01**: fscrypt AES-256-XTS on 4 directories (hsm, config, logs, .openclaw)
- [x] **TOOL-01**: Tool gating via plugin hooks
- [x] **TOOL-02**: Config drift detection with ConfigMonitor
- [x] **VERIFY-01**: 9-layer security verifier (`lobsec verify`)
- [x] **VERIFY-02**: Health check timer with continuous verification
- [x] **BOT-01**: Telegram bot commands (/status, /verify, /audit, /alerts, /sovereign)
- [x] **BOT-02**: Weather, email, calendar, contacts, web search integrations
- [x] **DEPLOY-01**: systemd hardened services (NoNewPrivileges, ProtectSystem=strict)
- [x] **DEPLOY-02**: Radicale CalDAV/CardDAV for calendar and contacts

### Active

<!-- Current scope. Building toward these. -->

(Defining for next milestone)

### Out of Scope

- Full OpenClaw fork — lobsec wraps, it doesn't fork
- Public-facing web UI — Telegram is the control plane
- Multi-user/multi-tenant — single-user deployment

## Context

- **Server**: Ubuntu 25.04 (VMware), social02 (10.4.11.197)
- **OpenClaw**: v2026.2.24 at /opt/lobsec/openclaw
- **Runtime**: Node.js 22, TypeScript strict, pnpm 10.30.0
- **Testing**: Vitest (765 tests, 35 files), oxlint
- **HSM**: SoftHSM2 v2.6.1 with 12 data objects + 2 keys
- **Inference**: Claude Haiku 4.5 (default), Portullama qwen2.5:32b (sovereign), Jetson (3 small models)
- **Codebase map**: `.planning/codebase/` (7 documents)

### Known Issues (from Mar 3, 2026 audit)

- Jetson not routed through proxy (needs CF-Access header injection in proxy)
- nftables egress not fully enforced (needs separate lobsec-proxy user)
- mTLS certs generated but not enforced between services
- Hardened sandbox image built but not activated in OpenClaw config
- message_sending hook never fires (OpenClaw limitation)
- Model discovery timeout (cosmetic, Portullama slow with 9 models)

## Constraints

- **Tech stack**: Node.js 22 + TypeScript strict — matches OpenClaw ecosystem
- **Security**: All secrets in HSM, never in plaintext files or environment (except bootstrap)
- **Deployment**: Single server, systemd managed, no container orchestration
- **Plugin SDK**: Limited to OpenClaw plugin API (hooks + registerCommand)
- **Sovereign**: Must support fully sovereign inference (no cloud dependency for core function)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| SoftHSM2 over real HSM | Cost/availability; upgrade path exists | ✓ Good |
| Proxy architecture over env vars | Credentials never touch agent process | ✓ Good |
| fscrypt over LUKS | Per-directory, no reboot needed | ✓ Good |
| Telegram as control plane | Already deployed, low friction | ✓ Good |
| Plugin hooks over OpenClaw fork | Maintainability, upgrade-safe | ✓ Good |
| Sovereign routing default=auto | Tools don't work on sovereign models | ✓ Good |
| Claude Haiku 4.5 as default | Cost/quality balance, tools work | ✓ Good |
| Radicale for CalDAV/CardDAV | Lightweight, Python, easy to deploy | ✓ Good |

---
*Last updated: 2026-03-04 after GSD initialization*
