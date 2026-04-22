# lobsec

## What This Is

A security wrapper around OpenClaw (224K+ stars, TypeScript/Node.js) that hardens AI agent deployments through 9 defense-in-depth layers: credential isolation via HSM, sovereign inference routing, tool gating, credential redaction, config drift detection, signed audit logging, sandboxed execution, network perimeter control, and filesystem encryption. Includes automated QA testing of external web apps via Playwright with LLM-driven student personas. Deployed in production as a Telegram-accessible AI assistant on Ubuntu 25.04.

## Core Value

No credential or sensitive data ever reaches an LLM provider — all secrets are isolated in HSM, redacted from message streams, and API keys are injected only at the proxy layer outside the agent's reach.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- ✓ CRED-01: All API keys stored in SoftHSM2, never in plaintext config — v1.0
- ✓ CRED-02: Proxy injects real API keys; gateway only sees proxy token — v1.0
- ✓ CRED-03: Credential redactor strips 9+ secret patterns from message streams — v1.0
- ✓ PROXY-01: LLM proxy with token auth, provider detection, key injection — v1.0
- ✓ PROXY-02: Ollama routed through proxy (Portullama sovereign backend) — v1.0
- ✓ PROXY-03: Anthropic routed through proxy (Claude Haiku 4.5 default) — v1.0
- ✓ PROXY-04: Egress firewall with DNS resolution and SSRF protection — v1.0
- ✓ PROXY-05: Configurable extra hosts via environment variable — v1.0
- ✓ ROUTE-01: Sovereign routing (auto/sovereign/public modes) — v1.0
- ✓ ROUTE-02: Memory search embeddings route through proxy to Portullama — v1.0
- ✓ SAND-01: Docker sandbox with hardened image (74.8MB, seccomp whitelist) — v1.0
- ✓ SAND-02: Sandbox mode=all enforced in config — v1.0
- ✓ NET-01: Gateway and proxy bind loopback only (127.0.0.1) — v1.0
- ✓ NET-02: nftables egress rules (443, 587, 993, 11435, 53, 123) — v1.0
- ✓ AUDIT-01: Structured JSONL audit logging — v1.0
- ✓ AUDIT-02: HSM RSA-2048 batch signing every 5 min with hash chain — v1.0
- ✓ CRYPT-01: fscrypt AES-256-XTS on 4 directories — v1.0
- ✓ TOOL-01: Tool gating via plugin hooks — v1.0
- ✓ TOOL-02: Config drift detection with ConfigMonitor — v1.0
- ✓ VERIFY-01: 9-layer security verifier (`lobsec verify`) — v1.0
- ✓ VERIFY-02: Health check timer with continuous verification — v1.0
- ✓ BOT-01: Telegram bot commands (/status, /verify, /audit, /alerts, /sovereign) — v1.0
- ✓ BOT-02: Weather, email, calendar, contacts, web search integrations — v1.0
- ✓ DEPLOY-01: systemd hardened services (NoNewPrivileges, ProtectSystem=strict) — v1.0
- ✓ DEPLOY-02: Radicale CalDAV/CardDAV for calendar and contacts — v1.0
- ✓ SKILL-01: Remove non-functional skills from sandbox (47 of 51) — v1.1
- ✓ GH-01: GitHub PAT stored in HSM — v1.1
- ✓ GH-03: GitHub plugin tool (issues, PRs, repos via REST API) — v1.1
- ✓ VERIFY-03: All 9 plugin tools register and work via Telegram — v1.1
- ✓ INFRA-01: Playwright + headless Chromium on Ubuntu 25.04 — v1.2
- ✓ INFRA-02: lobsec-examy.service with relaxed systemd hardening — v1.2
- ✓ INFRA-03: dev.examy.app in egress firewall allowlist — v1.2
- ✓ INFRA-04: Examy credentials in HSM (15 data objects total) — v1.2
- ✓ TEST-01 through TEST-07: Automated QA testing with personas, screenshots, errors, visual regression — v1.2
- ✓ RPT-01: Failure email notifications — v1.2
- ✓ RPT-02: GitHub issue auto-creation with hash-based dedup — v1.2
- ✓ RPT-03: Credential masking in screenshots and log sanitization — v1.2
- ✓ SCHED-01: examy_test plugin tool for on-demand execution — v1.2
- ✓ SCHED-02: systemd timer for daily automated execution — v1.2

- ✓ INFRA-01 through INFRA-07: SQLite database, Python venv, collector framework, subprocess bridge, cache layer, plugin package — v1.3
- ✓ COLL-01 through COLL-28: 28 data source missions written (11 producing data, rest WAF-blocked) — v1.3
- ✓ NORM-01 through NORM-05: Monthly normalization, publication dates, gap detection, schema/volume validation — v1.3
- ✓ STAT-01 through STAT-08: Stationarity, Granger causality, correlation, composites, anomaly detection, affordability, expat pipeline — v1.3
- ✓ PROD-01 through PROD-08: 8 intelligence products (buy/sell signal, distress, rental, supply, expat flow, macro health, arbitrage, salary-rent) — v1.3
- ✓ TOOL-01 through TOOL-13: 13 OpenClaw plugin tools for Telegram queries — v1.3
- ✓ SCHED-01 through SCHED-07: Collector orchestrator, 5 timers, timeout enforcement — v1.3
- ✓ SEC-01 through SEC-07: HSM credentials, fscrypt, nftables egress, credential redaction, audit, SQL injection prevention, PII protection — v1.3
- ✓ QUAL-01 through QUAL-05: Out-of-sample validation, staleness surfacing, conditional forward-fill, area name normalization, collection health — v1.3

- ✓ NORM-06 through NORM-09: DXB/MOHRE/DSC normalizers rewritten + all 11 sources verified — v1.4
- ✓ BACK-01 through BACK-05: Historical backfill for DSC, DXB, MOHRE, CBUAE, DP World (2019-2025) — v1.4
- ✓ AUTO-01 through AUTO-03: Pipeline automation (collection→normalization→analysis on schedule) — v1.4
- ✓ VERIF-01 through VERIF-03: 3+ tools returning real intelligence via Telegram — v1.4
- ✓ MACRO-01 through MACRO-04: World Bank, IMF, PMI, DFM stocks — v1.5
- ✓ COMM-01, COMM-02: Brent crude + gold commodities — v1.5
- ✓ SENT-01, SENT-02: Reddit r/UAE + NewsAPI collector — v1.5 (credential-blocked, no data yet)
- ✓ COST-01: CPI proxy via World Bank data — v1.5
- ✓ CBUAE-01: CBUAE expanded monetary data (7/8 metrics) — v1.5
- ✓ DORM-01 through DORM-03: Mission audit, 18 retired, pytrends fix — v1.5
- ✓ INTEG-01 through INTEG-04: Registry, egress, HSM, normalization integration — v1.5
- ✓ VERIF-01 through VERIF-03: 20 sources, 47 metrics 12+ obs, 9-group macro health — v1.5
- ○ DATA-01 through DATA-04: Dubai Pulse API integration — deferred (user registration needed)

### Shipped (Partial)

- ✓ BOT-01 through BOT-04: Weekly/monthly digests, sparklines, proactive anomaly alerts — v1.6
- ✓ SEC-01 through SEC-05: mTLS, Jetson proxy, nftables separation, sandbox, LUKS — v1.6
- ○ PULSE-01 through PULSE-08: Dubai Pulse API integration — v1.6 (blocked, credentials never obtained)
- ○ QUAL-01 through QUAL-05: Bayut API, Reddit/NewsAPI creds, Granger analysis — v1.6 (blocked, credentials)
- ○ VERIF-01 through VERIF-05: Verification — v1.6 (partial, blocked items prevent full verification)

### Shipped (v1.7)

- ✓ REPAIR-01, REPAIR-04, REPAIR-05: Portullama restored, weekly digest fixed, TLS lifecycle verified — v1.7
- ○ REPAIR-02, REPAIR-03: Jetson + memory search — v1.7 (deferred, external blockers)
- ✓ HOUSE-01 through HOUSE-05: Session trim, disk cleanup, ConfigMonitor, cron audit, deploy files — v1.7
- ✓ PIPE-01 through PIPE-04: Scraper health, collectors cleaned, pipeline verified, Feynman deployed — v1.7
- ✓ VERIF-01 through VERIF-03: Core bot, backends, timers all verified — v1.7

### Active

<!-- Current scope. Defined in REQUIREMENTS.md when next milestone starts. -->

(No active milestone — v1.8 not yet planned)

### Out of Scope

- Full OpenClaw fork — lobsec wraps, it doesn't fork
- Public-facing web UI — Telegram is the control plane
- Multi-user/multi-tenant — single-user deployment
- Mobile/responsive testing — desktop-first
- Video recording of test sessions — screenshots sufficient
- Self-healing tests — masks real issues
- Load/performance testing — different concern (k6/JMeter)

## Context

- **Server**: Ubuntu 25.04 (VMware), <HOSTNAME> (<HOST_IP>)
- **OpenClaw**: v2026.2.24 at /opt/lobsec/openclaw
- **Runtime**: Node.js 22, TypeScript strict, pnpm 10.30.0
- **Testing**: Vitest (765 tests, 35 files), oxlint
- **HSM**: SoftHSM2 v2.6.1 with 15 data objects + 2 keys
- **Inference**: Claude Haiku 4.5 (default), Portullama qwen2.5:32b (sovereign), Jetson (3 small models)
- **Codebase**: 24,450 LOC TypeScript, 18 files modified in v1.2 (+2,329 lines)
- **Plugins**: lobsec-security (9 hooks), lobsec-tools (9 tools including examy_test)
- **QA**: Daily Examy test at 3am UTC, weekly cleanup Sunday 4am UTC
- **Codebase map**: `.planning/codebase/` (7 documents)

### Known Issues

- Jetson returns CF-Access 403 — cloudflared tunnel down on remote device (user must restart)
- Memory search disabled — BGE-M3 crashes on Portullama (remote server needs model reinstall)
- message_sending hook never fires (OpenClaw limitation)
- mTLS is server-TLS only (OpenClaw doesn't present client certs) — SEC-01 partial
- Examy login stuck at "Loading..." (app-level issue)

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
| Playwright locators over page.evaluate() | Avoids TypeScript DOM type issues | ✓ Good |
| chromium_headless_shell over full Chromium | NoNewPrivileges compatibility | ✓ Good |
| Direct Node.js for scheduled tests | Zero LLM cost, simpler than gateway | ✓ Good |
| Hash-based GitHub issue dedup | Auto-close resolved, prevents duplicates | ✓ Good |
| 5% pixel diff threshold | Balances sensitivity vs. rendering noise | ✓ Good |

| Hybrid TypeScript+Python | TS orchestration, Py data science (pandas/statsmodels) | ✓ Good |
| SQLite over PostgreSQL | Single-server, embedded, WAL mode handles concurrency | ✓ Good |
| Single collector orchestrator | Avoids 28 separate timers and write contention | ✓ Good |
| Bonferroni correction for Granger | Multiple testing correction prevents spurious correlations | — Pending (needs data) |
| Ninja Scraper (Patchright+FastAPI) | Replaced TS collectors that couldn't handle real sites | ✓ Good |
| Aggressive backfill over forward-only | Unlock statistical analysis sooner with historical data | — Pending |

## Current State

**Latest shipped:** v1.7 System Health & Reliability (2026-04-22)
**Next milestone:** v1.8 (not yet planned)

**What's live:**
- 13 UAE RE plugin tools + 10 general tools accessible via Telegram
- Telegram bot connected and responding with cron scheduling enabled
- Claude Haiku 4.5 via proxy (default), Portullama qwen3.5:27b (sovereign)
- mTLS active, LUKS2 encrypted, nftables per-UID egress
- Automated pipeline: weekly/monthly/quarterly collection + monthly analysis on 25th
- Feynman research agent (v0.2.40, 8 workflows)
- Weekly digest (Mon 04:00 UTC), monthly report (26th), anomaly alerts (daily 20:00 UTC)
- Session: 210KB (down from 2.7MB), disk: 68% (down from 83%)

**Deferred (external blockers):**
- Jetson cloudflared tunnel down (user must restart on remote device)
- BGE-M3 memory search (embedding model crashes on Portullama, remote server issue)

**v1.7 Highlights:**
- Portullama sovereign routing restored (qwen3.5:27b)
- All timer services fixed (EnvironmentFile sourcing)
- Session bloat: 2.7MB → 210KB (92% reduction)
- Disk: 83% → 68% (~6GB freed)
- 5 broken data collectors disabled, scraper healthy
- Feynman research deployed as 10th plugin tool
- Cron scheduling enabled with security guard (1-hour minimum)

---
*Last updated: 2026-04-22 — v1.7 shipped, archived*
