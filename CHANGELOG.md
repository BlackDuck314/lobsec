# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.7.0] - 2026-04-22

### Added
- Cron scheduling with security guard (minimum 1-hour interval enforcement via plugin hook)
- Owner-only tool authorization for Telegram users (`commands.ownerAllowFrom`)
- Feynman research tool (8 workflows: deep research, lit review, summarize, audit, compare, draft, review, replicate)

### Changed
- Portullama model updated from qwen2.5:32b to qwen3.5:27b
- Sandbox tool policy now uses explicit deny list (overrides DEFAULT_TOOL_DENY for cron access)
- Redacted all sensitive infrastructure details from planning docs and deploy configs

### Fixed
- ConfigMonitor drift detection uses hash comparison only (no false positives from validation-only changes)
- Proxy egress firewall sourcing credentials via EnvironmentFile
- Timer services now source gateway .env for credential availability
- 5 broken data collectors disabled in registry (missing API keys, dead endpoints)
- Session bloat reduced from 2.7MB to 210KB (92% reduction)
- Disk usage reduced from 83% to 68% (~6GB freed)

## [0.6.0] - 2026-03-16

### Added
- UAE real estate intelligence system: 13 analytical tools, 34 data sources
- Automated data collection with scraper service (Playwright + Python)
- Statistical analysis: Granger causality, cross-correlation, composite signals
- Macro health dashboard with traffic-light scoring (6 signal groups)
- Area-level buy/sell signals, distress detection, rental intelligence
- Supply pipeline tracking, expat flow analysis, affordability mapping

### Changed
- Plugin tools expanded to 10 (added feynman_research, examy_test)
- Scraper runs on dedicated Python venv with Playwright browsers

## [0.5.0] - 2026-03-06

### Added
- Weekly intelligence digest (Monday 04:00 UTC) with sparkline charts
- Monthly comprehensive report (26th of month)
- Proactive anomaly alerts (daily 20:00 UTC, Telegram notification)
- LUKS2 full-disk encryption (15G encrypted volume, AES-256-XTS)
- Per-UID nftables egress separation (gateway and proxy have independent rules)
- Jetson inference proxied through lobsec-proxy with CF-Access header injection

### Security
- TLS 1.3 enforced on all internal connections (gateway + proxy)
- Docker sandbox hardened image rebuilt (74.8MB, seccomp whitelist, Python 3.11)
- systemd ProtectSystem=strict on all service units

## [0.4.0] - 2026-03-04

### Added
- Historical data backfill for 5 sources (DSC, DXB, MOHRE, CBUAE, DP World, 2019-2025)
- Pipeline automation: collection, normalization, and analysis on schedule
- World Bank, IMF, PMI, DFM stocks macro data collectors
- Brent crude oil and gold commodity tracking
- CPI proxy via World Bank data

### Fixed
- 4 normalizer rewrites (DXB, MOHRE, DSC, CBUAE) for correct date handling
- 18 retired missions cleaned from registry (dead URLs, WAF-blocked sources)

## [0.3.0] - 2026-03-01

### Added
- Automated QA testing with Playwright and LLM-driven student personas
- Examy test plugin tool for on-demand execution via Telegram
- GitHub issue auto-creation with hash-based dedup for test failures
- Screenshot capture and credential masking in test reports
- systemd timer for daily automated QA execution

### Security
- Examy credentials stored in HSM (15 data objects total)
- Playwright egress allowlisted in nftables
- Log sanitization strips credentials from test output

## [0.2.0] - 2026-02-28

### Added
- GitHub plugin tool (REST API: repos, issues, PRs, search)
- GitHub PAT stored in HSM
- 47 non-functional community skills removed from sandbox (4 kept: coding-agent, summarize, session-logs, skill-creator)
- Web search enabled (Perplexity Sonar via native OpenClaw tool)

### Fixed
- Sovereign routing default changed from "sovereign" to "auto" (tools now work via Telegram)
- IMAP SNI fix for Node 22 (explicit `servername` in `tls.connect()`)
- flatMap crash in message write/persist hooks (array content structure preserved)

## [0.1.0] - 2026-02-27

### Added
- 9-layer security architecture (L1-L9) wrapping OpenClaw
- OpenClaw plugin with 9 security hooks (tool gating, credential redaction, sovereign routing, config drift detection, audit logging)
- LLM proxy with sovereign-first inference routing and credential injection
- HSM credential management via PKCS#11 (SoftHSM2)
- fscrypt per-directory encryption for sensitive data directories
- HSM-signed tamper-evident audit logging with SHA-256 hash chains
- Docker sandbox hardening (rootless, cap_drop ALL, read-only rootfs, seccomp whitelist)
- Caddy L2 reverse proxy with TLS 1.3, rate limiting, and security headers
- nftables egress firewall with SSRF prevention and RFC1918 blocking
- mTLS certificate generation (P-256/ECDSA, self-signed CA, 30-day auto-renewal)
- Tool call validation with path containment, symlink resolution, and deny lists
- Credential redaction from all outputs (API keys, tokens, PII patterns)
- Sovereign/public inference routing via plugin hooks and proxy
- Budget enforcement framework for cloud API spend control
- systemd service units with NoNewPrivileges, ProtectSystem=strict, ProtectHome
- 706 tests across 33 test files (Vitest)
- Comprehensive documentation: design doc, threat model, security layers, encryption architecture
- OpenClaw update script with preflight checks, backup, and rollback
- Health check automation (15 checks every 5 minutes)
- Plugin tools: weather, email (send/read/fetch), calendar, contacts

### Security
- All credentials stored in HSM, never on persistent disk
- JIT credential injection: HSM to tmpfs to env vars, wiped on shutdown
- Zero public attack surface: loopback-only binding, SSH/VPN access only
- Config drift detection prevents runtime weakening of security posture
- Audit log integrity protected by HSM RSA-2048 signing key (non-extractable)
