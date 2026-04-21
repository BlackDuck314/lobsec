# v1.7 Requirements — System Health & Reliability

**Milestone:** v1.7 System Health & Reliability
**Goal:** Restore all broken capabilities found in the 2026-04-21 audit, clean up system debt, and verify end-to-end health. Bot should respond, all backends should route, all timers should fire, and the system should be maintainable.

## Core Infrastructure Repair

- [ ] **REPAIR-01**: Portullama reconnection — diagnose auth requirement on <SOVEREIGN_GPU_HOST>:11435, update proxy to send correct credentials. Verify sovereign routing works end-to-end via Telegram.
- [ ] **REPAIR-02**: Jetson reconnection — diagnose CF-Access 403 on <JETSON_HOSTNAME>, update CF tunnel credentials if needed. Verify small-model routing (gemma3:1b, llama3.2:3b, qwen2.5-coder:3b).
- [ ] **REPAIR-03**: Memory search restoration — once Portullama is back, verify BGE-M3 embeddings work via proxy. Test semantic search through Telegram.
- [ ] **REPAIR-04**: Weekly digest timer fix — add TELEGRAM_BOT_TOKEN to lobsec-weekly-digest.service environment (from HSM or .env). Verify Monday 04:00 UTC delivery.
- [ ] **REPAIR-05**: TLS cert lifecycle — verify PartOf=lobsec.service works (proxy auto-restarts with gateway). Test a gateway restart doesn't break proxy connectivity.

## System Housekeeping

- [ ] **HOUSE-01**: Session trimming — archive or truncate the 2.7MB/1140-message session file. Implement a session rotation policy (e.g., archive sessions older than 30 days).
- [ ] **HOUSE-02**: Disk cleanup — identify and clean large files on root disk (currently 81%). Target <70% usage. Remove stale Docker images, old logs, compile caches.
- [ ] **HOUSE-03**: ConfigMonitor drift — investigate and resolve the drift warning. Update baseline config if the drift is intentional (sandbox changes from today's fix).
- [ ] **HOUSE-04**: Cron job audit — review 5 OpenClaw cron jobs: re-enable or remove the 2 disabled ones (PT Legal All Sources, PT Legal Weekly Status). Verify the 3 active ones produce results.
- [ ] **HOUSE-05**: Stale file cleanup — remove orphaned files from git status (server.js, .bg-shell/, check-alerts.sh, etc.). Clean untracked deploy scripts.

## Data Pipeline Restoration

- [ ] **PIPE-01**: Scraper health check — verify lobsec-scraper service is running, test all enabled missions. Fix PropertyFinder if possible (broken selectors).
- [ ] **PIPE-02**: Sentiment collectors — reddit-sentiment and news-sentiment collectors failing (credential-blocked). Either provision credentials or disable gracefully with documentation.
- [ ] **PIPE-03**: Collection pipeline verification — run a full collection cycle (weekly + monthly missions), verify data lands in SQLite normalized_monthly table with correct timestamps.
- [ ] **PIPE-04**: Feynman integration — configure Feynman as an available tool for the lobsec bot. Verify research capabilities work via Telegram (deep research, literature review).

## Integration & Verification

- [ ] **VERIF-01**: Core bot verification — Telegram message → LLM response → tool execution cycle works end-to-end. Test 3+ tools (weather, email, uae_macro_health).
- [ ] **VERIF-02**: All backends accessible — Anthropic (primary), Portullama (sovereign), Jetson (edge) all respond through proxy. Memory search returns results.
- [ ] **VERIF-03**: All timers fire — weekly digest, monthly report, alerts timer, collection timers all produce output. Cron jobs deliver results via Telegram.

---
*Created: 2026-04-21 — Based on capabilities audit findings*
