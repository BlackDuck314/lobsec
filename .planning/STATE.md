---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: unknown
last_updated: "2026-03-12T12:42:00Z"
progress:
  total_phases: 2
  completed_phases: 2
  total_plans: 8
  completed_plans: 8
---

# Project State

## Current Position

Phase: 7.1 of 12 -- Ninja Scraper (INSERTED)
Plan: 3 of 4 -- Plan 03 COMPLETE (TS integration refactor)
Status: TS collectors deleted, SourceCollector refactored to HTTP client for Ninja Scraper API, CollectorRegistry factory pattern. Plans 01-03 complete. Ready for Plan 04 (production deployment + e2e verification).
Last activity: 2026-03-12 — Plan 07.1-03 complete. 2 tasks, 8 files (7 deleted, 1 created, 5 modified). 0 TS compile errors.

## Resume Instructions

1. v1.2 completed and archived (MILESTONES.md, milestones/ dir, git tag v1.2)
2. v1.3 "UAE Real Estate Intelligence System" roadmap COMPLETE -- 7 phases (6-12), 88 requirements
3. Research completed and synthesized in `.planning/research/SUMMARY.md`
4. Full playbook at `.planning/uae-re-playbook.md`
5. Requirements at `.planning/REQUIREMENTS.md` with full traceability table
6. **NOTE**: `gsd-tools roadmap get-phase 6` returns `found: false` — v1.3 phases are in `<details>` block. Bypass by manually constructing planner prompts with phase info from ROADMAP.md lines 43-48.
7. Phase 6 summaries: 06-01 (database), 06-02 (collector framework), 06-03 (deployment) at `.planning/phases/06-foundation-infrastructure/`
8. **RESOLVED**: 06-03 checkpoint cleared — plugin registered in openclaw.json, gateway restarted, all infrastructure verified
9. Phase 6 reqs: INFRA-01..07, SEC-01, SEC-02, SCHED-01 (10 requirements)
10. Phase 6 goal: Database, package structure, collector framework, Python analytics environment
11. Build order: Foundation -> MVP Collection -> Tier B -> Tier C -> Statistical Analysis -> Intelligence Products -> Plugin Tools & Hardening
12. Key risk: Do NOT build all 28 collectors before validating pipeline. Phase 7 (MVP) + Phase 10 (analysis) should validate end-to-end before expanding Tier B/C.

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-10)

**Core value:** No credential or sensitive data ever reaches an LLM provider
**Current focus:** v1.3 UAE Real Estate Intelligence System -- Phase 7.1 (Ninja Scraper)

## v1.3 Phase Summary

| Phase | Name | Requirements | Status |
|-------|------|-------------|--------|
| 6 | Foundation & Infrastructure | 10 (INFRA-01..07, SEC-01..02, SCHED-01) | ✅ Complete |
| 7 | MVP Data Collection (Tier A + DEWA) | 11 (COLL-01..05, COLL-15, NORM-01..05) | Paused (3/4 plans, blocked) |
| 7.1 | Ninja Scraper | 11 (same as Phase 7) | In Progress (3/4 plans) |
| 8 | Tier B Collection | 12 (COLL-06..13, SCHED-02..04, SCHED-07) | Pending |
| 9 | Tier C Collection | 15 (COLL-14, COLL-16..28, SCHED-05) | Pending |
| 10 | Statistical Analysis Pipeline | 11 (STAT-01..08, SCHED-06, SEC-06..07) | Pending |
| 11 | Intelligence Products | 10 (PROD-01..08, QUAL-01, QUAL-03) | Pending |
| 12 | Plugin Tools & Hardening | 19 (TOOL-01..13, QUAL-02,04,05, SEC-03..05) | Pending |

**Total: 88 requirements across 7 phases**

## Architecture Decisions

- SQLite (better-sqlite3) for time-series storage with WAL mode
- Dual-language: TypeScript for orchestration/collection, Python 3.13 for data science
- Python subprocess bridge with JSON I/O via stdin/stdout
- Single collector orchestrator (not 28 separate timers) to avoid SQLite write contention
- Both scheduled collection (systemd timers) AND on-demand Telegram queries
- All 28 sources in one milestone; Tier A validated first before expanding
- Accounts/auth not available yet -- build system, add credentials later

## Accumulated Context

### Roadmap Evolution
- Phase 7.1 inserted after Phase 7: Ninja Scraper (URGENT)

### Production Environment
- Server: Ubuntu 25.04 (VMware), <HOSTNAME> (<HOST_IP>)
- OpenClaw v2026.2.24, Node.js 22, sandbox mode off, skills enabled
- Both plugins active: 9 security hooks + 9 tools (including examy_test)
- Default model: Claude Haiku 4.5 via proxy
- Services: lobsec, lobsec-proxy, lobsec-radicale, lobsec-examy-test.timer, lobsec-examy-cleanup.timer
- Telegram: @lobsec_bot connected
- Daily Examy QA: 3am UTC automated, weekly cleanup Sunday 4am UTC

### Known Issues (carried)
- Jetson not routed through proxy (needs CF-Access header injection)
- nftables egress not fully enforced (needs separate lobsec-proxy user)
- mTLS certs generated but not enforced
- Hardened sandbox image built but not activated
- Examy login stuck at "Loading..." (app-level issue)

## Decisions

| Decision | Rationale |
|----------|-----------|
| Hybrid TypeScript+Python | TypeScript for orchestration, Python for pandas/statsmodels/scipy data science |
| SQLite over PostgreSQL | Single-server, embedded, WAL mode handles collection concurrency |
| Single orchestrator service | Avoids 28 separate timers and SQLite write contention |
| Phase 7 MVP before full expansion | Validate pipeline end-to-end with 6 sources before building remaining 22 |
| Bonferroni correction for Granger | Multiple testing correction prevents spurious correlations |
| fscrypt on /opt/lobsec/data/ | 5th encrypted directory, consistent with existing security architecture |
| WAL mode with NORMAL sync | Optimal read performance with acceptable write safety (64MB cache, MEMORY temp_store) |
| Dual stationarity testing | ADF + KPSS must both agree; conflicting results = "inconclusive" to avoid false claims |
| Forward-fill limit=1 | Monthly normalization handles single-month gaps without extrapolating beyond reasonable range |
| Deterministic cache keys | SHA-256 hash of JSON-serialized params with sorted keys ensures consistent hashing |
| Circuit breaker: 3/30s/1 | 3 failures to open, 30s reset timeout, 1 success to close — reasonable tolerance for transient failures |
| Stale after 2 failures | Distinguishes persistent issues (stale) from one-off failures (failed) |
| Semaphore concurrency | Wait queue with immediate release (not polling) — more efficient, avoids race conditions |
| Empty collection = error | rowCount=0 throws validation error — unusual and likely indicates upstream issues |
| SIGTERM then SIGKILL | Graceful termination with 5s fallback — gives Python scripts chance to clean up |
| Area lookup: exact match only | Case-insensitive exact match against canonical names, aliases, and source variants. No fuzzy matching until QUAL-04. Keeps normalization deterministic and fast. |
| Normalization upsert semantics | DELETE existing records for measurement_date range, then INSERT normalized records. Allows re-running without duplicates and supports late-arriving corrections. |
| Gap detection threshold: 2x frequency | Daily=2d, weekly=14d, monthly=60d, quarterly=180d. Tolerates occasional delays while catching persistent staleness. |
| Volume validation baseline: N=4 | Requires 4 successful collections before alerting. Warns when current <50% of rolling average. Balances sensitivity with false positive reduction. |
| schemas package created in wave 1 | Created in Plan 01 so Plans 02-03 (parallel) can add schema files without merge conflicts on __init__.py. |
| DLD/Ejari shared CSV download | Both collectors download same Dubai Pulse CSV independently. Filtering by trans_group_en (Sales vs Rent) happens in normalization. Each collector has own audit trail. |
| YoY/MoM null handling | Delta metrics return null until sufficient history exists (12+ months for YoY, 2+ months for MoM). Prevents false zeros in database. |
| Building permits multi-field classification | Keyword matching across permit_type, building_type, usage, project_type fields. Robust against dataset variations. |
| Renewal rate approximation | Estimated by volume overlap between months (min/previous) since DLD CSV doesn't distinguish new vs renewal. |
| ADREC replaces DARI/UAE Pass | Per user decision, DARI/UAE Pass permanently abandoned. ADREC public dashboards provide Abu Dhabi transaction data without authentication. COLL-04 fulfilled by ADREC. |
| Playwright click-to-download | ADREC uses waitForEvent('download') + saveAs() pattern (not HTTP GET). Per research: always use saveAs() immediately, never rely on download.path(). |
| Anti-bot measures for listing scrapers | Random 1-3s delays between areas, realistic user agent, graceful 403/CAPTCHA handling (skip, no retry). Do NOT retry immediately on block — makes it worse. |
| Price reduction single-scrape metric | Detected from portal badges during scraping (not historical comparison). Bayut/PropertyFinder show "Reduced" badge on listings. If badge absent, count=0 and log warning. |
| Bayut/PropertyFinder independent registration | Both collectors registered independently per user decision. Can fail without affecting each other. Enables cross-validation via identical output format. |
| Patchright Option A (bypass Crawlee pool) | Use Patchright pages directly, bypass Crawlee's browser pool. Lose auto-scaling but gain full stealth control. Evaluate Option B if browser pool becomes bottleneck. |
| BackgroundTasks over Celery | FastAPI BackgroundTasks sufficient for <10min scrapes. Max 10 concurrent limit. Celery deferred to Phase 8 if long scrapes emerge. |
| Ad-hoc Mission for /scrape | POST /scrape creates temporary Mission object so it works without pre-defined YAML files. Enables simple one-off scraping. |
| CRAWLEE_STORAGE_DIR at import | Set env var at module import time to ensure all Crawlee storage goes to /opt/lobsec/data/raw/crawlee-storage. |
| Handler as execution layer | Single execute_mission() entry point wraps type dispatch, area iteration, timeout, error handling. API and CLI both use handler, never call crawler directly. |
| Sequential area iteration | Areas within a single mission are visited sequentially (not concurrently). max_concurrent applies to concurrent missions at scheduler level. |
| Bayut/PropertyFinder slug differences | Bayut uses abbreviated slugs (jvc, jbr, jlt). PropertyFinder uses full slugs (jumeirah-village-circle, jumeirah-beach-residence). Same 20 areas mapped differently. |

## Blockers

**CRITICAL: UAE RE Plugin Load Failure (Plan 07-04 Task 2)**
- better-sqlite3 WAL pragma fails during OpenClaw plugin registration
- Error: "SqliteError: unable to open database file" at `db.pragma("journal_mode = WAL")`
- Database opens successfully, but WAL mode setup fails
- Same code works when executed directly as lobsec user
- Issue specific to OpenClaw plugin loading context
- Blocking: Cannot verify 7 collectors, cannot test end-to-end collection, cannot proceed to Task 3 checkpoint
- Investigation needed: OpenClaw plugin loader filesystem permissions/context

## Session Continuity

Last session: 2026-03-12
Stopped at: Completed 07.1-02-PLAN.md — 7 YAML missions + handler module
Resume file: None
Next: Execute 07.1-03-PLAN.md — TS integration refactor (delete old collectors, HTTP client wrapper)
Key context: packages/scraper/ has full engine + 7 missions + handler. Handler provides execute_mission() entry point. API main.py uses handler for all execution. Missions directory has all 7 YAML files validated.
User action needed: Register for Dubai Pulse API credentials (enables DLD, Ejari, Building Permits, DEWA — 4 of 7 collectors)
