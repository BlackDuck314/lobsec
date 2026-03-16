---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: unknown
last_updated: "2026-03-16T15:30:12.359Z"
progress:
  total_phases: 8
  completed_phases: 7
  total_plans: 31
  completed_plans: 30
---

# Project State

## Current Position

Phase: 12 of 12 -- Plugin Tools, Telegram Interface & Production Hardening (IN PROGRESS)
Plan: 3 of 4 -- 12-01, 12-02, 12-03 complete (wave 1 done). Next: 12-04 (deploy + Telegram verification checkpoint).
Status: Phase 12 wave 1 complete. SEC-03, SEC-04, SEC-05 marked complete. Credential redactor extended, nftables domain whitelist documented, collector audit logging added.
Last activity: 2026-03-16 — 12-03 complete. 4 credential patterns (Google Maps, Apify, Reddit), nftables 28-domain comment whitelist, update-egress-ips.sh, collector audit JSONL logging.

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
**Current focus:** v1.3 UAE Real Estate Intelligence System -- Phase 7.1 COMPLETE, ready for Phase 8 (Tier B Collection)

## v1.3 Phase Summary

| Phase | Name | Requirements | Status |
|-------|------|-------------|--------|
| 6 | Foundation & Infrastructure | 10 (INFRA-01..07, SEC-01..02, SCHED-01) | ✅ Complete |
| 7 | MVP Data Collection (Tier A + DEWA) | 11 (COLL-01..05, COLL-15, NORM-01..05) | Paused (3/4 plans, blocked) |
| 7.1 | Ninja Scraper | 11 (same as Phase 7) | ✅ Complete (4/4 plans) |
| 8 | Tier B Collection | 12 (COLL-06..13, SCHED-02..04, SCHED-07) | In Progress (3/4 plans, 10 reqs) |
| 9 | Tier C Collection | 15 (COLL-14, COLL-16..28, SCHED-05) | ✅ Complete (4/4 plans) |
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
- Server: Ubuntu 25.04 (VMware), social02 (10.4.11.197)
- OpenClaw v2026.2.24, Node.js 22, sandbox mode off, skills enabled
- Both plugins active: 9 security hooks + 9 tools (including examy_test)
- Default model: Claude Haiku 4.5 via proxy
- Services: lobsec, lobsec-proxy, lobsec-radicale, lobsec-scraper, lobsec-examy-test.timer, lobsec-examy-cleanup.timer
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
| SourceCollector uses native fetch() | Node 22 has native fetch — no HTTP client dependency needed for Ninja Scraper API calls. |
| All collectors same class | All 7 collectors are SourceCollector instances differentiated by missionName. Eliminates class hierarchy. |
| Factory pattern for registration | CollectorRegistry.createCollectors(db, scraperConfig) centralizes definitions in COLLECTOR_DEFINITIONS array. |
| Sequential area iteration | Areas within a single mission are visited sequentially (not concurrently). max_concurrent applies to concurrent missions at scheduler level. |
| Bayut/PropertyFinder slug differences | Bayut uses abbreviated slugs (jvc, jbr, jlt). PropertyFinder uses full slugs (jumeirah-village-circle, jumeirah-beach-residence). Same 20 areas mapped differently. |
| Deploy code via copy not pip install | /opt/lobsec/scraper/ receives cp -r of ninja_scraper module + missions. Matches lobsec service deployment pattern. |
| Dubai Pulse WAF expected | All 3 HTTP download sources (DLD, Ejari, permits) get "Request Rejected" from Dubai Pulse WAF. Engine correct, needs API credentials. |
| Bayut selectors need Phase 8 tuning | CSS selectors in bayut-listings.yml return null. Engine area iteration works (20 areas, 205s). DOM inspection needed for correct selectors. |
| All Tier B missions use browser_scrape | Consistent approach for government sources. Patchright overhead is small. RTA browser scrape may bypass Dubai Pulse WAF. |
| PDF extraction in Python not YAML | Clean separation: scraper collects files, Python understands content. pdfplumber in normalization modules, not missions. |
| Page targeting for PDF extraction | DXB 0-4, GDRFA 1-4, KHDA 0-9, CBUAE all pages. Reduces false positives from decorative tables. |
| Header detection for table identification | Lowercase keyword matching (visa+issued, enrollment+student, remittance+personal) before extracting values. |
| Sanity validation for critical metrics | DXB >100K passengers, KHDA >100K students. Raises error if suspiciously low (likely wrong table). |
| MOHRE targets statistical reports | mohre.gov.ae/en/data-library/statistical-report.aspx instead of press releases for structured data. |
| DXB targets PDF factsheets | More reliable for pdfplumber than HTML press releases. Consistent table formatting. |
| KHDA uses quarterly frequency | Quarterly timer checks for new annual report. No separate "annual" frequency in CollectionFrequency type. |
| GDRFA and CBUAE independent missions | Different URLs, different extraction logic, independent failure modes. |
| Measurement date patterns | Monthly → start of month, quarterly → start of quarter, annual → September (academic year). |
| Error messages for Telegram fallback | Descriptive ValueError with required field names when PDF extraction fails. Bot prompts user for manual entry. |
| UAE-level prefix for CBUAE | uae|cbuae_* instead of dubai|cbuae_* — remittance data is national, not Dubai-specific. |
- [Phase 09-tier-c-collection]: DSC over FCSA for demographics: Dubai Statistics Centre URL for more granular Dubai-specific population data
- [Phase 09-tier-c-collection]: Empty list valid for annual demographics: normalize_demographics returns [] on non-annual quarters — expected behavior, not an error
- [Phase 09-tier-c-collection]: Construction material breakdown optional: Jebel Ali port warns + skips metric if press release lacks breakdown — not an error
- [Phase 09]: proxy+user_agent_rotation optional fields added to Mission model for stealth scraping support
- [Phase 09]: Google Maps traffic uses max_attempts=1 (no retry on block) to avoid accelerating bans
- [Phase 09]: InsideAirbnb occupancy proxy = 1 - avg_availability_365/365; multihost_ratio uses calculated_host_listings_count>1
- [Phase 09]: DirectPythonCollector uses pythonModule as PythonScriptName for type-safe compile-time validation of Python bridge calls
- [Phase 09]: Mission proxy/user_agent_rotation default to False — all 20 existing Ninja Scraper missions load unchanged; NINJA_PROXY_URL no-op when absent
- [Phase 09]: 13 entries added to COLLECTOR_DEFINITIONS (not 14 as stated in must_haves.truths) — action section listed 13 distinct sources; action is authoritative
- [Phase 09]: Daily timer uses After=lobsec.service + Wants= (not Requires=) — DirectPythonCollector bypasses Ninja Scraper, only needs environment not gateway uptime
- [Phase 09-tier-c-collection]: 13 entries added to COLLECTOR_DEFINITIONS (not 14 as stated in must_haves.truths) — action section listed 13 distinct sources; action is authoritative. Total = 33 collectors.
- [Phase 10-01]: Direct DB write pattern for batch analysis — analyze_stationarity.py and analyze_granger.py write directly to SQLite, bridge stdout carries summary JSON only (not full result sets)
- [Phase 10-01]: Cross-correlation lag used as best_lag in granger_results — overrides Granger test best lag, more interpretable for downstream composite weighting
- [Phase 10-01]: Bonferroni N = total (signal, target) pairs computed before test loop — correct scope for batch mode (existing granger.py used N = maxlag, incorrect for batch)
- [Phase 10-03]: runStep() helper centralizes runPython call, analysis_log writes, and error handling — called 6 times for 6 pipeline steps (single call site, not duplicated)
- [Phase 10-03]: Digest gated on >= 3 Granger signals from last 24h — ensures digest only sent after a fresh pipeline run with validated signals (not stale historical results)
- [Phase 10-03]: Digest skip logged to analysis_log with reason — audit trail shows why digest was not dispatched when insufficient signals
- [Phase 10-statistical-analysis]: Area signal split for composite: bayut/propertyfinder/ejari = area-level signals; all other sources = city-wide signals contributing to both area and dubai composites
- [Phase 10-02]: Affordability rent normalization: ejari avg_rent_per_sqft * 750 sqft / 12 months for monthly 1BR cost estimate (typical Dubai 1BR)
- [Phase 10-statistical-analysis]: analyze.sh has no health check for Ninja Scraper — pipeline reads from SQLite not from scraper; no uptime dependency
- [Phase 11-01]: Chronological 70/30 split only — series[:train_n] and series[train_n:], NO random split. Monthly time-series data is not IID; shuffling introduces look-ahead bias.
- [Phase 11-01]: COALESCE(downweight_factor, 1.0) in composite LEFT JOIN ensures backward compatibility before validation has run
- [Phase 11-01]: Signals with < 12 obs are skipped (validated=1, factor=1.0) — insufficient history makes out-of-sample testing meaningless, not penalized
- [Phase 11-01]: SQLite multi-column IN workaround — used string concatenation key (a||'|'||b||'|'||c) since SQLite lacks tuple/row constructor IN syntax
- [Phase 11]: PROD-02 alert threshold >= 0.6 at area level ONLY — no city-wide threshold; tanh(weighted_avg/2) distress scaling
- [Phase 11]: Granger weight 1/pvalue for significant signals, equal weight 1.0 otherwise — same pattern for PROD-02 and future products
- [Phase 11-03]: Off-plan classification: keywords ["off-plan", "offplan", "pre-registration"] from procedure_name_en; graceful skip when column absent
- [Phase 11-03]: PROD-04 forward curve requires >= 3 points for linearSlope; projects 12 months; floors at 0 (negative extrapolation meaningless for unit counts)
- [Phase 11-03]: PROD-04 city-wide fallback: permits/DEWA try area-prefixed metrics first, then bare metric name
- [Phase 11-03]: PROD-03 gross yield: uses 750 sqft 1BR proxy constant (ejari avg_rent_per_sqft * 750 * 12 / sale_price * 100)
- [Phase 11]: [Phase 11-04]: Distress digest uses composite_scores proxy (score <= -0.6) not full PROD-02 17-signal calculation — approximation sufficient for monthly digest alerting
- [Phase 11-04]: Task 3 human-verify checkpoint approved by user — production deployment of all 8 intelligence products confirmed operational
- [Phase 12]: Hand-rolled Levenshtein over npm library: 20-line DP matrix sufficient, avoids dependency weight
- [Phase 12]: resolveAreaOrError helper centralises ambiguity/unknown error messaging across 6 area-param tools
- [Phase 12]: detectGaps requires frequency arg — always pass info.metadata.frequency
- [Phase 12]: 13 total tools not 14 — uae_collection_status is one of 5 operational tools so 8+5=13
- [Phase 12-03]: nftables domain comment whitelist (not IP sets) avoids CDN rotation breakage while satisfying domain documentation requirement (SEC-03)
- [Phase 12-03]: Reddit context-based credential patterns (client_id/secret env assignments) not refresh token regex — PRAW tokens have no fixed prefix, broad patterns risk UUID false positives

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

Last session: 2026-03-16
Stopped at: Completed 12-01-PLAN.md. area-normalizer.ts + 8 product tools registered in plugin index.ts.
Resume file: .planning/phases/12-plugin-tools-telegram-hardening/12-01-SUMMARY.md
Next: Phase 12 Plan 02 — 5 operational tools + Python scripts (TOOL-09..13, QUAL-02, QUAL-05). Phase 12 Plan 03 — security hardening (SEC-03..05). Both are wave 1 parallel.
Key context: Phase 11 complete. All 8 products deployed to /opt/lobsec/plugins/lobsec-uae-re/dist/products/. validation_results table in production DB. Digest has distress alerting. lobsec service active and verified by user.
User action needed: Register for Dubai Pulse API credentials. Store Reddit API credentials in HSM. Set up residential proxy for Google Maps foot traffic.
| Job posting aggregation not listings | Store weekly counts per sector/seniority (total_postings, postings_by_sector, postings_by_seniority, median_salary), not individual listings. Thousands/week would be too large and mostly noise. |
| Graceful failure on job platforms | skip_on_403 + skip_on_captcha, no retry on block. Aggressive retry accelerates bans. Weekly cycle allows temporary blocks to clear. Bayt/Indeed/GulfTalent provide coverage when LinkedIn blocks. |
| GulfTalent HSM-authenticated session | Credentials in HSM enable authenticated browser session for higher data quality (explicit seniority levels, better salary disclosure rates). Worth credential management overhead. |
| Seniority from salary range brackets | Junior <10K, Mid 10-25K, Senior 25-50K, Executive >50K AED/month. Based on UAE salary survey data, provides consistent classification across platforms. |
| 3 frequency-based timers not source-specific | Weekly/monthly/quarterly timers run multiple sources at each frequency, avoiding SQLite write contention from 20 concurrent timers. Orchestrator (collect.sh) handles sequential execution. |
| Non-overlapping timer schedules | Weekly/monthly at 02:00 UTC, quarterly at 05:00 UTC spreads load. Persistent=true ensures missed runs execute on boot. |
| Timeout by frequency | Weekly 30min (8 sources), monthly/quarterly 60min (6-7 sources). Accommodates browser automation overhead. |
| Deployment via cp not pip | Matches lobsec service pattern. YAML missions cp to /opt/lobsec/scraper/missions/, Python normalizers to /opt/lobsec/plugins/lobsec-uae-re/, restart service to hotload. |
