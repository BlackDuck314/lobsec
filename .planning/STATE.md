---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: unknown
last_updated: "2026-03-16T12:04:29.915Z"
progress:
  total_phases: 6
  completed_phases: 6
  total_plans: 23
  completed_plans: 23
---

# Project State

## Current Position

Phase: 10 of 12 -- Statistical Analysis Pipeline (COMPLETE)
Plan: 4 of 4 -- COMPLETE. analyze.sh, systemd timer, full production deployment.
Status: Phase 10 complete. analyze.sh + lobsec-uae-analyze.timer deployed. All 6 Python analysis modules running. Pipeline verified end-to-end (26 analysis_log entries). SCHED-06, SEC-06, SEC-07 fulfilled. Next run: 2026-03-25 02:00 UTC.
Last activity: 2026-03-16 — Plan 10-04 complete. 2/2 tasks done (1 auto + 1 human-verify checkpoint approved). Phase 10 fully complete. Ready for Phase 11 (Intelligence Products).

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
Stopped at: Completed 10-04-PLAN.md — analyze.sh, systemd timer, full production deployment. Phase 10 complete.
Resume file: .planning/phases/10-statistical-analysis/10-04-SUMMARY.md
Next: Phase 11 — Intelligence Products (PROD-01..08, QUAL-01, QUAL-03).
Key context: Phase 10 fully complete. Statistical analysis pipeline deployed and verified. lobsec-uae-analyze.timer fires 25th 02:00 UTC. All 6 Python modules (stationarity, granger, composite, anomalies, affordability, expat_funnel) deployed. 5 new DB tables populated. 26 analysis_log entries confirmed. 3 bugs auto-fixed (CHECK constraint, area_name column x2).
User action needed: Register for Dubai Pulse API credentials (enables DLD, Ejari, Building Permits, DEWA — 4 of 7 Tier A collectors). Store Reddit API credentials in HSM for collect_sentiment.py. Set up residential proxy service for Google Maps foot traffic (NINJA_PROXY_URL).
| Job posting aggregation not listings | Store weekly counts per sector/seniority (total_postings, postings_by_sector, postings_by_seniority, median_salary), not individual listings. Thousands/week would be too large and mostly noise. |
| Graceful failure on job platforms | skip_on_403 + skip_on_captcha, no retry on block. Aggressive retry accelerates bans. Weekly cycle allows temporary blocks to clear. Bayt/Indeed/GulfTalent provide coverage when LinkedIn blocks. |
| GulfTalent HSM-authenticated session | Credentials in HSM enable authenticated browser session for higher data quality (explicit seniority levels, better salary disclosure rates). Worth credential management overhead. |
| Seniority from salary range brackets | Junior <10K, Mid 10-25K, Senior 25-50K, Executive >50K AED/month. Based on UAE salary survey data, provides consistent classification across platforms. |
| 3 frequency-based timers not source-specific | Weekly/monthly/quarterly timers run multiple sources at each frequency, avoiding SQLite write contention from 20 concurrent timers. Orchestrator (collect.sh) handles sequential execution. |
| Non-overlapping timer schedules | Weekly/monthly at 02:00 UTC, quarterly at 05:00 UTC spreads load. Persistent=true ensures missed runs execute on boot. |
| Timeout by frequency | Weekly 30min (8 sources), monthly/quarterly 60min (6-7 sources). Accommodates browser automation overhead. |
| Deployment via cp not pip | Matches lobsec service pattern. YAML missions cp to /opt/lobsec/scraper/missions/, Python normalizers to /opt/lobsec/plugins/lobsec-uae-re/, restart service to hotload. |
