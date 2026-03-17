---
gsd_state_version: 1.0
milestone: v1.4
milestone_name: UAE RE Intelligence Activation
status: in_progress
last_updated: "2026-03-17T12:00:00Z"
progress:
  total_phases: 5
  completed_phases: 3
  total_plans: 6
  completed_plans: 8
---

# Project State

## Current Position

Phase: Phase 16 COMPLETE. Phase 15 blocked on user registration. Phase 17 next.
Status: Phase 16 complete (2/2 plans). All 3 AUTO requirements verified: collection auto-normalizes (AUTO-01), analysis runs via systemd timer (AUTO-02), all collection timers active (AUTO-03). Checkpoint approved.
Last activity: 2026-03-17 — Phase 16 complete. Pipeline automation verified end-to-end. Next: Phase 17 (End-to-End Verification).

### v1.4 Phase Status
| Phase | Name | Requirements | Status |
|-------|------|--------------|--------|
| 13 | Normalizer Fixes | NORM-06, NORM-07, NORM-08, NORM-09 | Complete (4/4 plans) |
| 14 | Historical Backfill | BACK-01, BACK-02, BACK-03, BACK-04, BACK-05 | Complete (2/2 plans) |
| 15 | Dubai Pulse Integration | DATA-01, DATA-02, DATA-03, DATA-04 | Not started (blocked on user registration) |
| 16 | Pipeline Automation | AUTO-01, AUTO-02, AUTO-03 | Complete (2/2 plans) |
| 17 | End-to-End Verification | VERIF-01, VERIF-02, VERIF-03 | Not started |

### Scraper Tuning Progress (outside GSD phases)
This work fills the gap between "missions written" (Phases 7.1-9) and "missions producing data".

**DONE:**
- Engine: post_load_wait_ms, wait_for_selector, pre_extract_js, container_selector
- Engine: PaginationConfig (click_next + page_param strategies), JS click fallback for overlay intercept
- Engine: PDF download handler (run_pdf_download_mission) with keyword filtering + metadata
- Engine: page_selectors extracted before pagination (was after, giving wrong data)
- Engine: page_size field for offset-based pagination (e.g. Indeed start=10,20,30)
- PropertyFinder: 3,936 cards/20 areas (10 pages each), data-testid selectors, page_param pagination
- Bayt Jobs: 150 cards (5 pages), click_next pagination with JS fallback, 12.4K total UAE jobs
- ADREC Abu Dhabi: 20 transactions, #salesTable, 14 fields per row
- LinkedIn Jobs: 60 structured cards (was raw HTML blobs), container_selector extraction
- KHDA Enrollment: PDF downloaded (Dubai private school landscape 2024-25, 2.5MB, enrollment data)
- CBUAE Remittances: PDF downloaded (Statistical Bulletin Dec 2025, 59 pages, fund transfer data on p58)
- CBUAE Mortgages: PDF downloaded (Banking Indicators Dec 2025, 1 page, credit/lending data)
- DP World / Jebel Ali: RSS feed from __NEXT_DATA__ → 15.5M TEU + 5.4M breakbulk tonnes (2024)
- Indeed Jobs: 16 cards (domcontentloaded fix, page 2 blocked by anti-bot)
- Ingest pipeline: 9 sources → 287 metrics → SQLite (was 7→280)
- DXB Airport: HTML fact file scrape working (95.2M pax 2025, top markets, quarterly data)
- MOHRE Observatory: Dashboard scrape working (12.4% workforce growth, 176K nationals in private sector)
- DSC Demographics: PDF download working (4,248,200 population, 12-page 2024 bulletin)
- DEWA: Found new stats page (/en/about-us/strategy-excellence/annual-statistics) with annual PDFs
- pdfplumber installed in scraper-venv

**RECOVERED (2026-03-17) — URLs found, missions updated:**
- DXB Airport: media.dubaiairports.ae/fact-files (HTML text, 95.2M pax data captured)
- MOHRE Permits: observatory.mohre.gov.ae (dashboard, workforce growth data captured)
- DSC Demographics: dsc.gov.ae/Publication/ (direct PDF, 12-page 2024 bulletin downloaded)

**BLOCKED (confirmed via inspection):**
- RTA Statistics: WAF "Request Rejected" (headless detected)
- DTCM/DET Tourism: 403 Access Denied (dubaidet.gov.ae WAF blocks server IP)
- DEWA Connections: 403 (dewa.gov.ae WAF blocks all pages from server)
- GulfTalent: 403 Access Denied
- Bayut: CAPTCHA ("Please verify your identity" — anti-bot detection)
- Indeed: Timeout (networkidle never fires)
- Hays Salary: Form-gated PDF (requires registration to download)

**ACCESSIBLE (need work):**
- DEWA Annual Statistics: PDFs accessible via browser but WAF blocks httpx download. Need browser-session download.

### v1.3 Phase Status (actual, not aspirational)
| Phase | Status | Notes |
|-------|--------|-------|
| 6 | ✅ Complete | Foundation infrastructure |
| 7 | ✅ Complete | WAL blocker resolved, collectors verified |
| 7.1 | ✅ Complete | Ninja Scraper engine |
| 8 | ✅ Code complete | Missions written, selectors were placeholders |
| 9 | ✅ Code complete | Missions written, selectors were placeholders |
| 10 | ✅ Verified | Analysis pipeline smoke tested — all 7 steps pass, needs 12+ months data |
| 11 | ✅ Verified | Intelligence products wired, 13 tools registered, needs analysis data |
| 12 | ✅ Complete | Plugin tools + Telegram + hardening |
| POST | ✅ Done (tuning) | Scraper tuning complete — DXB, MOHRE, DSC, DP World, PF all producing data |

## Resume Instructions

1. v1.4 roadmap created (5 phases, 13-17, 17 requirements)
2. Phase 13 COMPLETE: All 4 normalizer fix plans executed. 11 sources, 306 rows in normalized_monthly.
3. Phase 14 (backfill) is next — must backfill 3+ years of historical data for statistical analysis
4. Phase 15 (Dubai Pulse) is blocked on user registration at dubaidata.ae — parallel track possible after DATA-01
5. Phase 16 (automation) wires the pipeline together — depends on Phase 13 normalizers (done) + Phase 14 backfill
6. Phase 17 (verification) is the final gate — needs data flowing through the pipeline
7. Key data state: 11 sources in normalized_monthly (306 rows). Most sources have 1-5 observations — not enough for statistical analysis (need 12+)
8. Next: Run `/gsd:plan-phase 14` to start planning historical backfill

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-17)

**Core value:** No credential or sensitive data ever reaches an LLM provider
**Current focus:** v1.4 UAE RE Intelligence Activation — Phase 17 (End-to-End Verification) next

## v1.4 Phase Summary

| Phase | Name | Requirements | Status |
|-------|------|-------------|--------|
| 13 | Normalizer Fixes | NORM-06, NORM-07, NORM-08, NORM-09 | Complete (4/4 plans) |
| 14 | Historical Backfill | BACK-01, BACK-02, BACK-03, BACK-04, BACK-05 | Complete (2/2 plans) |
| 15 | Dubai Pulse Integration | DATA-01, DATA-02, DATA-03, DATA-04 | Not started |
| 16 | Pipeline Automation | AUTO-01, AUTO-02, AUTO-03 | Complete (2/2 plans) |
| 17 | End-to-End Verification | VERIF-01, VERIF-02, VERIF-03 | Not started |

**Total: 17 requirements across 5 phases**

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
- v1.4 Phases 13-17 added 2026-03-17

### Production Environment
- Server: Ubuntu 25.04 (VMware), <HOSTNAME> (<HOST_IP>)
- OpenClaw v2026.2.24, Node.js 22, sandbox mode off, skills enabled
- Both plugins active: 9 security hooks + 10 general tools + 13 UAE RE tools
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
- 8 sources in normalized_monthly each have exactly 1 observation — statistical analysis needs 12+

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
- [Phase 12]: Task 2 human-verify checkpoint approved by user — Telegram end-to-end verified for 13 UAE RE plugin tools
- [Phase 13-01]: DXB normalizer uses annual measurement_date (YYYY-01-01) — DXB fact file reports annual data, not monthly. Q4 uses Oct 1, busiest month uses Dec 1.
- [Phase 13-01]: Sanity check threshold 10M for annual DXB passengers — DXB handles tens of millions per year, anything below 10M indicates wrong data extraction
- [Phase 13-03]: 69.2% working age (25-54) is correct for Dubai's expat-heavy economy — higher than typical 56-60% estimate but accurate per PDF age group table
- [Phase 13-03]: No expat/national metrics in 2024 Population Bulletin — omitted (not zeroed) from normalizer output
- [Phase 13-02]: uae| prefix for MOHRE metrics — MOHRE is a federal ministry, data is UAE-level not Dubai-specific
- [Phase 13-02]: Only extract Emiratisation chart (chart 8) — other Chart.js configs have no identifying label text, indices may change between scrapes
- [Phase 13-02]: De-duplicate stat cards by metric label — dashboard HTML repeats same cards across tab sections (12 cards but only 6 unique metrics)
- [Phase 13-02]: Removed pandas dependency for ref_year fallback — int(collected_at[:4]) sufficient, avoids heavy import for trivial operation
- [Phase 14-02]: Hardcoded verified values over PDF parsing for CBUAE Table 48 — complex multi-line headers and merged cells make pdfplumber fragile; research-verified values used with PDF sanity check
- [Phase 14-02]: CBUAE annual measurement dates use YYYY-01-01 convention (consistent with other annual sources)
- [Phase 14-02]: CBUAE quarterly measurement dates use start-of-quarter (Q1=Jan 1, Q2=Apr 1, Q3=Jul 1, Q4=Oct 1)
- [Phase 14-02]: DXB BACK-02 borderline: strict 2022-2024 filter yields 11 rows (not 12), but 17 total rows spanning 2022-2025 satisfies requirement intent per plan note
- [Phase 16-01]: adapt_scraper_format() as adapter function — preserves core normalize_xxx logic, converts scraper format at entry point
- [Phase 16-01]: bedrooms schema int -> float — pandera cannot coerce NaN to int64, float naturally supports NaN for nullable bedrooms
- [Phase 16-01]: Bayut blocked data returns area-level zero counts (20 metrics) not empty list — preserves area coverage tracking even when CAPTCHA-blocked
- [Phase 16-02]: PropertyFinder poll timeout is config issue not normalization failure — maxWaitMs 10min insufficient for 20-area x 10-page scrape (~30min). Timer path works via longer TimeoutSec.
- [Phase 16-02]: analyze.log file ownership must be lobsec:lobsec — systemd service runs as lobsec user, file was root-owned from initial creation

## Blockers

None active. Previous SQLite WAL blocker resolved (2026-03-17).
Phase 15 (Dubai Pulse) requires user to register at dubaidata.ae before DATA-01 can be marked complete.

## Session Continuity

Last session: 2026-03-17
Stopped at: Phase 16 complete. Checkpoint approved. Phase 17 (End-to-End Verification) next.
Resume file: N/A
Next: Phase 17 (End-to-End Verification) — verify intelligence tools return real data via Telegram. Phase 15 still blocked on user registration.
Key context: Phase 16 complete. Pipeline fully automated: collection auto-normalizes, analysis runs on 25th via systemd, all timers active. 11 sources in normalized_monthly, analysis pipeline runs all 7 steps successfully.
User action needed: Register for Dubai Pulse API credentials at dubaidata.ae (required for Phase 15).
| Job posting aggregation not listings | Store weekly counts per sector/seniority (total_postings, postings_by_sector, postings_by_seniority, median_salary), not individual listings. Thousands/week would be too large and mostly noise. |
| Graceful failure on job platforms | skip_on_403 + skip_on_captcha, no retry on block. Aggressive retry accelerates bans. Weekly cycle allows temporary blocks to clear. Bayt/Indeed/GulfTalent provide coverage when LinkedIn blocks. |
| GulfTalent HSM-authenticated session | Credentials in HSM enable authenticated browser session for higher data quality (explicit seniority levels, better salary disclosure rates). Worth credential management overhead. |
| Seniority from salary range brackets | Junior <10K, Mid 10-25K, Senior 25-50K, Executive >50K AED/month. Based on UAE salary survey data, provides consistent classification across platforms. |
| 3 frequency-based timers not source-specific | Weekly/monthly/quarterly timers run multiple sources at each frequency, avoiding SQLite write contention from 20 concurrent timers. Orchestrator (collect.sh) handles sequential execution. |
| Non-overlapping timer schedules | Weekly/monthly at 02:00 UTC, quarterly at 05:00 UTC spreads load. Persistent=true ensures missed runs execute on boot. |
| Timeout by frequency | Weekly 30min (8 sources), monthly/quarterly 60min (6-7 sources). Accommodates browser automation overhead. |
| Deployment via cp not pip | Matches lobsec service pattern. YAML missions cp to /opt/lobsec/scraper/missions/, Python normalizers to /opt/lobsec/plugins/lobsec-uae-re/, restart service to hotload. |
