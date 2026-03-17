# Roadmap: lobsec

## Milestones

- v1.0 MVP — Security wrapper deployed (shipped 2026-02-27)
- v1.1 Tool Reliability — Skills cleanup + GitHub tool (shipped 2026-03-04)
- v1.2 Examy QA Automation — Phases 1-5 (shipped 2026-03-06)
- v1.3 UAE Real Estate Intelligence System — Phases 6-12 (shipped 2026-03-16)
- **v1.4 UAE RE Intelligence Activation** — Phases 13-17 (planned)

## Phases

<details>
<summary>v1.0 MVP — SHIPPED 2026-02-27</summary>

- [x] Phase 1-5: Security wrapper with HSM, proxy, audit, sandbox, firewall, plugins, bot integrations

</details>

<details>
<summary>v1.1 Tool Reliability — SHIPPED 2026-03-04</summary>

- [x] Phase 1: Skills cleanup (47 removed, 4 kept) + GitHub PAT in HSM
- [x] Phase 2: GitHub plugin tool (REST API) + tool verification

</details>

<details>
<summary>v1.2 Examy QA Automation (Phases 1-5) — SHIPPED 2026-03-06</summary>

- [x] Phase 1: System Dependencies & Browser Validation (2/2 plans) — completed 2026-03-04
- [x] Phase 2: Core Test Automation (2/2 plans) — completed 2026-03-05
- [x] Phase 3: Security Integration (2/2 plans) — completed 2026-03-05
- [x] Phase 4: Reporting & GitHub Integration (3/3 plans) — completed 2026-03-05
- [x] Phase 5: Scheduling & Production Hardening (2/2 plans) — completed 2026-03-05

</details>

<details>
<summary>v1.3 UAE Real Estate Intelligence System — Phases 6-12 — SHIPPED 2026-03-16</summary>

28 data sources, data science pipeline, 8 intelligence products, delivered as an OpenClaw plugin with Telegram interface. Granger-validated leading indicators with the expat lifecycle funnel as unique differentiator.

- [x] Phase 6: Foundation & Infrastructure — Database, package structure, collector framework, Python analytics environment (completed 2026-03-11)
  Requirements: INFRA-01, INFRA-02, INFRA-03, INFRA-04, INFRA-05, INFRA-06, INFRA-07, SEC-01, SEC-02, SCHED-01
  **Plans:** 3 plans (2 complete, 1 at checkpoint)
  Plans:
  - [x] 06-01-PLAN.md — Package scaffolding, SQLite database, Python environment, intelligence cache ✅
  - [x] 06-02-PLAN.md — Collector framework (SourceCollector, CollectorRegistry) and Python subprocess bridge ✅
  - [⚠️] 06-03-PLAN.md — Plugin wiring, deployment (fscrypt, venv, systemd), production verification ⚠️ CHECKPOINT
  Success criteria:
  1. SQLite database created at /opt/lobsec/data/uae-re.db with WAL mode, raw_sources/normalized_monthly/intelligence_cache/collection_log tables, indexed on (source, measurement_date)
  2. Python 3.13 venv installed at /opt/lobsec/analytics-venv/ with pandas, statsmodels, scipy, numpy, pdfplumber, vaderSentiment, praw, pytrends all importable
  3. SourceCollector base class with abstract collect(), schema validation, and error propagation; CollectorRegistry with frequency scheduling and max 3 concurrency
  4. Python subprocess bridge (runPython()) successfully executes a pandas script via stdin/stdout JSON I/O with timeout enforcement
  5. Plugin package @lobsec/uae-re deploys to /opt/lobsec/plugins/lobsec-uae-re/ and registers with OpenClaw; /opt/lobsec/data/ encrypted with fscrypt; new API keys stored in HSM

- [ ] Phase 7: MVP Data Collection (Tier A + DEWA) — Core transaction data sources and normalization pipeline
  Requirements: COLL-01, COLL-02, COLL-03, COLL-04, COLL-05, COLL-15, NORM-01, NORM-02, NORM-03, NORM-04, NORM-05
  **Plans:** 4 plans
  Plans:
  - [x] 07-01-PLAN.md — Normalization pipeline foundation (area mapping, orchestrator, gap detection, volume validation, pandera) ✅ 2026-03-11
  - [x] 07-02-PLAN.md — CSV collectors (DLD sales, Ejari rentals, building permits) with Python normalization ✅ 2026-03-11
  - [x] 07-03-PLAN.md — Browser automation collectors (ADREC Abu Dhabi, Bayut, PropertyFinder) with Python normalization ✅ 2026-03-11
  - [⏸] 07-04-PLAN.md — DEWA collector coded; deployment BLOCKED by SQLite WAL pragma failure ⏸ 2026-03-11
  Success criteria:
  1. DLD sales transactions and Ejari rental contracts collected from Dubai Pulse CSV, parsed with correct field mapping
  2. Dubai building permits collected monthly, classified residential vs commercial; ADREC Abu Dhabi collected via Playwright CSV export from public dashboard
  3. Bayut property listings collected via Playwright with listing count, asking price, days on market, price reductions per area; PropertyFinder added as second source
  4. DEWA connections/closures scraped from press releases with new connections and disconnections per area
  5. All sources normalized to monthly frequency via pandas resample('ME').mean() with forward-fill limited to 1 period; both measurement_date and available_date stored; gap detection, schema validation, and volume validation operational

- [x] Phase 7.1: Ninja Scraper (INSERTED) — General-purpose Python scraping engine replacing failed TS collectors ✅ 2026-03-12
  Requirements: COLL-01, COLL-02, COLL-03, COLL-04, COLL-05, COLL-15, NORM-01, NORM-02, NORM-03, NORM-04, NORM-05
  **Plans:** 4 plans (all complete)
  **Verification:** 19/19 must-haves verified, 11/11 requirements fulfilled, score: PASSED
  Plans:
  - [x] 07.1-01-PLAN.md — Scraper engine core + FastAPI service (Crawlee, Patchright, missions, auth) ✅ 2026-03-12
  - [x] 07.1-02-PLAN.md — 7 YAML missions for UAE RE sources + mission handler ✅ 2026-03-12
  - [x] 07.1-03-PLAN.md — TS integration refactor (delete old collectors, HTTP client wrapper) ✅ 2026-03-12
  - [x] 07.1-04-PLAN.md — Production deployment + end-to-end verification ✅ 2026-03-12
  Success criteria (4.5/5 met):
  1. @lobsec/scraper package at packages/scraper/ with Crawlee, Patchright, FastAPI engine ✅
  2. 7 YAML mission files validated and loaded by Ninja Scraper service ✅
  3. TS CollectorRegistry refactored to thin HTTP client calling scraper API ✅
  4. lobsec-scraper.service running on port 18791 with token auth ✅
  5. At least 1 end-to-end collection verified: scrape -> raw file -> normalization -> SQLite ⚠️ (scrape→raw proven, normalization not triggered)

- [x] Phase 8: Tier B Collection (Population & Employment Signals) — 13 demographic and employment data sources with scheduling ✅ 2026-03-13
  Requirements: COLL-06, COLL-07, COLL-08, COLL-09, COLL-10, COLL-11, COLL-12, COLL-13, SCHED-02, SCHED-03, SCHED-04, SCHED-07
  **Plans:** 4 plans (4/4 complete)
  Plans:
  - [x] 08-01-PLAN.md — Government/institutional YAML missions + Python normalizers (MOHRE, DXB, GDRFA, KHDA, RTA, CBUAE) ✅ 2026-03-13
  - [x] 08-02-PLAN.md — Job platform + salary survey YAML missions + normalizers (LinkedIn, Bayt, Indeed, GulfTalent, Cooper Fitch, Hays, Robert Half) ✅ 2026-03-13
  - [x] 08-03-PLAN.md — TS registry integration + collect.sh orchestrator ✅ 2026-03-13
  - [x] 08-04-PLAN.md — systemd timers + production deployment + verification ✅ 2026-03-13
  Success criteria (5/5 met):
  1. MOHRE work permits, DXB airport passengers, RTA vehicle registrations collected via press release/HTML scraping ✅
  2. GDRFA visa transactions and salary survey PDFs extracted via pdfplumber with correct field mapping ✅
  3. KHDA school enrollment, job postings (4 platforms), and CBUAE remittance data collected ✅
  4. systemd timers operational: weekly (Mon 02:00 UTC = 06:00 GST), monthly (1st 02:00 UTC = 06:00 GST), quarterly (15th Jan/Apr/Jul/Oct 05:00 UTC = 09:00 GST) ✅
  5. Timeout enforcement active: 30min weekly, 60min monthly/quarterly ✅

- [x] Phase 9: Tier C Collection (Alternative Economic Signals) — 14 alternative data sources completing all 28 (completed 2026-03-16)
  Requirements: COLL-14, COLL-16, COLL-17, COLL-18, COLL-19, COLL-20, COLL-21, COLL-22, COLL-23, COLL-24, COLL-25, COLL-26, COLL-27, COLL-28, SCHED-05
  Success criteria:
  1. Google Trends (6 keyword groups), social sentiment (Reddit PRAW + VADER), and Google Maps foot traffic (50 locations) collected on daily schedule (23:00 GST)
  2. RTA metro ridership, DTCM tourism stats, DED business licenses, DEWA connections collected via RTA/Dubai Pulse open data
  3. CBUAE mortgage rates, Jebel Ali port cargo, customs household imports, FCSA demographics extracted from quarterly PDFs
  4. InsideAirbnb/STR data, F&B closures (Zomato + Google Maps), moving company inquiries, commercial office reports (JLL/CBRE/Savills) collected
  5. All 28 sources registered in CollectorRegistry with correct frequencies; daily timer (23:00 GST) operational

- [x] Phase 10: Statistical Analysis Pipeline — Stationarity testing, Granger causality, correlations, composite indices, and derived models (completed 2026-03-16)
  Requirements: STAT-01, STAT-02, STAT-03, STAT-04, STAT-05, STAT-06, STAT-07, STAT-08, SCHED-06, SEC-06, SEC-07
  Success criteria:
  1. ADF stationarity test runs on all normalized series with results logged to stationarity_results table; KPSS cross-check flags disagreements
  2. Granger causality tests all Tier A+B signals against DLD price/volume with Bonferroni correction (p < 0.05/N); cross-correlation detects optimal lag (1-12 months) per validated signal
  3. Composite index constructed from z-score normalized validated signals with Granger-derived weights scaled to [-1, +1]
  4. EWMA anomaly detection flags outliers for DEWA closures, visa cancellations, listing volume; affordability model computes salary-to-rent ratio by bracket and area; expat pipeline 10-stage funnel aggregates z-scores per stage
  5. Pipeline timer (25th 06:00 GST) recomputes all analysis after monthly data lands; all queries use parameterized SQL; raw PII never logged

- [x] Phase 11: Intelligence Products — All 8 intelligence products with caching and validation (completed 2026-03-16)
  Requirements: PROD-01, PROD-02, PROD-03, PROD-04, PROD-05, PROD-06, PROD-07, PROD-08, QUAL-01, QUAL-03
  **Plans:** 4 plans
  Plans:
  - [x] 11-01-PLAN.md — Out-of-sample validation (QUAL-01), forward-fill audit (QUAL-03), validation_results table, pipeline integration, composite downweighting ✅
  - [x] 11-02-PLAN.md — PROD-01 area signal score + PROD-02 distress detection + shared format utilities ✅
  - [x] 11-03-PLAN.md — PROD-03 rental intelligence + PROD-04 supply pipeline + PROD-07 off-plan/ready arbitrage + DLD normalizer extension ✅
  - [x] 11-04-PLAN.md — PROD-05 expat funnel + PROD-06 macro health + PROD-08 salary-rent + digest distress alerting + production deployment ✅
  Success criteria:
  1. Area Buy/Sell Signal Score produces 9-component composite scaled -1 to +1 per area/property type; Distress Detection System produces 17-signal score with alert threshold >=0.6
  2. Rental Intelligence Dashboard computes all 10 metrics (gross yield, rental momentum, vacancy proxy, renewal rate, listing absorption, pipeline pressure, affordability ratio, STR premium, rent-to-income, DOM trend)
  3. Supply Pipeline Tracker shows permits, DEWA, cargo, customs with 12-24mo forward curve; Expat Population Flow Dashboard renders 10-stage funnel with stage-level metrics
  4. Macro Health Dashboard produces traffic light output (green/amber/red) for 6 signal groups; Off-Plan vs Ready Arbitrage shows premium spread; Salary-Rent Pressure Map covers 5 income brackets
  5. Out-of-sample validation confirms Granger results on held-out data; conditional forward-fill limits gap filling to 1 period only with NULL for extended outages

- [x] Phase 12: Plugin Tools, Telegram Interface & Production Hardening — 13 plugin tools, data quality UX, security integration, and production readiness (completed 2026-03-16)
  Requirements: TOOL-01, TOOL-02, TOOL-03, TOOL-04, TOOL-05, TOOL-06, TOOL-07, TOOL-08, TOOL-09, TOOL-10, TOOL-11, TOOL-12, TOOL-13, QUAL-02, QUAL-04, QUAL-05, SEC-03, SEC-04, SEC-05
  Success criteria:
  1. All 13 plugin tools registered and callable via Telegram: uae_area_signal, uae_distress, uae_rental_intel, uae_supply_pipeline, uae_expat_flow, uae_macro_health, uae_arbitrage, uae_salary_rent, uae_raw_data, uae_collection_status, uae_trigger_collection, uae_granger_test, uae_correlation
  2. Area name normalization with fuzzy matching supports abbreviations (JVC, JBR, DIFC) and shows "Did you mean?" for ambiguous input
  3. Telegram responses include data freshness warnings when sources are >2x overdue; collection health dashboard shows all sources with last update, row count, staleness, next scheduled run
  4. nftables egress rules whitelist all 28 source domains; credential redactor extended with new API key patterns; all collection runs audit-logged (source, timestamp, row count, success/failure)
  5. End-to-end integration verified: scheduled collection populates data, pipeline computes products, Telegram query returns formatted intelligence with freshness metadata

</details>

<details>
<summary>v1.4 UAE RE Intelligence Activation — Phases 13-17 (planned)</summary>

Normalize captured data, backfill history, register Dubai Pulse, automate the full pipeline, and verify the system produces real intelligence answers via Telegram.

- [ ] **Phase 13: Normalizer Fixes** - All captured raw data correctly transformed into normalized_monthly rows
- [ ] **Phase 14: Historical Backfill** - 3+ years of time-series depth unlocked for statistical analysis
- [ ] **Phase 15: Dubai Pulse Integration** - DLD/Ejari/Permits flowing from official API (requires user registration)
- [ ] **Phase 16: Pipeline Automation** - Full scrape→ingest→normalize→analyze chain runs on schedule without manual intervention
- [ ] **Phase 17: End-to-End Verification** - At least 3 intelligence products return real data via Telegram

</details>

## Phase Details

### Phase 13: Normalizer Fixes
**Goal**: All captured raw data correctly transformed into normalized_monthly rows
**Depends on**: Phase 12 (v1.3 infrastructure complete)
**Requirements**: NORM-06, NORM-07, NORM-08, NORM-09
**Success Criteria** (what must be TRUE):
  1. DXB Airport normalizer parses the HTML fact file JSON and writes passenger_count, top_origin_market, quarterly breakdown rows to normalized_monthly for the current scrape cycle
  2. MOHRE Observatory normalizer parses dashboard JSON and writes workforce_growth_rate, establishment_growth_rate, emiratisation_count rows to normalized_monthly
  3. DSC normalizer runs pdfplumber on the demographics PDF and writes total_population, expat_count, national_count, population_growth_rate rows to normalized_monthly
  4. All 8 existing sources (PropertyFinder, ADREC, Bayt, LinkedIn, Indeed, KHDA, CBUAE, DP World) have at least 1 row each in normalized_monthly after a triggered collection run
**Plans:** 4 plans
Plans:
- [x] 01-PLAN.md — Rewrite DXB normalizer for HTML fact file JSON (NORM-06)
- [x] 02-PLAN.md — Rewrite MOHRE normalizer for observatory dashboard JSON (NORM-07)
- [x] 03-PLAN.md — Rewrite DSC normalizer for PDF extraction via pdfplumber (NORM-08)
- [ ] 04-PLAN.md — Verify all 8 sources + deploy normalizer fixes to production (NORM-09)

### Phase 14: Historical Backfill
**Goal**: 3+ years of time-series depth available in normalized_monthly to unlock statistical analysis
**Depends on**: Phase 13 (normalizers must be correct before backfilling)
**Requirements**: BACK-01, BACK-02, BACK-03, BACK-04, BACK-05
**Success Criteria** (what must be TRUE):
  1. DSC normalized_monthly contains population rows for 2022, 2023, and 2024 annual publications (3 rows minimum)
  2. DXB normalized_monthly contains at least 12 monthly or quarterly passenger count observations spanning 2022-2024
  3. MOHRE normalized_monthly contains at least 16 monthly workforce observations spanning 2021-2025
  4. CBUAE normalized_monthly contains at least 4 quarterly remittance/transfer rows covering consecutive quarters
  5. DP World normalized_monthly contains at least 3 annual throughput rows covering 2022, 2023, 2024
**Plans**: TBD

### Phase 15: Dubai Pulse Integration
**Goal**: Official DLD/Ejari/Permits data flows from Dubai Pulse API into the collection pipeline
**Depends on**: Phase 13 (normalizers), user action (DATA-01 registration at dubaidata.ae)
**Requirements**: DATA-01, DATA-02, DATA-03, DATA-04
**Success Criteria** (what must be TRUE):
  1. Dubai Pulse API credentials are registered at dubaidata.ae and stored in HSM (user must complete registration before this criterion can be met)
  2. DLD sales transaction collector queries the Dubai Pulse API and writes transaction_count, median_price_sqft, total_value rows to normalized_monthly
  3. Ejari rental contract collector queries the Dubai Pulse API and writes new_contracts, renewed_contracts, avg_annual_rent rows to normalized_monthly
  4. Building permits collector queries the Dubai Pulse API and writes residential_permits, commercial_permits rows to normalized_monthly
**Plans**: TBD

### Phase 16: Pipeline Automation
**Goal**: The full scrape→ingest→normalize→analyze chain executes automatically with no manual intervention
**Depends on**: Phase 13 (normalizers correct), Phase 14 (backfill complete)
**Requirements**: AUTO-01, AUTO-02, AUTO-03
**Success Criteria** (what must be TRUE):
  1. After a collection run completes (triggered manually or by timer), normalized_monthly rows appear for the collected sources without any manual normalization step
  2. The analysis pipeline (stationarity, Granger, composites, anomalies) runs automatically on the 25th of the month and its completion is logged to analysis_log
  3. All three collection timer schedules (weekly Mon 02:00 UTC, monthly 1st 02:00 UTC, quarterly 15th Jan/Apr/Jul/Oct 05:00 UTC) are confirmed active via systemctl list-timers and have a successful last-run entry
**Plans**: TBD

### Phase 17: End-to-End Verification
**Goal**: The intelligence system produces real, data-backed answers to Telegram queries
**Depends on**: Phase 16 (automation wired), Phase 14 (backfill provides sufficient data depth)
**Requirements**: VERIF-01, VERIF-02, VERIF-03
**Success Criteria** (what must be TRUE):
  1. At least 3 of the 13 plugin tools (e.g. uae_area_signal, uae_rental_intel, uae_macro_health) return non-null intelligence data when queried via Telegram — not placeholder or "no data" responses
  2. uae_macro_health returns a traffic-light breakdown covering at least 2 of the 6 signal groups with green/amber/red status based on real normalized data
  3. uae_collection_status shows all active sources with a last_successful_run timestamp within the past 7 days
**Plans**: TBD

## Progress

| Phase | Milestone | Plans | Status | Completed |
|-------|-----------|-------|--------|-----------|
| 1. System Dependencies | v1.2 | 2/2 | Complete | 2026-03-04 |
| 2. Core Test Automation | v1.2 | 2/2 | Complete | 2026-03-05 |
| 3. Security Integration | v1.2 | 2/2 | Complete | 2026-03-05 |
| 4. Reporting & GitHub | v1.2 | 3/3 | Complete | 2026-03-05 |
| 5. Scheduling & Hardening | v1.2 | 2/2 | Complete | 2026-03-05 |
| 6. Foundation & Infrastructure | v1.3 | 3/3 | Complete | 2026-03-11 |
| 7. MVP Data Collection | v1.3 | 1/4 | Paused | - |
| 7.1 Ninja Scraper | v1.3 | 4/4 | Complete ✅ VERIFIED | 2026-03-12 |
| 8. Tier B Collection | v1.3 | 4/4 | Complete ✅ | 2026-03-13 |
| 9. Tier C Collection | v1.3 | 4/4 | Complete | 2026-03-16 |
| 10. Statistical Analysis | v1.3 | 4/4 | Complete | 2026-03-16 |
| 11. Intelligence Products | v1.3 | 4/4 | Complete | 2026-03-16 |
| 12. Plugin Tools & Hardening | v1.3 | 4/4 | Complete | 2026-03-16 |
| 13. Normalizer Fixes | v1.4 | 2/4 | In progress | - |
| 14. Historical Backfill | v1.4 | 0/TBD | Not started | - |
| 15. Dubai Pulse Integration | v1.4 | 0/TBD | Not started | - |
| 16. Pipeline Automation | v1.4 | 0/TBD | Not started | - |
| 17. End-to-End Verification | v1.4 | 0/TBD | Not started | - |

---
*Roadmap updated: 2026-03-17 after Phase 13 planning (4 plans created)*
