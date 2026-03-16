# Requirements: UAE Real Estate Intelligence System

**Defined:** 2026-03-11
**Core Value:** Predict UAE real estate market movements through Granger-validated leading indicators derived from 28 heterogeneous data sources, with the expat lifecycle funnel as the unique differentiator no competitor offers.

## v1.3 Requirements

Requirements for the UAE RE intelligence system. All 28 sources, 8 intelligence products, delivered as an OpenClaw plugin with Telegram interface.

### Infrastructure

- [x] **INFRA-01**: SQLite database (`uae-re.db`) with WAL mode, indexed on `(source, measurement_date)`, stored under fscrypt-encrypted `/opt/lobsec/data/`
- [x] **INFRA-02**: Python 3.13 venv at `/opt/lobsec/analytics-venv/` with pandas, statsmodels, scipy, numpy, pdfplumber, vaderSentiment, praw, pytrends
- [x] **INFRA-03**: Collector base class (`SourceCollector`) with abstract `collect()` method, schema validation, and error propagation
- [x] **INFRA-04**: Collector Registry with frequency-based scheduling, dependency resolution, and controlled concurrency (max 3 concurrent)
- [x] **INFRA-05**: Python subprocess bridge (`runPython()`) with JSON I/O via stdin/stdout, timeout enforcement, and error handling
- [x] **INFRA-06**: Intelligence cache layer with TTL-based expiry (1hr default), params hash as key, stored in SQLite `intelligence_cache` table
- [x] **INFRA-07**: `@lobsec/uae-re` package structure deployed as OpenClaw plugin at `/opt/lobsec/plugins/lobsec-uae-re/`

### Data Collection -- Tier A (Core Transaction Data)

- [x] **COLL-01**: DLD sales transactions -- weekly CSV download from Dubai Pulse, fields: trans_group_en, actual_worth, meter_sale_price, prop_type_en, area_name_en, rooms_en, trans_date ✅ 2026-03-11
- [x] **COLL-02**: Ejari rental contracts -- filtered from same DLD CSV (trans_group_en=Rent), derived: renewal_rate, avg_rent_per_sqft, rent_YoY_change ✅ 2026-03-11
- [x] **COLL-03**: Dubai building permits -- monthly CSV from Dubai Pulse, classify residential vs commercial, track permit withdrawal/expiry ✅ 2026-03-11
- [x] **COLL-04**: DARI Abu Dhabi -- headless browser scrape with UAE Pass authentication (Playwright), extract transaction summaries
- [x] **COLL-05**: Property listings -- Bayut via Apify scraper, extract: listing count, asking price, days on market (DOM), price reductions per area

### Data Collection -- Tier B (Population & Employment Signals)

- [ ] **COLL-06**: MOHRE work permits -- monthly press release scrape, extract new permits issued by sector/nationality
- [ ] **COLL-07**: DXB airport passengers -- monthly stats from dubaiairports.ae, extract arrival/departure volumes
- [ ] **COLL-08**: GDRFA visa transactions -- quarterly report PDF extraction, visa issuances and cancellations by type
- [ ] **COLL-09**: KHDA school enrollment -- annual census, enrollment by curriculum, withdrawal rate tracking
- [ ] **COLL-10**: RTA vehicle registrations -- monthly from Dubai Pulse, new registrations vs deregistrations
- [ ] **COLL-11**: Job postings aggregation -- LinkedIn/Bayt/Indeed via Apify, segmented by seniority and sector
- [ ] **COLL-12**: Salary surveys -- annual PDFs (Cooper Fitch, Hays, Robert Half), extract median salaries by role/seniority
- [ ] **COLL-13**: Remittance outflows -- quarterly CBUAE report, total personal remittances

### Data Collection -- Tier C (Alternative Economic Signals)

- [x] **COLL-14**: Google Trends -- pytrends API, 6 keyword groups (buy/rent/expat/distress/luxury/exit)
- [x] **COLL-15**: DEWA connections/closures -- press release scrape, new connections and disconnections per area
- [x] **COLL-16**: RTA metro ridership -- monthly from RTA open data, station-level ridership
- [x] **COLL-17**: CBUAE mortgage rates -- quarterly PDF extraction, EIBOR + mortgage outstanding
- [x] **COLL-18**: DTCM tourism stats -- monthly from dubaitourism.ae, hotel occupancy, visitor numbers
- [ ] **COLL-19**: InsideAirbnb/STR data -- quarterly bulk download + Apify weekly, occupancy and ADR
- [x] **COLL-20**: Jebel Ali port cargo -- monthly from DP World press releases, construction material volumes
- [ ] **COLL-21**: F&B closures -- Zomato API + Google Maps permanently_closed tracking
- [ ] **COLL-22**: Dubai customs household imports -- quarterly CBUAE foreign trade stats, furniture/household goods
- [x] **COLL-23**: DED business licenses -- monthly from Dubai Pulse, new vs cancelled licenses by sector
- [x] **COLL-24**: Social sentiment -- Reddit (r/dubai, r/dubairealestate) via PRAW + VADER compound score
- [x] **COLL-25**: FCSA demographics -- annual population estimates, age/nationality breakdown
- [ ] **COLL-26**: Google Maps foot traffic -- weekly Popular Times for 50 key locations (malls, metro stations)
- [x] **COLL-27**: Moving company inquiries -- quarterly standardized quote requests, booking lead days
- [ ] **COLL-28**: Commercial office reports -- quarterly JLL/CBRE/Savills PDFs, Grade A vacancy, absorption rates

### Data Normalization & Pipeline

- [x] **NORM-01**: Monthly normalization -- all 28 sources resampled to monthly frequency via pandas `resample('ME').mean()` with forward-fill limited to 1 period
- [x] **NORM-02**: Publication date tracking -- store both `measurement_date` and `available_date` for every data point to prevent look-ahead bias
- [x] **NORM-03**: Gap detection -- track last successful collection per source, flag STALE when gap exceeds 2x expected frequency
- [x] **NORM-04**: Schema validation -- validate expected columns, data types, and value ranges on every collection run; fail loudly on mismatch
- [x] **NORM-05**: Data volume validation -- compare current collection row count to rolling 30-day average; alert if <50%

### Statistical Analysis

- [ ] **STAT-01**: Stationarity testing -- ADF test on all normalized series, hard gate before any Granger analysis; log results to `stationarity_results` table
- [ ] **STAT-02**: KPSS cross-check -- run KPSS alongside ADF for confirmation; flag disagreements for manual review
- [ ] **STAT-03**: Granger causality testing -- test all Tier A+B signals against DLD price/volume with Bonferroni correction (p < 0.05/N)
- [ ] **STAT-04**: Cross-correlation lag detection -- find optimal lag (1-12 months) for each validated signal via `scipy.stats.pearsonr` loop
- [ ] **STAT-05**: Composite index construction -- z-score normalize validated signals, apply Granger-derived weights, scale to [-1, +1]
- [ ] **STAT-06**: Anomaly detection -- EWMA-based outlier flagging (rolling mean +/- 2 std dev) for DEWA closures, visa cancellations, listing volume
- [ ] **STAT-07**: Affordability model -- salary-to-rent ratio by income bracket and area, using median salaries from COLL-12
- [ ] **STAT-08**: Expat pipeline flow model -- 10-stage lifecycle funnel (awareness -> job search -> visa -> housing -> settlement -> ... -> exit), z-score aggregation per stage

### Intelligence Products

- [ ] **PROD-01**: Area Buy/Sell Signal Score -- 9-component composite, scale -1 to +1, monthly update per area/property type
- [ ] **PROD-02**: Distress Detection System -- 17-signal score (8 market + 9 lifecycle), alert threshold >=0.6
- [ ] **PROD-03**: Rental Intelligence Dashboard -- 10 metrics: gross yield, rental momentum, vacancy proxy, renewal rate, listing absorption, pipeline pressure, affordability ratio, STR premium, rent-to-income, DOM trend
- [ ] **PROD-04**: Supply Pipeline Tracker -- building permits, DEWA new connections, Jebel Ali cargo, customs household imports, 12-24mo forward curve
- [ ] **PROD-05**: Expat Population Flow Dashboard -- 10-stage funnel visualization, awareness-to-exit with stage-level metrics
- [ ] **PROD-06**: Macro Health Dashboard -- 6 signal groups (employment, housing, spending, mobility, sentiment, population), traffic light output (green/amber/red)
- [ ] **PROD-07**: Off-Plan vs Ready Arbitrage Tracker -- premium spread by area, developer incentive monitoring, DLD procedure_name_en filtering
- [ ] **PROD-08**: Salary-Rent Pressure Map -- 5 income brackets, area segment mapping, migration prediction (flight risk by bracket)

### Plugin Tools & Telegram Interface

- [ ] **TOOL-01**: `uae_area_signal(area, property_type)` -- returns buy/sell score with component breakdown
- [ ] **TOOL-02**: `uae_distress(area?)` -- returns distress signals for area or top-N distressed areas
- [ ] **TOOL-03**: `uae_rental_intel(area, bedrooms)` -- returns yields, affordability, momentum, DOM
- [ ] **TOOL-04**: `uae_supply_pipeline(area?)` -- returns permit count, DEWA, cargo, delivery timeline
- [ ] **TOOL-05**: `uae_expat_flow()` -- returns 10-stage funnel with current stage metrics
- [ ] **TOOL-06**: `uae_macro_health()` -- returns traffic light dashboard with signal group details
- [ ] **TOOL-07**: `uae_arbitrage(area, property_type)` -- returns off-plan vs ready premium spread
- [ ] **TOOL-08**: `uae_salary_rent(income_bracket)` -- returns pressure map with affordable areas
- [ ] **TOOL-09**: `uae_raw_data(source, start_date, end_date)` -- returns raw CSV data for any source
- [ ] **TOOL-10**: `uae_collection_status()` -- returns last run times, row counts, and staleness flags
- [ ] **TOOL-11**: `uae_trigger_collection(source?)` -- manually trigger collection for one or all sources
- [ ] **TOOL-12**: `uae_granger_test(signal, target)` -- run Granger causality test on demand
- [ ] **TOOL-13**: `uae_correlation(signal, target, max_lag)` -- run cross-correlation analysis on demand

### Scheduling & Orchestration

- [x] **SCHED-01**: Single collector orchestrator service (`lobsec-uae-collector.service`) with controlled concurrency and priority queue
- [ ] **SCHED-02**: Weekly timer (Mon 06:00 GST) -- DLD, Ejari, listings
- [ ] **SCHED-03**: Monthly timer (1st 06:00 GST) -- permits, DARI, MOHRE, DXB, RTA, DEWA, metro, DED, DTCM
- [ ] **SCHED-04**: Quarterly timer (15th Jan/Apr/Jul/Oct 09:00 GST) -- GDRFA, CBUAE, customs, port cargo, Airbnb, moving companies, commercial reports
- [ ] **SCHED-05**: Daily timer (23:00 GST) -- Google Trends, social sentiment, foot traffic
- [ ] **SCHED-06**: Pipeline timer (25th 06:00 GST) -- recompute all intelligence products after monthly data lands
- [ ] **SCHED-07**: Timeout enforcement -- max 5min for CSV/API, 20min for browser automation, kill and alert on exceed

### Security Integration

- [x] **SEC-01**: HSM credential storage -- all new API keys (Google Maps, Reddit, Apify, Zomato, UAE Pass) in SoftHSM2 — pattern verified, keys added in Phase 7+
- [x] **SEC-02**: fscrypt encryption on `/opt/lobsec/data/` (5th encrypted directory)
- [ ] **SEC-03**: nftables egress rules -- whitelist domains for all 28 sources (Dubai Pulse, DARI, MOHRE, Apify, Google, Reddit, etc.)
- [ ] **SEC-04**: Credential redaction -- extend existing redactor with new API key patterns
- [ ] **SEC-05**: Audit logging -- all collection runs logged (source, timestamp, row count, success/failure) via existing audit infrastructure
- [ ] **SEC-06**: SQL injection prevention -- parameterized queries for all user-supplied area names; validate against area allowlist
- [ ] **SEC-07**: PII protection -- log only metadata (row count, status), never raw visa/employment data

### Data Quality & Validation

- [ ] **QUAL-01**: Out-of-sample validation -- split data into training/test sets, validate Granger results on held-out data
- [ ] **QUAL-02**: Staleness surfacing -- Telegram responses include data freshness warnings when sources are >2x overdue
- [ ] **QUAL-03**: Conditional forward-fill -- fill gaps up to 1 period only; leave NULL for extended outages instead of propagating stale data
- [ ] **QUAL-04**: Area name normalization -- fuzzy matching for Telegram queries, support abbreviations (JVC, JBR, DIFC), show "Did you mean?" for ambiguous input
- [ ] **QUAL-05**: Collection health dashboard -- `uae_collection_status()` shows all sources with last update, row count, staleness flag, next scheduled run

## v1.4 Requirements (Deferred)

### Enhanced Analytics
- **ENH-01**: ARIMA/LSTM price forecasting models
- **ENH-02**: Monte Carlo simulation for correlation validation
- **ENH-03**: Time-series cross-validation (walk-forward) for signal robustness
- **ENH-04**: Custom Granger weight optimization (grid search)

### Visualization
- **VIZ-01**: Interactive web dashboard (React + Recharts)
- **VIZ-02**: Neighbourhood heatmaps with geocoded area data
- **VIZ-03**: Historical trend charts with drill-down

### Automation
- **AUTO-01**: Weekly email digest (top 3 buy signals, top 3 distress alerts)
- **AUTO-02**: Distress threshold alerts via Telegram (score >= 0.6)
- **AUTO-03**: GitHub issue auto-creation for persistent collection failures

## Out of Scope

| Feature | Reason |
|---------|--------|
| Real-time streaming data | Sources update daily/weekly/monthly -- real-time is waste |
| Property-level price predictions | Overfitting risk, Zillow Zestimate problem |
| AI chatbot for property search | Commodity feature, Bayut/PropertyFinder already do this |
| Social media auto-posting | Regulatory risk (unlicensed investment advice) |
| Blockchain property registry | DLD is the authority, parallel registries add confusion |
| Native mobile app | Telegram + PWA covers mobile use cases |
| User-generated reviews | Moderation burden, legal liability, not core competency |
| Mortgage calculator | Commodity feature, every bank has one |
| Property management CRM | Different user base (B2B), scope creep |
| Crypto payments | Regulatory uncertainty, niche demand |
| Multi-market expansion (Sharjah, Ajman) | Need PMF in Dubai first |
| REST API for third-party integrations | Premature, no partners yet |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| INFRA-01 | 6 | Complete |
| INFRA-02 | 6 | Complete |
| INFRA-03 | 6 | Complete |
| INFRA-04 | 6 | Complete |
| INFRA-05 | 6 | Complete |
| INFRA-06 | 6 | Complete |
| INFRA-07 | 6 | Complete |
| COLL-01 | 7 | ✅ Complete (07-02) |
| COLL-02 | 7 | ✅ Complete (07-02) |
| COLL-03 | 7 | ✅ Complete (07-02) |
| COLL-04 | 7 | Complete |
| COLL-05 | 7 | Complete |
| COLL-06 | 8 | Pending |
| COLL-07 | 8 | Pending |
| COLL-08 | 8 | Pending |
| COLL-09 | 8 | Pending |
| COLL-10 | 8 | Pending |
| COLL-11 | 8 | Pending |
| COLL-12 | 8 | Pending |
| COLL-13 | 8 | Pending |
| COLL-14 | 9 | Complete |
| COLL-15 | 7 | Complete |
| COLL-16 | 9 | Complete |
| COLL-17 | 9 | Complete |
| COLL-18 | 9 | Complete |
| COLL-19 | 9 | Pending |
| COLL-20 | 9 | Complete |
| COLL-21 | 9 | Pending |
| COLL-22 | 9 | Pending |
| COLL-23 | 9 | Complete |
| COLL-24 | 9 | Complete |
| COLL-25 | 9 | Complete |
| COLL-26 | 9 | Pending |
| COLL-27 | 9 | Complete |
| COLL-28 | 9 | Pending |
| NORM-01 | 7 | Complete (07-01) |
| NORM-02 | 7 | Complete (07-01) |
| NORM-03 | 7 | Complete (07-01) |
| NORM-04 | 7 | Complete (07-01) |
| NORM-05 | 7 | Complete (07-01) |
| STAT-01 | 10 | Pending |
| STAT-02 | 10 | Pending |
| STAT-03 | 10 | Pending |
| STAT-04 | 10 | Pending |
| STAT-05 | 10 | Pending |
| STAT-06 | 10 | Pending |
| STAT-07 | 10 | Pending |
| STAT-08 | 10 | Pending |
| PROD-01 | 11 | Pending |
| PROD-02 | 11 | Pending |
| PROD-03 | 11 | Pending |
| PROD-04 | 11 | Pending |
| PROD-05 | 11 | Pending |
| PROD-06 | 11 | Pending |
| PROD-07 | 11 | Pending |
| PROD-08 | 11 | Pending |
| TOOL-01 | 12 | Pending |
| TOOL-02 | 12 | Pending |
| TOOL-03 | 12 | Pending |
| TOOL-04 | 12 | Pending |
| TOOL-05 | 12 | Pending |
| TOOL-06 | 12 | Pending |
| TOOL-07 | 12 | Pending |
| TOOL-08 | 12 | Pending |
| TOOL-09 | 12 | Pending |
| TOOL-10 | 12 | Pending |
| TOOL-11 | 12 | Pending |
| TOOL-12 | 12 | Pending |
| TOOL-13 | 12 | Pending |
| SCHED-01 | 6 | Complete |
| SCHED-02 | 8 | Pending |
| SCHED-03 | 8 | Pending |
| SCHED-04 | 8 | Pending |
| SCHED-05 | 9 | Pending |
| SCHED-06 | 10 | Pending |
| SCHED-07 | 8 | Pending |
| SEC-01 | 6 | Complete |
| SEC-02 | 6 | Complete |
| SEC-03 | 12 | Pending |
| SEC-04 | 12 | Pending |
| SEC-05 | 12 | Pending |
| SEC-06 | 10 | Pending |
| SEC-07 | 10 | Pending |
| QUAL-01 | 11 | Pending |
| QUAL-02 | 12 | Pending |
| QUAL-03 | 11 | Pending |
| QUAL-04 | 12 | Pending |
| QUAL-05 | 12 | Pending |

**Coverage:**
- v1.3 requirements: 88 total (9 categories)
- Mapped to phases: 88
- Unmapped: 0

**Phase distribution:**
- Phase 6 (Foundation & Infrastructure): 10
- Phase 7 (MVP Data Collection): 11
- Phase 8 (Tier B Collection): 12
- Phase 9 (Tier C Collection): 15
- Phase 10 (Statistical Analysis): 11
- Phase 11 (Intelligence Products): 10
- Phase 12 (Plugin Tools & Hardening): 19

---
*Requirements defined: 2026-03-11*
*Traceability completed: 2026-03-11 -- all 88 requirements mapped to phases 6-12*
