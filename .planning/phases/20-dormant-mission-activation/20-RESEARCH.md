# Phase 20: Dormant Mission Activation - Research

**Researched:** 2026-03-25
**Domain:** Mission audit, normalization gap analysis, broken collector triage
**Confidence:** HIGH

## Summary

Phase 20 requires a full audit of all 38 registered missions in the UAE RE Intelligence system, identifying which produce usable data, which have normalizers, and which are permanently blocked. Research reveals a clear three-tier picture:

**17 sources are fully operational** (collecting, normalizing, and producing rows in `normalized_monthly`). **9 sources have raw data files but are NOT producing normalized output** -- these are the activation targets. **12 sources are broken or dormant** with no usable raw data, due to WAF blocks, missing credentials, empty scraper results, or authentication requirements.

Among the 9 sources with raw data but no normalized output, the most promising candidates for activation are: CBUAE Mortgages (PDF with pdfplumber, normalizer code exists), CBUAE Remittances (same pattern, normalizer code exists), KHDA Enrollment (PDF downloaded, normalizer code exists), FCSA Demographics (PDF downloaded, normalizer code exists), DXB Passengers (HTML scraped, normalizer code exists), and MOHRE Permits (JSON scraped, normalizer code exists). All 6 already have both raw data AND normalizer Python files -- the gap is that the collection pipeline never triggered normalization because collection was logged as failure or the data format mismatched expectations.

Two critical bugs were identified: (1) Google Trends is broken because pytrends 4.9.2 uses `method_whitelist` which was removed in urllib3 2.0+ (installed: 2.6.3), and (2) Reddit sentiment and NewsAPI are missing API credentials that were never stored in HSM or .env.

**Primary recommendation:** Focus on running existing normalizers against existing raw data (6 sources have both data + normalizer code), fix Google Trends by upgrading pytrends, and retire 6 permanently blocked missions (DLD, Ejari, Building Permits behind WAF; GulfTalent needs credentials; InsideAirbnb/Hays have no data and no viable scraping path).

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DORM-01 | Audit all 38 deployed missions -- identify usable vs blocked | Complete inventory below: 17 active, 9 have data but no normalized output, 12 broken/dormant |
| DORM-02 | Add normalization handlers for missions producing data but lacking ingest logic (target: 5+ sources) | 6 sources have BOTH raw data AND normalizer code but never ran normalization. 3 more have raw data but normalizer needs work. Total addressable: 9 sources |
| DORM-03 | Fix or retire permanently blocked missions -- update status, remove from collection timers | 6 missions confirmed permanently blocked (WAF, 403, missing creds with no path). 3 missions fixable (pytrends bug, missing but obtainable creds). 3 missions have data issues (empty JSON, bad selectors) |
</phase_requirements>

## Complete Mission Inventory

### Tier 1: Fully Operational (17 sources -- collecting + normalizing + in normalized_monthly)

| # | Source | Type | Frequency | Rows | Metrics | Last Success |
|---|--------|------|-----------|------|---------|-------------|
| 1 | adrec-abu-dhabi | Scraper | monthly | 18 | 18 | 2026-03-11 |
| 2 | bayt-jobs | Scraper | weekly | 21 | 16 | 2026-03-23 |
| 3 | cbuae (transfers) | Scraper | quarterly | 54 | 6 | (manual ingest) |
| 4 | cbuae-expanded | DirectPython | quarterly | 47 | 7 | 2026-03-23 |
| 5 | commodities | DirectPython | monthly | 208 | 4 | 2026-03-23 |
| 6 | dfm-stocks | DirectPython | monthly | 488 | 8 | 2026-03-23 |
| 7 | dpworld (jebel-ali-port) | Scraper | monthly | 7 | 2 | (manual ingest) |
| 8 | dxb-passengers | Scraper | monthly | 17 | 7 | (manual ingest) |
| 9 | fcsa-demographics | Scraper | quarterly | 6 | 3 | (manual ingest) |
| 10 | imf-weo | DirectPython | quarterly | 255 | 10 | 2026-03-23 |
| 11 | indeed-jobs | Scraper | weekly | 10 | 6 | 2026-03-23 |
| 12 | khda (enrollment) | Scraper | quarterly | 37 | 37 | (manual ingest) |
| 13 | linkedin-jobs | Scraper | weekly | 12 | 7 | 2026-03-23 |
| 14 | mohre-permits | Scraper | monthly | 32 | 11 | (manual ingest) |
| 15 | propertyfinder | Scraper | weekly | 206 | 206 | 2026-03-16 |
| 16 | spglobal-pmi | DirectPython | monthly | 1 | 1 | 2026-03-23 |
| 17 | worldbank-macro | DirectPython | quarterly | 115 | 5 | 2026-03-23 |

**Note:** Sources marked "(manual ingest)" have normalized data from prior manual runs -- their automated collection pipeline has not successfully completed a collect+normalize cycle. The raw data exists from earlier scraper runs and was normalized manually or during development.

### Tier 2: Have Raw Data BUT No Automated Normalize Cycle (9 sources -- activation targets)

| # | Source | Type | Raw Data Files | Raw Size | Normalizer Exists? | Issue |
|---|--------|------|---------------|----------|-------------------|-------|
| 1 | bayut-listings | Scraper | 3 files | 28K | YES (normalize_bayut.py) | All price/bedroom/sqft fields are `null` -- selector mismatch |
| 2 | cbuae-mortgages | Scraper | 2 (PDF+meta) | 340K | YES (normalize_mortgages.py) | Never attempted in collection_log; has valid PDF |
| 3 | cbuae-remittances | Scraper | 3 (PDF+meta+bin) | 1.8M | YES (normalize_remittances.py) | Never attempted in collection_log; has valid PDF |
| 4 | dxb-passengers | Scraper | 2 files | 72K | YES (normalize_dxb.py) | 2026-03-17 HTML (62K) has embedded stats; raw is JS blob |
| 5 | fcsa-demographics | Scraper | 3 (PDF+json+bin) | 1.5M | YES (normalize_demographics.py) | Never attempted in collection_log; has 12-page PDF |
| 6 | khda-enrollment | Scraper | 3 (PDF+meta+bin) | 2.6M | YES (normalize_khda.py) | Never attempted in collection_log; has valid PDF |
| 7 | mohre-permits | Scraper | 1 file | 108K | YES (normalize_mohre.py) | Never attempted in collection_log; has scraped JSON |
| 8 | jebel-ali-port | Scraper | 1 file | 3.2M | YES (normalize_port.py) | HTML contains DP World press releases (RSS in __NEXT_DATA__) |
| 9 | google-trends | DirectPython | 9 files | 40K | YES (normalize_trends.py) | pytrends bug: `method_whitelist` removed in urllib3 2.x |

### Tier 3: Broken / Dormant (12 sources -- no usable raw data)

| # | Source | Type | Failure Mode | Evidence | Verdict |
|---|--------|------|-------------|----------|---------|
| 1 | dld-sales | Scraper | WAF blocked | "Request Rejected" HTML in all 4 CSV files | RETIRE: Dubai Pulse WAF; no workaround |
| 2 | ejari-rentals | Scraper | WAF blocked | "Request Rejected" HTML in all 4 CSV files | RETIRE: Same WAF as DLD |
| 3 | building-permits | Scraper | WAF blocked | "Request Rejected" HTML in both CSV files | RETIRE: Same WAF as DLD |
| 4 | dewa-connections | Scraper | Timeout | Page.goto timeout on DEWA press releases | RETIRE: DEWA site blocks headless browsers |
| 5 | gulftalent-jobs | Scraper | 403/Empty | Empty `[]` in both JSON files; needs auth credentials | RETIRE: Requires paid account credentials |
| 6 | google-maps-traffic | Scraper | Timeout | Circuit breaker open; 1hr timeout on 50-location scrape | RETIRE: Google Maps Popular Times not scrapable at scale |
| 7 | reddit-sentiment | DirectPython | Missing creds | Circuit breaker open; REDDIT_CLIENT_ID/SECRET not set | FIX: User must create Reddit app + store creds in HSM |
| 8 | news-sentiment | DirectPython | Missing creds | Circuit breaker open; NEWSAPI_KEY not set | FIX: User must obtain NewsAPI key + store in HSM |
| 9 | dtcm-tourism | Scraper | Empty data | `[]` (empty array) in JSON | DORMANT: DTCM page may need JS execution or API |
| 10 | rta-metro | Scraper | Null data | `data_table: null` in JSON | DORMANT: RTA stats page requires JS + pagination |
| 11 | rta-vehicles | Scraper | Null data | `data_table: null` pointing at dubaipulse.gov.ae | DORMANT: Dubai Pulse data portal behind WAF |
| 12 | hays-salary / roberthalf-salary / cooper-fitch-salary / commercial-office-reports / customs-imports / ded-licenses / fb-closures / gdrfa-visas / insideairbnb | Scraper | No directory or empty | No raw data directory exists; never been attempted | DORMANT: Missions defined but never successfully executed |

**Subtotals for Tier 3:**
- **6 RETIRE** (confirmed blocked, no path forward): dld-sales, ejari-rentals, building-permits, dewa-connections, gulftalent-jobs, google-maps-traffic
- **2 FIX** (credential issue, user action needed): reddit-sentiment, news-sentiment
- **11+ DORMANT** (never ran, no data, would need significant mission/selector work): dtcm-tourism, rta-metro, rta-vehicles, hays-salary, roberthalf-salary, cooper-fitch-salary, commercial-office-reports, customs-imports, ded-licenses, fb-closures, gdrfa-visas, insideairbnb

## Standard Stack

### Core (Already Deployed -- No New Dependencies)
| Library | Version | Purpose | Status |
|---------|---------|---------|--------|
| pdfplumber | 0.11.4 | PDF table extraction for CBUAE/KHDA/FCSA PDFs | Installed in analytics-venv |
| pandas | 2.2.3 | Data manipulation for normalizers | Installed |
| pandera | 0.20.4 | Schema validation for normalizers | Installed |
| praw | 7.8.1 | Reddit API (needs credentials) | Installed |
| vaderSentiment | 3.3.2 | Sentiment scoring | Installed |

### Fix Required
| Library | Current | Fix | Purpose |
|---------|---------|-----|---------|
| pytrends | 4.9.2 | Upgrade to 4.9.3+ or patch | Google Trends; `method_whitelist` incompatibility with urllib3 2.x |

### Version Verification
All versions confirmed via `/opt/lobsec/analytics-venv/bin/python3 -m pip show`. No new packages needed.

## Architecture Patterns

### Existing Normalization Pipeline
```
Collection success → normalizeCollectionResult() → runPython("normalize_{source}")
  → Python reads raw file (JSON/PDF/HTML) via filePath from stdin
  → Python returns [{ measurement_date, metric_name, value, available_date }]
  → TypeScript upserts to normalized_monthly table (DELETE range + INSERT)
```

### Why Tier 2 Sources Have Data But No Normalized Output

The gap exists because:

1. **Scraper-based collectors log "success" only when rowCount > 0 AND the scraper API returns completed status.** PDF download missions often return `row_count: 1` (the PDF itself), but some missions were never properly triggered via the orchestrator (they were manually scraped during development).

2. **The auto-normalization only fires after a successful `collector.run()` call** in the CLI orchestrator (`cli.js`). Manual scraper runs (via `POST /crawl`) do not trigger normalization.

3. **Solution pattern:** For sources that already have raw data + normalizer code, the planner should create a task that manually invokes normalization against existing raw data files, then fix the collection pipeline so future runs auto-normalize.

### Manual Normalization Invocation Pattern
```bash
# Example: normalize CBUAE mortgages PDF
echo '{"filePath":"/opt/lobsec/data/raw/cbuae-mortgages/2026-03-16.pdf","source":"cbuae-mortgages","collectedAt":"2026-03-16T00:00:00Z"}' | \
  PYTHONPATH=/opt/lobsec/plugins/lobsec-uae-re/python \
  /opt/lobsec/analytics-venv/bin/python3 -m uae_re.normalize_mortgages
```

### Normalizer Input Contract
- **JSON/CSV sources:** `filePath` points to the `.json` or `.csv` raw data file
- **PDF sources:** `filePath` points to the `.pdf` file directly; the normalizer calls pdfplumber internally
- **HTML sources:** `filePath` points to the `.json` or `.html` file; the normalizer parses as text

### Source Name vs Normalized Source Name
Some sources use different names in `normalized_monthly`:
| Registry Source | Normalized Source |
|----------------|-------------------|
| cbuae-remittances | cbuae |
| jebel-ali-port | dpworld |
| khda-enrollment | khda |
| fcsa-demographics | fcsa-demographics |
| bayut-listings | (not yet in normalized_monthly) |

## Detailed Analysis: Tier 2 Activation Targets

### 1. CBUAE Mortgages (cbuae-mortgages) -- HIGH confidence
- **Raw data:** Valid 339K PDF (`uae_emirate_dec-25.pdf` -- Banking Indicators December 2025)
- **Normalizer:** `normalize_mortgages.py` -- extracts EIBOR 3m, mortgage outstanding, new mortgage count via pdfplumber
- **Expected metrics:** `uae|cbuae_eibor_3m`, `uae|cbuae_mortgage_outstanding_aed`, `uae|cbuae_new_mortgage_count`
- **Action:** Run normalizer against existing PDF, verify output, add to quarterly timer
- **Risk:** pdfplumber table extraction may not match actual PDF table structure (need manual test)

### 2. CBUAE Remittances (cbuae-remittances) -- HIGH confidence
- **Raw data:** Valid 1.8M PDF (`statistical-bulletin-december-2025.pdf`)
- **Normalizer:** `normalize_remittances.py` -- extracts personal/worker remittances from balance of payments tables
- **Expected metrics:** `uae|cbuae_personal_remittances`, `uae|cbuae_workers_remittances`, `uae|cbuae_total_outflows`
- **Action:** Run normalizer against existing PDF, verify output
- **Note:** Source `cbuae` already has 54 rows in normalized_monthly (from prior manual run). This confirms the normalizer works.

### 3. KHDA Enrollment (khda-enrollment) -- HIGH confidence
- **Raw data:** Valid 2.6M PDF (`Dubai-Private-School-Landsacpe-En.pdf` -- 2024-25)
- **Normalizer:** `normalize_khda.py` -- extracts enrollment by curriculum via pdfplumber
- **Expected metrics:** khda_total_students, khda_{curriculum}_students/schools (37 metrics already in normalized_monthly)
- **Action:** Verify normalizer runs against the latest PDF; data already exists in normalized_monthly from prior run
- **Note:** This source IS already in normalized_monthly (37 rows). May just need the automated pipeline connection verified.

### 4. FCSA Demographics (fcsa-demographics) -- HIGH confidence
- **Raw data:** Valid 782K PDF (`Population Bulletin Emirate of Dubai - 2024.pdf`)
- **Normalizer:** `normalize_demographics.py` -- extracts population, growth rate, working age %
- **Expected metrics:** `dsc_total_population`, `dsc_population_growth_pct`, `dsc_working_age_pct`
- **Action:** Verify normalizer runs against existing PDF; data already exists (6 rows)
- **Note:** This source IS already in normalized_monthly. Automated pipeline needs connection.

### 5. DXB Passengers (dxb-passengers) -- MEDIUM confidence
- **Raw data:** 62K JSON from `media.dubaiairports.ae/dubai-airports-main-fact-file/`
- **Normalizer:** `normalize_dxb.py` -- extracts annual/quarterly passengers, flights, cargo
- **Expected metrics:** `dxb_annual_passengers`, `dxb_yoy_growth_pct`, etc.
- **Action:** Normalizer may need adjustment for new HTML format (changed from PDF to embedded HTML stats)
- **Risk:** Raw data is JavaScript-heavy HTML dump; normalizer may expect different structure
- **Note:** Already has 17 rows in normalized_monthly from prior manual entry.

### 6. MOHRE Permits (mohre-permits) -- MEDIUM confidence
- **Raw data:** 108K JSON with stat cards from observatory.mohre.gov.ae
- **Normalizer:** `normalize_mohre.py` -- extracts workforce growth, skilled workers, emiratisation
- **Action:** Verify normalizer parses the stat_cards format correctly
- **Note:** Already has 32 rows in normalized_monthly. URL was updated 2026-03-17 to new observatory site.

### 7. Jebel Ali Port (jebel-ali-port) -- MEDIUM confidence
- **Raw data:** 3.2M HTML with DP World press releases (RSS embedded in __NEXT_DATA__)
- **Normalizer:** `normalize_port.py` -- extracts container throughput TEU, cargo tonnes
- **Action:** May need HTML parsing adjustment for Next.js __NEXT_DATA__ JSON extraction
- **Note:** Already has 7 rows in normalized_monthly as `dpworld`. Needs RSS parsing from HTML.

### 8. Bayut Listings (bayut-listings) -- LOW confidence
- **Raw data:** 3 JSON files but ALL fields are `null` (price, bedrooms, sqft, listing_count all null)
- **Normalizer:** `normalize_bayut.py` exists
- **Problem:** Scraper selectors are broken -- Bayut changed their HTML structure
- **Action:** Requires fixing scraper selectors in `bayut-listings.yml`, re-scraping, THEN normalizing
- **Risk:** Bayut may deploy anti-bot measures; selector maintenance is ongoing

### 9. Google Trends (google-trends) -- HIGH confidence (fixable)
- **Raw data:** 9 JSON files but all have empty arrays (0 data points)
- **Normalizer:** `normalize_trends.py` exists
- **Root cause:** pytrends 4.9.2 incompatible with urllib3 2.6.3 (`method_whitelist` removed)
- **Fix:** `pip install --upgrade pytrends` (4.9.3+ fixes this) OR pin urllib3<2.0
- **After fix:** Will start producing data on next daily collection run

## Blocked Mission Details

### DLD Sales + Ejari Rentals + Building Permits (Dubai Pulse WAF)
All three hit the same WAF at `dubaipulse.gov.ae`:
```html
<html><head><title>Request Rejected</title></head><body>
The requested URL was rejected. Please consult with your administrator.
Your support ID is: 2831694023056279869
```
This is a Web Application Firewall blocking automated/headless requests. The same WAF blocks RTA Vehicles. **Dubai Pulse requires user registration** (per STATE.md: "Dubai Pulse deferred -- user hasn't registered at dubaidata.ae"). Without API credentials, these are permanently blocked.

### Google Maps Traffic
Times out at 3,600,000ms (1 hour). Attempting to scrape Popular Times data from 50 Google Maps locations is not viable at scale. Google actively blocks automated access.

### DEWA Connections
`Page.goto: Timeout 30000ms exceeded` -- DEWA's site blocks headless browsers or has Cloudflare protection.

### GulfTalent Jobs
Requires authenticated session (HSM credentials: `gulftalent-username`, `gulftalent-password`). These credentials have never been stored -- the mission needs a paid GulfTalent account.

## Common Pitfalls

### Pitfall 1: Normalizer Expects Different File Format Than What Scraper Produces
**What goes wrong:** Normalizer code written for PDF but scraper outputs JSON metadata wrapper
**Why it happens:** PDF download missions produce `.pdf` + `.meta.json` files. The normalizer must receive the `.pdf` path, not the `.meta.json` path.
**How to avoid:** When manually running normalizers, always point `filePath` to the actual data file (`.pdf` for PDF sources, `.json` for JSON sources).

### Pitfall 2: pytrends urllib3 Incompatibility
**What goes wrong:** All Google Trends fetches fail silently with empty arrays
**Why it happens:** pytrends 4.9.2 calls `Retry(method_whitelist=...)` which was removed in urllib3 2.0
**How to avoid:** Upgrade pytrends: `pip install pytrends>=4.9.3`

### Pitfall 3: Circuit Breaker Stays Open After Credential Fix
**What goes wrong:** After adding missing credentials, collector still fails with "Circuit breaker is open"
**Why it happens:** CircuitBreaker has 30s reset timeout; but consecutive failures > threshold keep it open
**How to avoid:** Restart the lobsec service (or wait for circuit breaker reset) after fixing credentials

### Pitfall 4: Normalized Source Name Mismatch
**What goes wrong:** Collection runs under source name "cbuae-remittances" but normalized_monthly has source "cbuae"
**Why it happens:** Some normalizers use abbreviated source names in their output records
**How to avoid:** Check normalized_monthly before inserting to avoid duplicates with different source names

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PDF table extraction | Custom PDF parser | pdfplumber (already installed) | Handles merged cells, multi-page tables |
| Sentiment analysis | Custom NLP model | vaderSentiment (already installed) | Rule-based, no GPU needed, well-tested |
| Google Trends data | Custom scraping | pytrends (needs upgrade) | Handles rate limiting, cookie rotation |
| Reddit data | Custom API calls | praw (already installed) | Handles OAuth, pagination, rate limits |

## Recommended Plan Structure

### Plan 20-01: Audit + Fix Broken Collectors (DORM-01 + DORM-03)
1. **Task 1:** Run pytrends upgrade (`pip install pytrends>=4.9.3`) and verify Google Trends collector works
2. **Task 2:** Update mission status: retire 6 blocked missions (remove from collection timers or add `enabled: false`), mark 2 as "needs-credentials" (reddit-sentiment, news-sentiment)
3. **Task 3:** Update registry.ts to skip retired missions (or add `enabled` flag to COLLECTOR_DEFINITIONS)

### Plan 20-02: Activate Dormant Normalizers (DORM-02)
1. **Task 1:** Test-run normalizers against existing raw data for 6 sources:
   - cbuae-mortgages (PDF)
   - cbuae-remittances (PDF)
   - khda-enrollment (PDF)
   - fcsa-demographics (PDF)
   - dxb-passengers (JSON/HTML)
   - mohre-permits (JSON)
   Fix any normalizer issues found during testing.
2. **Task 2:** Wire up the automated collection-to-normalization pipeline for these sources (verify they're registered in DIRECT_PYTHON_SOURCES or handled correctly by the scraper-based flow)
3. **Task 3:** Fix Bayut listings selectors and re-scrape (if time permits -- lower priority)

### Expected Outcome
- 6 additional sources producing normalized data (from 17 to 23 sources)
- Google Trends collector fixed and producing data
- 6 missions retired from active collection
- 2 missions documented as "needs credentials" for user action

## Code Examples

### Manual Normalization Test (PDF source)
```bash
echo '{"filePath":"/opt/lobsec/data/raw/cbuae-mortgages/2026-03-16.pdf","source":"cbuae-mortgages","collectedAt":"2026-03-16T00:00:00Z"}' | \
  PYTHONPATH=/opt/lobsec/plugins/lobsec-uae-re/python \
  /opt/lobsec/analytics-venv/bin/python3 -m uae_re.normalize_mortgages
```

### pytrends Fix
```bash
/opt/lobsec/analytics-venv/bin/pip install --upgrade pytrends
# Then test:
echo '{"outputDir": "/tmp/test-trends"}' | \
  PYTHONPATH=/opt/lobsec/plugins/lobsec-uae-re/python \
  /opt/lobsec/analytics-venv/bin/python3 -m uae_re.collect_trends
```

### Adding Enabled Flag to Collector Definitions (example)
```typescript
const COLLECTOR_DEFINITIONS: Array<{
  missionName: string;
  metadata: CollectorMetadata;
  enabled?: boolean;  // Add optional flag
}> = [
  {
    missionName: "dld-sales",
    metadata: { source: "dld-sales", frequency: "weekly", priority: 1, timeout: 120_000 },
    enabled: false,  // WAF blocked -- retired
  },
  // ...
];
```

### Running Normalization From CLI
```bash
# Use existing CLI to run a single source's collection + normalization
sudo -u lobsec /opt/lobsec/bin/collect.sh cbuae-mortgages
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-----------------|--------------|--------|
| pytrends method_whitelist | pytrends allowed_methods | urllib3 2.0 (2023) | Google Trends collection broken |
| Dubai Pulse open CSV | Dubai Pulse WAF-blocked | ~2025 | DLD/Ejari/Permits permanently blocked |
| DEWA press releases | DEWA statistics PDFs | Mission yml updated | DEWA still blocks headless browsers |
| DXB Airport PDF factsheet | HTML fact file page | 2026-03-17 | Normalizer may need HTML parser update |
| MOHRE statistical reports | MOHRE Observatory dashboard | 2026-03-17 | New data format (stat cards) |

## Open Questions

1. **Do the PDF normalizers actually extract data correctly from the downloaded PDFs?**
   - What we know: Normalizer code exists and follows a tested pattern (pdfplumber table extraction)
   - What's unclear: Whether the actual PDF table structure matches what the normalizer expects
   - Recommendation: Run each normalizer manually and check output before wiring into pipeline

2. **Should retired missions be removed from registry.ts or just flagged?**
   - What we know: Currently all 38 missions are registered and attempted on collection runs
   - What's unclear: Whether removing them causes downstream issues (gap detection, etc.)
   - Recommendation: Add `enabled: false` flag rather than removing, to preserve audit trail

3. **Will the user provide Reddit and NewsAPI credentials?**
   - What we know: Both collectors are coded and tested but need API keys
   - What's unclear: Whether user wants to pursue these sources
   - Recommendation: Document as blocked-on-user-action; don't spend implementation time

4. **Bayut selector maintenance burden**
   - What we know: Bayut listings scraper returns all nulls -- selectors are stale
   - What's unclear: Whether Bayut has anti-bot measures that will keep breaking selectors
   - Recommendation: Low priority -- PropertyFinder already covers the same listing data

## Sources

### Primary (HIGH confidence)
- Direct inspection of production files at `/opt/lobsec/data/raw/` -- all 33 directories examined
- SQLite queries against `/opt/lobsec/data/uae-re.db` -- normalized_monthly and collection_log tables
- Source code inspection: `registry.ts`, `types.ts`, all 35 normalizer Python files
- Manual test of Google Trends collector revealing pytrends/urllib3 incompatibility

### Secondary (MEDIUM confidence)
- Scraper mission YAML files in `/root/lobsec/packages/scraper/missions/` -- 31 files reviewed
- systemd timer configuration -- 6 collection timers active (daily/weekly/monthly/quarterly)
- Python bridge code (`bridge.ts`, `direct.ts`) -- understood invocation pattern

## Metadata

**Confidence breakdown:**
- Mission inventory: HIGH -- direct inspection of database + filesystem
- Activation targets: HIGH -- normalizer code exists, raw data verified
- Blocked missions: HIGH -- error evidence from collection_log and raw file inspection
- pytrends fix: HIGH -- root cause confirmed via manual reproduction

**Research date:** 2026-03-25
**Valid until:** 2026-04-25 (stable -- mission status unlikely to change without intervention)
