# Phase 20: Mission Audit Report

**Audited:** 2026-03-25
**Total registered missions:** 38 (in COLLECTOR_DEFINITIONS)
**Sources in collection_log:** 20 (18 never attempted by automated pipeline)
**Sources in normalized_monthly:** 17

## Classification Summary

| Classification | Count | Sources |
|----------------|-------|---------|
| ACTIVE | 17 | adrec-abu-dhabi, bayt-jobs, cbuae (remittances), cbuae-expanded, commodities, dfm-stocks, dpworld (jebel-ali-port), dxb-passengers, fcsa-demographics, imf-weo, indeed-jobs, khda (enrollment), linkedin-jobs, mohre-permits, propertyfinder, spglobal-pmi, worldbank-macro |
| ACTIVATION-TARGET | 4 | bayut-listings, cbuae-mortgages, google-trends, jebel-ali-port |
| BLOCKED-CREDENTIALS | 2 | reddit-sentiment, news-sentiment |
| DORMANT-NEVER-RAN | 8 | cooper-fitch-salary, hays-salary, roberthalf-salary, commercial-office-reports, customs-imports, ded-licenses, fb-closures, insideairbnb |
| DORMANT-BROKEN | 3 | dtcm-tourism, rta-metro, rta-vehicles |
| RETIRED | 6 | dld-sales, ejari-rentals, building-permits, dewa-connections, gulftalent-jobs, google-maps-traffic |

**Note:** Some sources (dpworld, cbuae, khda, dxb-passengers, fcsa-demographics, mohre-permits) have normalized data from manual ingestion during development. Their automated collect-then-normalize pipeline is not yet verified. They are classified as ACTIVE because they DO have normalized data available for analysis.

---

## Tier 1: ACTIVE (17 sources producing normalized data)

| # | Source (registry) | Normalized Source | Rows | Metrics | Collection Log | Last Activity | Notes |
|---|-------------------|------------------|------|---------|----------------|---------------|-------|
| 1 | adrec-abu-dhabi | adrec | 18 | 18 | 3 runs, 1 success | 2026-03-11 | Scraper-based |
| 2 | bayt-jobs | bayt-jobs | 21 | 16 | 3 runs, 3 successes | 2026-03-23 | Weekly, stable |
| 3 | cbuae-remittances | cbuae | 54 | 6 | Never in log | Manual ingest | PDF-based, normalizer exists |
| 4 | cbuae-expanded | cbuae-expanded | 47 | 7 | Never in log | 2026-03-23 | DirectPython, QER PDFs |
| 5 | commodities | commodities | 208 | 4 | Never in log | 2026-03-23 | DirectPython (BZ=F, GC=F) |
| 6 | dfm-stocks | dfm-stocks | 488 | 8 | 2 runs, 1 success | 2026-03-23 | DirectPython, Yahoo Finance |
| 7 | jebel-ali-port | dpworld | 7 | 2 | Never in log | Manual ingest | RSS parsing from __NEXT_DATA__ |
| 8 | dxb-passengers | dxb-passengers | 17 | 7 | Never in log | Manual ingest | HTML fact file |
| 9 | fcsa-demographics | fcsa-demographics | 6 | 3 | Never in log | Manual ingest | PDF-based |
| 10 | imf-weo | imf-weo | 255 | 10 | 1 run, 1 success | 2026-03-23 | DirectPython, IMF API |
| 11 | indeed-jobs | indeed-jobs | 10 | 6 | 3 runs, 3 successes | 2026-03-23 | Weekly, stable |
| 12 | khda-enrollment | khda | 37 | 37 | Never in log | Manual ingest | PDF-based |
| 13 | linkedin-jobs | linkedin-jobs | 12 | 7 | 8 runs, 4 successes | 2026-03-23 | Weekly, some circuit breaker failures |
| 14 | mohre-permits | mohre-permits | 32 | 11 | Never in log | Manual ingest | JSON stat cards |
| 15 | propertyfinder-listings | propertyfinder | 206 | 206 | 5 runs, 1 success | 2026-03-23 | Weekly, some circuit breaker failures |
| 16 | spglobal-pmi | spglobal-pmi | 1 | 1 | 1 run, 1 success | 2026-03-23 | DirectPython, press release |
| 17 | worldbank-macro | worldbank-macro | 115 | 5 | 1 run, 1 success | 2026-03-23 | DirectPython, WB API |

**Total normalized rows:** 1,534 across 354 distinct metrics from 17 sources.

---

## Tier 2: ACTIVATION-TARGET (4 sources with raw data but not yet fully operational)

### 1. bayut-listings
- **Classification:** ACTIVATION-TARGET (broken selectors)
- **Raw data:** 3 JSON files (28K total), all fields null (price, bedrooms, sqft)
- **Collection log:** 3 runs, 2 successes (returns data structure but all values null)
- **Normalizer:** `normalize_bayut.py` exists
- **Blocker:** Bayut changed HTML structure; selectors return null. Needs selector update + re-scrape.
- **Action for Plan 20-02:** Fix selectors, re-scrape, then normalize.

### 2. cbuae-mortgages
- **Classification:** ACTIVATION-TARGET (has raw PDF + normalizer)
- **Raw data:** 1 PDF (340K) -- `uae_emirate_dec-25.pdf` (Banking Indicators December 2025)
- **Collection log:** Never attempted
- **Normalizer:** `normalize_mortgages.py` exists -- extracts EIBOR 3m, mortgage outstanding, new mortgage count
- **Action for Plan 20-02:** Run normalizer against existing PDF, verify output, wire into pipeline.

### 3. google-trends
- **Classification:** ACTIVATION-TARGET (FIXED in this plan)
- **Raw data:** 9 JSON files (40K total), all had empty arrays
- **Collection log:** 9 runs, 0 successes (all "Empty collection: rowCount is 0")
- **Root cause:** pytrends 4.9.2 uses `method_whitelist` removed in urllib3 2.x
- **Fix applied:** Patched pytrends request.py: `method_whitelist` -> `allowed_methods`
- **Verification:** Collector now produces 318 records across 6 keyword groups
- **Normalizer:** `normalize_trends.py` exists
- **Action for Plan 20-02:** Verify normalize pipeline end-to-end.

### 4. jebel-ali-port (secondary activation)
- **Classification:** ACTIVE (has 7 rows in normalized_monthly as "dpworld")
- **Raw data:** 3.2M HTML with DP World press releases (RSS in __NEXT_DATA__)
- **Note:** Already producing data via manual ingest. Automated pipeline needs verification.

---

## Tier 3: BLOCKED-CREDENTIALS (2 sources needing API keys)

### 1. reddit-sentiment
- **Classification:** BLOCKED-CREDENTIALS
- **Collection log:** 9 runs, 0 successes (all "Circuit breaker is open")
- **Blocker:** Missing `REDDIT_CLIENT_ID` and `REDDIT_CLIENT_SECRET` environment variables
- **Collector:** `collect_sentiment.py` (PRAW-based, r/dubai + r/UAE)
- **Action:** User must create Reddit developer app and provide client ID/secret for HSM storage.

### 2. news-sentiment
- **Classification:** BLOCKED-CREDENTIALS
- **Collection log:** 2 runs, 0 successes (circuit breaker open)
- **Blocker:** Missing `NEWSAPI_KEY` environment variable
- **Collector:** `collect_news_sentiment.py` (NewsAPI.org, UAE business headlines + VADER)
- **Action:** User must obtain NewsAPI key and store in HSM.

---

## Tier 4: DORMANT-NEVER-RAN (8 sources -- missions defined, never executed)

| # | Source | Raw Data | Directory | Issue |
|---|--------|----------|-----------|-------|
| 1 | cooper-fitch-salary | None | Empty dir | Paywalled salary survey reports |
| 2 | hays-salary | None | Empty dir | Paywalled salary survey reports |
| 3 | roberthalf-salary | None | Empty dir | Paywalled salary survey reports |
| 4 | commercial-office-reports | None | No dir | Paywalled commercial RE reports |
| 5 | customs-imports | None | No dir | No public API or scraping path |
| 6 | ded-licenses | None | No dir | Behind DED portal login |
| 7 | fb-closures | None | No dir | No viable scraping approach for FB closures |
| 8 | insideairbnb | None | Empty dir | No Inside Airbnb data for UAE available |

**Common trait:** All 8 have registered COLLECTOR_DEFINITIONS entries and YAML mission files but no viable data acquisition path. They waste collection cycles on every scheduled run.

---

## Tier 5: DORMANT-BROKEN (3 sources -- attempted but producing unusable data)

### 1. dtcm-tourism
- **Raw data:** 1 JSON file (2 bytes = `[]`)
- **Collection log:** Never in automated log (manual scrape only)
- **Issue:** DTCM tourism stats page requires complex JS execution; scraper returns empty array
- **Normalizer:** `normalize_tourism.py` exists but has no input data

### 2. rta-metro
- **Raw data:** 1 JSON file (159 bytes) with `data_table: null`
- **Collection log:** Never in automated log
- **Issue:** RTA statistics page requires JS pagination; scraper gets null table data
- **Normalizer:** `normalize_metro.py` exists but has no input data

### 3. rta-vehicles
- **Raw data:** 1 JSON file (161 bytes) pointing at dubaipulse.gov.ae
- **Collection log:** 1 run, 1 success (misleading -- data is null)
- **Issue:** Dubai Pulse WAF blocks headless browsers
- **Normalizer:** `normalize_rta.py` exists but has no input data

---

## Tier 6: RETIRED (6 sources -- permanently blocked, no workaround)

### 1. dld-sales
- **Block reason:** Dubai Pulse WAF ("Request Rejected")
- **Evidence:** 4 CSV files, all 246 bytes of WAF rejection HTML
- **Collection log:** 4 runs, 0 successes
- **Verdict:** RETIRE. Dubai Pulse requires registered account at dubaidata.ae. User has not registered.

### 2. ejari-rentals
- **Block reason:** Dubai Pulse WAF (same as DLD)
- **Evidence:** 4 CSV files, all 246 bytes of WAF rejection HTML
- **Collection log:** 3 runs, 0 successes
- **Verdict:** RETIRE.

### 3. building-permits
- **Block reason:** Dubai Pulse WAF (same as DLD)
- **Evidence:** 2 CSV files, all 246 bytes of WAF rejection HTML
- **Collection log:** 1 run, 0 successes
- **Verdict:** RETIRE.

### 4. dewa-connections
- **Block reason:** DEWA site blocks headless browsers (timeout)
- **Evidence:** 2 JSON files with URL metadata only (280 bytes each, no data)
- **Collection log:** 1 run, 0 successes (circuit breaker open)
- **Verdict:** RETIRE.

### 5. gulftalent-jobs
- **Block reason:** Requires paid account credentials
- **Evidence:** 2 JSON files, both `[]` (empty arrays, 2 bytes each)
- **Collection log:** 2 runs, 0 successes
- **Verdict:** RETIRE.

### 6. google-maps-traffic
- **Block reason:** Google Maps Popular Times not scrapable at scale (1hr timeout, 50 locations)
- **Evidence:** Empty directory, no raw data files
- **Collection log:** 1 run, 0 successes (circuit breaker open)
- **Verdict:** RETIRE.

---

## Evidence: Database Queries

### Collection Log Summary (20 sources with activity)
```
adrec-abu-dhabi     | 3 runs  | 1 success  | Last: 2026-03-11
bayt-jobs           | 3 runs  | 3 successes| Last: 2026-03-23
bayut-listings      | 3 runs  | 2 successes| Last: 2026-03-23
building-permits    | 1 run   | 0 successes| Last: 2026-03-11
dewa-connections    | 1 run   | 0 successes| Last: 2026-03-11
dfm-stocks          | 2 runs  | 1 success  | Last: 2026-03-23
dld-sales           | 4 runs  | 0 successes| Last: 2026-03-23
ejari-rentals       | 3 runs  | 0 successes| Last: 2026-03-23
google-maps-traffic | 1 run   | 0 successes| Last: 2026-03-23
google-trends       | 9 runs  | 0 successes| Last: 2026-03-24
gulftalent-jobs     | 2 runs  | 0 successes| Last: 2026-03-23
imf-weo             | 1 run   | 1 success  | Last: 2026-03-23
indeed-jobs         | 3 runs  | 3 successes| Last: 2026-03-23
linkedin-jobs       | 8 runs  | 4 successes| Last: 2026-03-23
news-sentiment      | 2 runs  | 0 successes| Last: 2026-03-24
propertyfinder      | 5 runs  | 1 success  | Last: 2026-03-23
reddit-sentiment    | 9 runs  | 0 successes| Last: 2026-03-24
rta-vehicles        | 1 run   | 1 success  | Last: 2026-03-13
spglobal-pmi        | 1 run   | 1 success  | Last: 2026-03-23
worldbank-macro     | 1 run   | 1 success  | Last: 2026-03-23
```

### 18 Sources Never in Collection Log
```
cbuae-remittances, cbuae-mortgages, khda-enrollment, mohre-permits, dxb-passengers,
gdrfa-visas, rta-metro, dtcm-tourism, ded-licenses, jebel-ali-port, fb-closures,
cooper-fitch-salary, hays-salary, roberthalf-salary, insideairbnb, customs-imports,
commercial-office-reports, fcsa-demographics, commodities, cbuae-expanded
```

### Normalized Monthly Summary (17 sources)
```
adrec            |  18 rows |  18 metrics
bayt-jobs        |  21 rows |  16 metrics
cbuae            |  54 rows |   6 metrics
cbuae-expanded   |  47 rows |   7 metrics
commodities      | 208 rows |   4 metrics
dfm-stocks       | 488 rows |   8 metrics
dpworld          |   7 rows |   2 metrics
dxb-passengers   |  17 rows |   7 metrics
fcsa-demographics|   6 rows |   3 metrics
imf-weo          | 255 rows |  10 metrics
indeed-jobs      |  10 rows |   6 metrics
khda             |  37 rows |  37 metrics
linkedin-jobs    |  12 rows |   7 metrics
mohre-permits    |  32 rows |  11 metrics
propertyfinder   | 206 rows | 206 metrics
spglobal-pmi     |   1 rows |   1 metric
worldbank-macro  | 115 rows |   5 metrics
```

---

## Recommendations

### Immediate (Plan 20-01 -- this plan)
1. Retire 6 permanently blocked sources with `enabled: false` in registry
2. Disable 12 dormant sources (no data, no viable path) with `enabled: false`
3. Keep google-trends enabled (fixed by pytrends patch)
4. Keep bayut-listings enabled (fixable selector issue, not permanent block)
5. Keep reddit-sentiment and news-sentiment enabled (work if credentials provided)

### Next (Plan 20-02)
1. Run existing normalizers against raw data for cbuae-mortgages, google-trends
2. Verify automated pipeline for 6 sources with manual-ingest data
3. Fix Bayut selectors if viable

### Deferred
1. Dubai Pulse sources (dld-sales, ejari-rentals, building-permits) -- require user registration at dubaidata.ae
2. Reddit/NewsAPI credentials -- require user action
3. Salary surveys (cooper-fitch, hays, roberthalf) -- paywalled, no path forward
