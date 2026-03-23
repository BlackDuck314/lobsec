---
phase: 18-macro-economic-apis
plan: 02
subsystem: uae-re-macro-pmi-health
tags: [pmi, spglobal, macro-health, signal-groups, nftables, collectors, normalizers]
dependency_graph:
  requires: [18-01 macro-api-collectors]
  provides: [spglobal-pmi-source, macro-health-8-groups]
  affects: [normalized_monthly, prod06-macro-health, collection_log]
tech_stack:
  added: [S&P Global PMI direct HTTP + pdfplumber]
  patterns: [DirectPythonCollector, fallback-collection, macro-health-signal-groups]
key_files:
  created:
    - packages/uae-re/python/uae_re/collect_pmi.py
    - packages/uae-re/python/uae_re/normalize_pmi.py
    - packages/uae-re/python/uae_re/schemas/pmi_schema.py
  modified:
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/src/normalization/types.ts
    - packages/uae-re/src/collectors/registry.ts
    - packages/uae-re/src/products/prod06-macro-health.ts
decisions:
  - "PMI direct HTTP worked unexpectedly (AWS WAF did not block), extracted PMI 44.8 via pdfplumber"
  - "nftables already allows tcp dport 443 for all HTTPS egress, no additional rules needed"
  - "Macro Economy and RE Stocks groups placed after Population (positions 7-8)"
metrics:
  duration: 389s
  completed: "2026-03-23T15:48:00Z"
  tasks_completed: 2
  tasks_total: 2
  files_created: 3
  files_modified: 4
---

# Phase 18 Plan 02: PMI Collector + Macro Health Enhancement Summary

PMI collector with direct HTTP + pdfplumber extraction deployed (value 44.8 extracted successfully), macro health dashboard expanded from 6 to 8 signal groups (Macro Economy + RE Stocks), total normalized sources now 15.

## What Was Built

### Task 1: PMI Collector + Normalizer + Schema + TS Registration + Signal Groups

**PMI Collector (collect_pmi.py):**
- Strategy 1: Direct HTTP GET to pmi.spglobal.com with browser User-Agent
- Strategy 2: Ninja Scraper API fallback for browser automation
- PDF extraction via pdfplumber: regex for headline PMI number (2-digit.1-decimal, 40-65 range)
- Graceful fallback: saves pmi_value=null if both strategies fail
- Result: Direct HTTP worked on first attempt (AWS WAF did not trigger)

**PMI Normalizer (normalize_pmi.py):**
- Single metric: `uae|spglobal_pmi_headline`
- If pmi_value is null, returns empty list (no rows inserted)
- measurement_date = first of month from collectedAt

**PMI Schema (pmi_schema.py):**
- Validates collectedAt key exists
- Validates pmi_value is null or float in range 30.0-70.0

**TS Registration:**
- Extended PythonScriptName with `collect_pmi` and `normalize_pmi`
- Added `spglobal-pmi` to SOURCE_MODULE_MAP
- Added to COLLECTOR_DEFINITIONS (38 total, was 37) and DIRECT_PYTHON_SOURCES (6 total, was 5)

**Macro Health Signal Groups:**
- Added "Macro Economy" group: worldbank-macro GDP growth + IMF WEO GDP growth
- Added "RE Stocks" group: DFM Emaar close + DFM Emaar Development close
- Dashboard now has 8 signal groups (was 6)

**nftables:**
- Existing `tcp dport 443 accept` rule already covers all 4 macro API domains (api.worldbank.org, www.imf.org, query2.finance.yahoo.com, pmi.spglobal.com)
- No changes needed

### Task 2: Deploy + Verify End-to-End

- Deployed to /opt/lobsec/plugins/lobsec-uae-re/ (dist + python)
- PMI collection: SUCCESS (value 44.8, method: direct_http)
- PMI normalization: 1 record inserted (uae|spglobal_pmi_headline = 44.8, 2026-03-01)
- All 4 macro sources verified in normalized_monthly
- Macro health dashboard output shows 8 groups with data:
  - Macro Economy: GREEN (0.36) -- WB GDP +0.24, IMF GDP +0.47
  - RE Stocks: RED (-1.30) -- Emaar -1.84, Emaar Dev -0.76
- Total sources: 15 (was 11 before Phase 18)

## Production Data

| Source | Metrics | Total Rows | Obs per Metric | Date Range |
|--------|---------|------------|----------------|------------|
| worldbank-macro | 5 | 115 | 17-25 | 2000-2024 |
| imf-weo | 10 | 255 | 4-47 | 1980-2030 |
| dfm-stocks | 8 | 488 | 61 | 2021-03 to 2026-03 |
| spglobal-pmi | 1 | 1 | 1 | 2026-03 |
| **Phase 18 Total** | **24** | **859** | | |

### Macro Health Dashboard (8 Groups)

| Group | Light | Avg Z-Score | Source A | Source B |
|-------|-------|-------------|----------|----------|
| Employment | GREEN | 1.46 | mohre: 1.46 | bayt: n/a |
| Housing | AMBER | n/a | ejari: no data | pf: no data |
| Spending | AMBER | n/a | ded: no data | rta: no data |
| Mobility | GREEN | 0.88 | dxb: 0.88 | metro: no data |
| Sentiment | AMBER | n/a | reddit: no data | trends: no data |
| Population | GREEN | 1.24 | gdrfa: no data | fcsa: 1.24 |
| **Macro Economy** | **GREEN** | **0.36** | **WB GDP: 0.24** | **IMF GDP: 0.47** |
| **RE Stocks** | **RED** | **-1.30** | **Emaar: -1.84** | **EmaarDev: -0.76** |

## Deviations from Plan

### Auto-fixed Issues

None -- plan executed exactly as written.

### Observations

**1. [Observation] PMI direct HTTP succeeded unexpectedly**
- **Found during:** Task 2, Step 2 (PMI collection)
- **Expected:** AWS WAF to block direct HTTP access (MEDIUM confidence source)
- **Actual:** Direct HTTP with browser User-Agent returned valid content, pdfplumber extracted PMI value 44.8
- **Impact:** Positive -- PMI data available on first attempt without needing Ninja Scraper
- **Note:** AWS WAF may block in future; collector has Ninja Scraper fallback ready

**2. [Observation] nftables already sufficient**
- **Found during:** Task 1, Part D
- **Expected:** Need to add IP-based rules for 4 API domains
- **Actual:** Existing `tcp dport 443 accept` allows all HTTPS egress from uid 995
- **Impact:** No nftables changes needed -- all macro API domains already reachable

**3. [Observation] RE Stocks showing RED signal**
- **Found during:** Task 2, Step 4 (macro health verification)
- **Issue:** Both Emaar (-1.84) and Emaar Development (-0.76) z-scores are negative
- **Context:** This is real market data -- RE stocks trending down relative to 5-year average
- **Impact:** None (correct behavior, not a bug)

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | b22d060 | PMI collector + normalizer + schema + TS registration + 8 signal groups |

## Success Criteria Verification

- [x] PMI collector + normalizer deployed (collection succeeded with value 44.8)
- [x] Macro Health Dashboard has 8 signal groups (6 existing + Macro Economy + RE Stocks)
- [x] nftables egress allows all 4 API domains (tcp dport 443 accept)
- [x] End-to-end: 4 macro sources producing normalized data, total sources = 15
- [x] At least 3 metrics with 12+ observations (all 18 non-forecast metrics qualify)
- [x] 38 collectors registered in COLLECTOR_DEFINITIONS
- [x] TypeScript build: 0 errors
- [x] Python modules import correctly

## Self-Check: PASSED

All 3 created files verified present in source and deployed to production. Commit b22d060 verified in git log. All 6 deployed files confirmed at /opt/lobsec/plugins/lobsec-uae-re/.
