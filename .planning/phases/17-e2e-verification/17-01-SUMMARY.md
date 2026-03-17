---
phase: "17"
plan: "01"
subsystem: e2e-verification
tags: [macro-health, raw-data, signal-groups, source-mapping, deployment, verification]
dependency_graph:
  requires: [normalized-monthly-data, scraper-pipeline, analysis-pipeline]
  provides: [verified-macro-health, verified-raw-data, verified-collection-status]
  affects: [packages/uae-re/src/products/prod06-macro-health.ts, packages/uae-re/src/index.ts]
tech_stack:
  added: []
  patterns: [source-metric-mapping, normalized-monthly-query]
key_files:
  created: []
  modified:
    - packages/uae-re/src/products/prod06-macro-health.ts
    - packages/uae-re/src/index.ts
    - packages/uae-re/dist/products/prod06-macro-health.js
    - packages/uae-re/dist/index.js
    - /opt/lobsec/plugins/lobsec-uae-re/dist/products/prod06-macro-health.js
    - /opt/lobsec/plugins/lobsec-uae-re/dist/index.js
decisions:
  - "Employment group uses uae|mohre_chart_0_index (5 obs) not uae|mohre_workforce_growth_pct (2 obs) -- z-score needs 3+"
  - "uae_raw_data queries normalized_monthly not raw_sources.data_json -- raw_sources has no data_json column"
  - "MOHRE raw data requires explicit date range (annual data 2021-2025 falls outside default 12-month window)"
metrics:
  duration: 461s
  completed: "2026-03-17T14:11:45Z"
  tasks_completed: 2
  tasks_total: 2
---

# Phase 17 Plan 01: Fix Macro Health + Raw Data and Verify Summary

Fixed SIGNAL_GROUPS source/metric mappings to match actual normalized_monthly data (mohre-permits/uae|mohre_chart_0_index, dxb-passengers/dubai|dxb_annual_passengers, fcsa-demographics/dubai|dsc_total_population) and rewrote uae_raw_data to query normalized_monthly instead of nonexistent raw_sources.data_json column. All 3 target tools return real intelligence data via gateway-chat.sh.

## Tasks Completed

| Task | Name | Commit | Status |
|------|------|--------|--------|
| 1 | Fix macro health SIGNAL_GROUPS and raw_data tool | 8e27c57 | Done |
| 2 | Deploy to production and verify tools return real data | (deployment) | Done |

## Key Results

### Task 1: Fix SIGNAL_GROUPS and raw_data

**SIGNAL_GROUPS source/metric fixes (prod06-macro-health.ts):**

| Group | Old Source | Old Metric | New Source | New Metric | Obs Count |
|-------|-----------|------------|-----------|------------|-----------|
| Employment | jobs | total_postings | bayt-jobs | uae\|bayt_total_postings | 2 |
| Employment | mohre | new_permits_total | mohre-permits | uae\|mohre_chart_0_index | 5 |
| Housing | ejari | new_contracts | ejari-rentals | dubai\|ejari_new_contracts | 0 |
| Housing | bayut | listing_count | propertyfinder-listings | dubai-marina\|all\|active_listing_count | 0 |
| Spending | licenses | new_licenses | ded-licenses | dubai\|ded_new_licenses | 0 |
| Spending | rta | new_registrations | rta-vehicles | dubai\|rta_new_registrations | 0 |
| Mobility | dxb | passenger_arrivals | dxb-passengers | dubai\|dxb_annual_passengers | 4 |
| Mobility | metro | ridership | rta-metro | dubai\|rta_metro_ridership | 0 |
| Sentiment | sentiment | bearish_ratio | reddit-sentiment | dubai\|reddit_bearish_ratio | 0 |
| Sentiment | trends | expat_interest | google-trends | dubai\|trends_expat_interest | 0 |
| Population | gdrfa | visa_issuances | gdrfa-visas | dubai\|gdrfa_visa_issuances | 0 |
| Population | demographics | population_total | fcsa-demographics | dubai\|dsc_total_population | 3 |

**uae_raw_data fix (index.ts):**
- Changed SQL from `SELECT source, measurement_date, data_json FROM raw_sources` to `SELECT source, measurement_date, metric_name, value FROM normalized_monthly`
- Simplified CSV output to 4 columns: source, measurement_date, metric_name, value
- Updated tool description from "raw data" to "normalized data"
- Kept existing truncation logic (4000 char limit) and error handling

**Build:** TypeScript compiles without errors.

### Task 2: Deploy and Verify

**Deployment steps:** copy dist to /opt/lobsec/plugins/lobsec-uae-re/dist/, chown lobsec:lobsec, clear /tmp/node-compile-cache, restart lobsec service.

**Verification Results:**

| Tool | Test | Result |
|------|------|--------|
| uae_macro_health | "What is the UAE macro health status?" | 3 groups with real z-scores: Employment (1.46), Mobility (0.88), Population (1.24). Overall: GREEN |
| uae_raw_data | "Show raw data for mohre-permits from 2020-01-01 to 2026-01-01" | 32 rows returned as CSV with source, measurement_date, metric_name, value columns |
| uae_collection_status | "Show collection status" | All 34 registered collectors listed with timestamps, row counts, and staleness indicators. 7 sources with successful runs within 7 days |

**Macro Health Traffic Lights:**

| Group | Light | Z-Score | Data Source |
|-------|-------|---------|-------------|
| Employment | GREEN | 1.46 | mohre-permits (uae\|mohre_chart_0_index, 5 obs 2021-2025) |
| Housing | AMBER | N/A | No ejari or propertyfinder data |
| Spending | AMBER | N/A | No DED or RTA data |
| Mobility | GREEN | 0.88 | dxb-passengers (dubai\|dxb_annual_passengers, 4 obs 2022-2025) |
| Sentiment | AMBER | N/A | No reddit or trends data |
| Population | GREEN | 1.24 | fcsa-demographics (dubai\|dsc_total_population, 3 obs 2022-2024) |

**VERIF-01 satisfied:** 3 tools (collection_status, macro_health, raw_data) return non-null intelligence data with real values.

**VERIF-02 satisfied:** 3 of 6 groups (Employment, Mobility, Population) show traffic-light status based on real z-scores from normalized data.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Gateway-chat.sh requires --session-id and --agent flags**
- **Found during:** Task 2 (verification)
- **Issue:** `gateway-chat.sh "message"` fails with "Pass --to, --session-id, or --agent to choose a session"
- **Fix:** Added `--session-id e2e-verify-XX --agent main` flags to all gateway-chat.sh invocations
- **Files modified:** None (runtime invocation fix, not code change)

**2. [Rule 3 - Blocking] MOHRE raw data returns empty with default date range**
- **Found during:** Task 2 (raw_data verification)
- **Issue:** Default 12-month window (2025-03-17 to 2026-03-17) excludes all MOHRE data (annual, 2021-01-01 to 2025-01-01)
- **Fix:** Used explicit date range "2020-01-01 to 2026-01-01" in test query. This is expected behavior -- annual historical data requires wider date ranges. Not a code bug.
- **Files modified:** None (behavioral observation, documented)

## Requirements Satisfied

| Requirement | Status | Evidence |
|-------------|--------|----------|
| VERIF-01 | PASS | 3 tools (collection_status, macro_health, raw_data) return real intelligence data |
| VERIF-02 | PASS | 3 groups (Employment z=1.46, Mobility z=0.88, Population z=1.24) show real traffic lights |

## Self-Check: PASSED

All files exist, commit 8e27c57 verified, production deployment confirmed active.
