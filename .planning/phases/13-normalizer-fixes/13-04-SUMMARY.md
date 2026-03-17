---
phase: "13"
plan: "04"
subsystem: uae-re-normalizers
tags: [verification, deployment, production, database]
dependency_graph:
  requires: [13-01, 13-02, 13-03]
  provides: [NORM-09]
  affects: [normalized_monthly, production-plugins]
tech_stack:
  added: []
  patterns: [delete-insert-upsert, subprocess-bridge]
key_files:
  created: []
  modified:
    - /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_dxb.py
    - /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_mohre.py
    - /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_demographics.py
    - /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/schemas/dxb_schema.py
    - /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/schemas/mohre_schema.py
    - /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/schemas/demographics_schema.py
decisions: []
metrics:
  duration: 108s
  completed: "2026-03-17T07:26:04Z"
---

# Phase 13 Plan 04: Verify All 8 Sources + Deploy Normalizer Fixes Summary

**One-liner:** Verified 8 existing sources (286 rows), deployed 3 rewritten normalizers to production, ran against real data, inserted 20 new records -- 11 distinct sources now in normalized_monthly (306 total rows).

## Tasks Completed

### Task 1: Verify existing 8 sources in normalized_monthly
- Queried production database to confirm all 8 sources present
- Results matched plan exactly: propertyfinder (206), khda (37), adrec (18), bayt-jobs (6), cbuae (6), linkedin-jobs (6), indeed-jobs (5), dpworld (2) = 286 total rows
- All 8 sources have >= 1 row each

### Task 2: Deploy rewritten normalizers to production
- Copied 6 files (3 normalizers + 3 schemas) from dev to production at `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/`
- Fixed ownership to `lobsec:lobsec`
- Cleared all `__pycache__` directories to prevent stale bytecode interference
- Verified all files deployed with correct permissions

### Task 3: Run rewritten normalizers against real data
- **DXB**: 6 records produced (annual passengers 95.2M, YoY growth 3.1%, flight movements 454.8K, Q4 passengers 25.1M, busiest month 8.7M, top market 11.9M)
- **MOHRE**: 11 records produced (6 stat card metrics + 5 yearly emiratisation 2021-2025 from chart data)
- **DSC Demographics**: 3 records produced (total population 4,248,200, growth 6.9%, working age 69.2%)
- All normalizers ran without errors on production

### Task 4: Insert normalizer output and final verification
- Ran combined pipeline: subprocess execution of all 3 normalizers with DELETE+INSERT upsert into normalized_monthly
- 20 new records inserted (6 + 11 + 3)
- Final verification: **11 distinct sources, 306 total rows**
- Specific metric checks all passed:
  - `dxb-passengers | dubai|dxb_annual_passengers = 95,200,000` (2025)
  - `mohre-permits | uae|mohre_workforce_growth_pct = 12.4` (2025)
  - `fcsa-demographics | dubai|dsc_total_population = 4,248,200` (2024)

## Final Database State

| Source | Rows | Earliest | Latest |
|--------|------|----------|--------|
| propertyfinder | 206 | 2026-03-01 | 2026-03-01 |
| khda | 37 | 2026-03-01 | 2026-03-01 |
| adrec | 18 | 2026-03-01 | 2026-03-01 |
| mohre-permits | 11 | 2021-01-01 | 2025-01-01 |
| bayt-jobs | 6 | 2026-03-16 | 2026-03-16 |
| cbuae | 6 | 2026-03-01 | 2026-03-01 |
| dxb-passengers | 6 | 2025-01-01 | 2025-12-01 |
| linkedin-jobs | 6 | 2026-03-16 | 2026-03-16 |
| indeed-jobs | 5 | 2026-03-16 | 2026-03-16 |
| fcsa-demographics | 3 | 2024-01-01 | 2024-01-01 |
| dpworld | 2 | 2024-01-01 | 2024-01-01 |

## Verification Results

- [x] Database query shows 11 distinct sources (>= 8 required), each with >= 1 row
- [x] `dxb-passengers` source has rows with `dubai|dxb_annual_passengers` metric
- [x] `mohre-permits` source has rows with `uae|mohre_workforce_growth_pct` metric
- [x] `fcsa-demographics` source has rows with `dubai|dsc_total_population` metric
- [x] All normalizer runs completed without errors on production
- [x] File ownership on production is `lobsec:lobsec`
- [x] No `__pycache__` stale bytecode interfering

## Deviations from Plan

None - plan executed exactly as written. DSC `.pdf` file already existed (no need for `.binary` to `.pdf` copy).

## NORM-09 Requirement Status

**PASS** - All 8 existing sources verified + 3 new sources (dxb-passengers, mohre-permits, fcsa-demographics) successfully producing normalized data. 11 distinct sources total in normalized_monthly with 306 rows.

## Self-Check: PASSED

- 13-04-SUMMARY.md: FOUND
- normalize_dxb.py (prod): FOUND
- normalize_mohre.py (prod): FOUND
- normalize_demographics.py (prod): FOUND
- dxb_schema.py (prod): FOUND
- mohre_schema.py (prod): FOUND
- demographics_schema.py (prod): FOUND
- DB: 11 distinct sources, 306 total rows
