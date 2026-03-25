---
phase: 20-dormant-mission-activation
plan: 02
subsystem: uae-re-normalizer-activation
tags: [normalizer-testing, data-upsert, google-trends, pdfplumber, rss-parsing, cbuae-mortgages]
dependency_graph:
  requires: [20-01 mission-audit]
  provides: [20-active-sources, normalizer-fixes]
  affects: [normalized_monthly, collection-pipeline, analysis-reports]
tech_stack:
  added: []
  patterns: [html-rss-extraction, wide-table-pdf-parsing, manual-normalization-upsert]
key_files:
  created: []
  modified:
    - packages/uae-re/python/uae_re/normalize_mortgages.py
    - packages/uae-re/python/uae_re/normalize_port.py
decisions:
  - "Rewrote normalize_mortgages.py for actual Banking Indicators PDF format (wide per-emirate table) instead of non-existent separate mortgage tables"
  - "Rewrote normalize_port.py to parse HTML __NEXT_DATA__ RSS feed instead of expecting pre-structured JSON"
  - "Used jebel-ali-port as new source name (not dpworld) for new Jebel Ali data extracted from RSS"
  - "Google Trends produces 325 normalized records from 6 keyword groups (53 weekly data points each)"
metrics:
  duration: 819s
  completed: "2026-03-25T17:31:24Z"
  tasks_completed: 2
  tasks_total: 2
  files_created: 0
  files_modified: 2
---

# Phase 20 Plan 02: Activate Dormant Normalizers Summary

Tested 7 normalizers against existing raw data, fixed 2 normalizers with incorrect format assumptions, verified Google Trends end-to-end after pytrends patch, and upserted 352 records. Result: 20 distinct sources in normalized_monthly (up from 17), 1,866 total rows (up from 1,534), 384 distinct metrics.

## What Was Built

### Task 1: Test 7 Normalizers Against Existing Raw Data

Tested each normalizer manually against production raw data files. Results:

| # | Source | Status | Metrics | Records | Notes |
|---|--------|--------|---------|---------|-------|
| 1 | cbuae-mortgages | PASS (after fix) | 5 | 5 | Rewrote for Banking Indicators PDF format |
| 2 | cbuae-remittances | WRONG-PDF | 0 | 0 | PDF is Banking Statistics bulletin, not Balance of Payments. No remittance tables present. Source `cbuae` already active (54 rows from prior run). |
| 3 | khda-enrollment | INFOGRAPHIC-PDF | 0 | 0 | PDF is infographic layout, not machine-readable tables. Source `khda` already active (37 rows from prior run). |
| 4 | fcsa-demographics | PASS | 3 | 3 | Population 4.2M, growth 6.9%, working age 69.2% |
| 5 | dxb-passengers | PASS | 6 | 6 | Annual passengers 95.2M, YoY growth 3.1%, 454.8K flights |
| 6 | mohre-permits | PASS | 11 | 11 | Workforce growth 12.4%, emiratisation 176K |
| 7 | jebel-ali-port | PASS (after fix) | 2 | 2 | 15.5M TEU, 5.4M MT breakbulk cargo (2024) |

**5 of 7 normalizers produced valid output** (exceeds 5-of-7 target).

**Normalizer Fixes Applied:**

1. **normalize_mortgages.py** -- Complete rewrite. Original expected separate EIBOR/mortgage tables. Actual PDF is a single wide Banking Indicators table (41 rows x 53 cols) with per-emirate (AD/DXB/OE) monthly data. New version extracts 5 metrics by summing AD+DXB+OE for gross credit, private sector credit, individual lending, deposits, and capital reserves.

2. **normalize_port.py** -- Complete rewrite. Original expected pre-structured JSON with `scrapedAt`, `container_throughput_teu`, `cargo_volume_tonnes` fields. Actual raw data is 3.2M HTML from dpworld.com with `__NEXT_DATA__` containing an RSS feed of 446 press releases. New version parses the HTML, extracts __NEXT_DATA__ JSON, navigates to RSS items, filters for Jebel Ali throughput articles, and extracts TEU/cargo figures from article descriptions via regex.

### Task 2: Google Trends End-to-End + Final Verification

**Google Trends Collection:** Successfully collected 318 raw records across 6 keyword groups:
- buy_intent: "buy apartment Dubai", "Dubai property investment", "off-plan Dubai"
- rent_intent: "rent apartment Dubai", "Dubai rental", "furnished flat Dubai"
- expat_lifecycle: "Dubai work visa", "UAE job", "move to Dubai", "Golden Visa Dubai"
- distress: "break tenancy Dubai", "cancel Ejari", "move out Dubai"
- luxury: "luxury villa Dubai", "penthouse Dubai", "premium apartment Dubai"
- exit_moving: "moving companies dubai", "international movers dubai", "leaving Dubai"

**Google Trends Normalization:** 325 normalized records with 25 distinct metrics (per-keyword + group averages), covering 13 months (Mar 2025 - Mar 2026).

**Final Source Count:**

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Distinct sources | 17 | 20 | +3 |
| Total rows | 1,534 | 1,866 | +332 |
| Distinct metrics | 354 | 384 | +30 |

**New sources added:**
- `cbuae-mortgages`: 5 rows, 5 metrics (banking indicators)
- `jebel-ali-port`: 2 rows, 2 metrics (port throughput from RSS)
- `google-trends`: 325 rows, 25 metrics (search interest indices)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] normalize_mortgages.py expected wrong PDF format**
- **Found during:** Task 1, source 1a
- **Issue:** Normalizer expected separate EIBOR/mortgage/lending tables. Actual PDF is a single wide Banking Indicators table with 41 rows and per-emirate columns.
- **Fix:** Complete rewrite to parse wide-format table, find latest month columns, extract target rows by label match with row-range limits.
- **Files modified:** `packages/uae-re/python/uae_re/normalize_mortgages.py`
- **Commit:** cca2c21

**2. [Rule 1 - Bug] normalize_port.py expected JSON but raw data is HTML**
- **Found during:** Task 1, source 1g
- **Issue:** Normalizer tried to `json.load()` an HTML file (3.2M). The raw data contains __NEXT_DATA__ with an RSS feed.
- **Fix:** Complete rewrite to parse HTML, extract __NEXT_DATA__ JSON, navigate RSS feed structure, find Jebel Ali articles, extract figures from description text.
- **Files modified:** `packages/uae-re/python/uae_re/normalize_port.py`
- **Commit:** cca2c21

### Not Issues (Expected Behavior)

**3. cbuae-remittances PDF is wrong document type**
- The downloaded PDF is a Banking & Monetary Statistics bulletin (59 pages), not a Balance of Payments report. It has no remittance tables. The `cbuae` source already has 54 rows from a prior manual run with the correct PDF. Not a normalizer bug -- the scraper downloaded a different CBUAE publication.

**4. khda-enrollment PDF is infographic format**
- The KHDA Dubai Private School Landscape 2024-25 document is a visual infographic, not a traditional tabular report. pdfplumber extracts fragments instead of data tables. The `khda` source already has 37 rows from prior manual entry. Not fixable without OCR.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | cca2c21 | Fix normalize_mortgages.py and normalize_port.py, upsert 27 records |
| 2 | (data only) | Google Trends collection + normalization (325 records upserted to DB) |

## Success Criteria Verification

- [x] 5+ normalizers from the 7 tested produce correct output (5 PASS: cbuae-mortgages, fcsa-demographics, dxb-passengers, mohre-permits, jebel-ali-port)
- [x] At least 1 new source added (3 new: cbuae-mortgages, jebel-ali-port, google-trends)
- [x] Total distinct sources >= 18 (actual: 20)
- [x] Google Trends collector verified working (325 normalized records)
- [x] Normalizer fixes deployed to production
- [x] DORM-02 requirement satisfied

## Self-Check: PASSED

All files verified present. Commit cca2c21 verified in git log. Database has 20 sources, 1,866 rows. Production normalizers deployed. Service active.
