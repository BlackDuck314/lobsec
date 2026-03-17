---
phase: "13"
plan: "02"
subsystem: normalizer
tags: [mohre, dashboard, stat-cards, chart-labels, normalization]
dependency_graph:
  requires: []
  provides: [mohre-dashboard-normalizer]
  affects: [normalize_mohre.py, mohre_schema.py]
tech_stack:
  added: []
  patterns: [stat-card-regex-extraction, chartjs-config-parsing, label-deduplication]
key_files:
  created: []
  modified:
    - packages/uae-re/python/uae_re/schemas/mohre_schema.py
    - packages/uae-re/python/uae_re/normalize_mohre.py
decisions:
  - "uae| prefix for MOHRE metrics (federal ministry, not Dubai-specific)"
  - "Annual measurement_date (YYYY-01-01) for all MOHRE dashboard data"
  - "Only extract Emiratisation chart (chart 8) -- other charts are ambiguous unnamed indices"
  - "De-duplicate stat cards by metric label (same data repeats across tab sections)"
metrics:
  duration: 328s
  completed: "2026-03-17T07:21:03Z"
  tasks_completed: 3
  tasks_total: 3
---

# Phase 13 Plan 02: Rewrite MOHRE Observatory Normalizer Summary

Replaced article/press-release text extraction with dashboard JSON parsing (stat_cards regex + Chart.js chart_labels parsing), extracting 11 annual metrics from MOHRE Observatory scrape data.

## Tasks Completed

| Task | Name | Commit | Status |
|------|------|--------|--------|
| 1 | Rewrite mohre_schema.py for dashboard JSON validation | a65ea49 (pre-committed) | Done |
| 2 | Rewrite normalize_mohre.py for stat_cards + chart_labels | a65ea49 (pre-committed) | Done |
| 3 | Verify against actual raw data | (verification) | Done |

## Verification Results

All 11 metrics extracted from `/opt/lobsec/data/raw/mohre-permits/2026-03-17.json`:

### Stat Card Metrics (6)

| Metric | Value | measurement_date |
|--------|-------|-----------------|
| uae\|mohre_workforce_growth_pct | 12.4 | 2025-01-01 |
| uae\|mohre_skilled_worker_growth_pct | 6.3 | 2025-01-01 |
| uae\|mohre_youth_workforce_pct | 54.9 | 2025-01-01 |
| uae\|mohre_establishment_growth_pct | 7.8 | 2025-01-01 |
| uae\|mohre_female_leadership_pct | 17.4 | 2025-01-01 |
| uae\|mohre_emiratisation_count | 176,125 | 2025-01-01 |

### Chart Label Metrics (5 yearly records)

| Metric | Value | measurement_date |
|--------|-------|-----------------|
| uae\|mohre_emiratisation_yearly | 37,569 | 2021-01-01 |
| uae\|mohre_emiratisation_yearly | 60,136 | 2022-01-01 |
| uae\|mohre_emiratisation_yearly | 91,773 | 2023-01-01 |
| uae\|mohre_emiratisation_yearly | 131,883 | 2024-01-01 |
| uae\|mohre_emiratisation_yearly | 176,255 | 2025-01-01 |

All 8 verification checks passed:
- At least 4 records: PASS (11 records)
- All source=mohre-permits: PASS
- workforce_growth_pct=12.4: PASS
- emiratisation_count=176125: PASS
- emiratisation_yearly=5 records: PASS
- All dates YYYY-01-01: PASS
- No duplicates: PASS
- establishment_growth_pct=7.8: PASS

## Deviations from Plan

### Pre-committed Code

The code for Tasks 1 and 2 was already committed in `a65ea49` (part of Plan 01's docs commit) by the previous executor. The files on disk matched the plan specification exactly, so no additional code commit was needed. Verification (Task 3) confirmed the code works correctly against real data.

### Auto-fixed: Removed pandas dependency for ref_year fallback

**Rule 2 -- Missing critical functionality**: The plan code used `import pandas as pd` for a simple year extraction fallback (`pd.to_datetime(collected_at).year`). Replaced with `int(collected_at[:4])` to avoid importing a heavy library for trivial string slicing. pandas is not imported anywhere in the final normalizer.

## Key Changes

### mohre_schema.py
- Replaced `validate_mohre_json(data: dict)` (in-memory dict validation) with `validate_mohre_json(file_path: str)` (file loading + validation)
- Validates: file exists, is valid JSON, is non-empty list, each item has stat_cards and chart_labels lists
- Returns parsed data (caller no longer reads file separately)
- Removed article/scrapedAt/source_url validation entirely

### normalize_mohre.py
- Removed `extract_permit_numbers()` text extraction function entirely
- Added `extract_stat_card_metrics()`: regex-based stat card parsing with keyword-to-metric mapping and de-duplication
- Added `extract_emiratisation_chart()`: Chart.js config parsing for yearly time series
- `normalize_mohre()` takes stat_cards + chart_labels lists (not a data dict with articles)
- `main()` aggregates stat_cards and chart_labels across all page objects
- Changed metric prefix from `dubai|mohre_` to `uae|mohre_` (MOHRE is federal)
- Changed from monthly to annual measurement_date

## Self-Check: PASSED
