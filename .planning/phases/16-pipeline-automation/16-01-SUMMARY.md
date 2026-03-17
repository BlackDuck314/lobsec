---
phase: "16"
plan: "01"
subsystem: normalization
tags: [normalizer, scraper-format, jobs, listings, pipeline]
dependency_graph:
  requires: []
  provides: [scraper-format-adapters, fixed-normalizers]
  affects: [normalize_jobs.py, normalize_propertyfinder.py, normalize_bayut.py, jobs_schema.py, listings_schema.py]
tech_stack:
  added: []
  patterns: [adapter-pattern, format-conversion, string-parsing]
key_files:
  created: []
  modified:
    - packages/uae-re/python/uae_re/normalize_jobs.py
    - packages/uae-re/python/uae_re/normalize_propertyfinder.py
    - packages/uae-re/python/uae_re/normalize_bayut.py
    - packages/uae-re/python/uae_re/schemas/jobs_schema.py
    - packages/uae-re/python/uae_re/schemas/listings_schema.py
decisions:
  - "adapt_scraper_format() as adapter function (not modifying normalize_xxx core logic)"
  - "bedrooms schema changed from int to float (NaN not coercible to int64 in pandera)"
  - "Bayut blocked data returns area-level zero counts (20 metrics) not empty list"
metrics:
  duration: 426s
  completed: "2026-03-17T10:50:13Z"
  tasks_completed: 3
  tasks_total: 3
---

# Phase 16 Plan 01: Fix Normalizers for Scraper Format Summary

Added adapt_scraper_format() adapters to 3 normalizer modules (jobs, propertyfinder, bayut) converting Ninja Scraper list-of-pages/areas output to the dict format normalizers expect, with string-to-numeric parsing for prices, salaries, and total counts.

## Tasks Completed

| Task | Name | Commit | Status |
|------|------|--------|--------|
| 1 | Fix jobs normalizer and schema for scraper list format | b72c266 | Done |
| 2 | Fix listings normalizers and schema for scraper format | fe23fea | Done |
| 3 | Deploy fixed normalizers to production and verify | (deployment) | Done |

## Key Changes

### Task 1: Jobs normalizer (LinkedIn, Bayt, Indeed)
- **adapt_scraper_format()**: Merges `cards` arrays from all pages into single `listings` list
- **total_count parser**: Handles "12.4K jobs found", "1,000+", int, and None formats with K/M suffix multiplier
- **Salary parser**: Converts "$1,500 - $2,000" strings to salary_min/salary_max ints
- **career_level mapping**: Maps Bayt's `career_level` to `seniority_level` for seniority classification
- **validate_jobs_json()**: Now accepts both list (scraper format) and dict (legacy format)
- **Results**: LinkedIn=7 metrics (60 cards), Bayt=13 metrics (150 cards, median salary $2,125), Indeed=6 metrics (16 cards)

### Task 2: Listings normalizers (PropertyFinder, Bayut)
- **adapt_scraper_format()**: Converts area-list format to `{scrapedAt, areas: [...]}` dict, injecting `collectedAt` as `scrapedAt`
- **Price parser**: Handles "33,500,000 AED", "7,500,000 AEDHigh demand~ 16K Mortgage Cashback" formats
- **String-to-numeric**: Bedrooms ("4" -> int), sqft ("4,567 sqft" -> float)
- **Bayut null handling**: CAPTCHA-blocked data (all null fields) produces empty listings per area
- **Schema fix**: `bedrooms` changed from `int` to `float` (pandas NaN not coercible to int64)
- **listingCount validation**: Now accepts None (defaults to 0) for blocked sources
- **Results**: PropertyFinder=297 metrics (3,936 cards/20 areas), Bayut=20 metrics (all zeros, CAPTCHA blocked)

### Task 3: Production deployment
- All 5 Python files deployed to `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/`
- Bytecode cache cleared, ownership set to `lobsec:lobsec`
- All 5 normalizers verified against production raw data files

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Pandera bedrooms schema type**
- **Found during:** Task 2
- **Issue:** ListingItemSchema declared `bedrooms: Series[int]` with `nullable=True`, but pandera cannot coerce NaN values to int64 (some PropertyFinder listings have null bedrooms)
- **Fix:** Changed to `Series[float]` which naturally supports NaN
- **Files modified:** packages/uae-re/python/uae_re/schemas/listings_schema.py
- **Commit:** fe23fea

## Production Verification Results

| Source | Module | Metrics | Details |
|--------|--------|---------|---------|
| linkedin-jobs | normalize_jobs | 7 | 60 cards, 1,000+ total, no salary data |
| bayt-jobs | normalize_jobs | 13 | 150 cards, 12,400 total, median salary $2,125 |
| indeed-jobs | normalize_jobs | 6 | 16 cards, no total_count, no salary data |
| propertyfinder-listings | normalize_propertyfinder | 297 | 3,936 cards, 20 areas, median palm-jumeirah $17M |
| bayut-listings | normalize_bayut | 20 | All areas CAPTCHA-blocked, 20 zero-count metrics |

## Self-Check: PASSED

All 5 source files found in repo and production. Both commits (b72c266, fe23fea) verified in git log. All 5 production normalizers tested and producing correct output.
