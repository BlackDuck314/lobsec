---
phase: 13
plan: 03
subsystem: uae-re/normalizers
tags: [normalizer, pdf-extraction, demographics, pdfplumber]
dependency_graph:
  requires: []
  provides: [NORM-08]
  affects: [normalize_demographics, demographics_schema]
tech_stack:
  added: []
  patterns: [pdfplumber-pdf-extraction, pdf-table-parsing, clean-number-helper]
key_files:
  created: []
  modified:
    - packages/uae-re/python/uae_re/schemas/demographics_schema.py
    - packages/uae-re/python/uae_re/normalize_demographics.py
decisions:
  - "69.2% working age (25-54) is correct for Dubai expat-heavy economy"
  - "No expat/national metrics in 2024 Population Bulletin -- omitted, not zeroed"
metrics:
  duration: 165s
  completed: "2026-03-17T07:18:10Z"
  tasks_completed: 3
  tasks_total: 3
requirements: [NORM-08]
---

# Phase 13 Plan 03: Rewrite DSC Demographics Normalizer Summary

Rewrote demographics normalizer from JSON field extraction to pdfplumber PDF table extraction -- 3 metrics from 12-page DSC Population Bulletin (4.2M total pop, 6.9% growth, 69.2% working age).

## Tasks Completed

### Task 1: Rewrite demographics_schema.py for PDF validation
- **Commit:** 9f63287
- Replaced `validate_demographics_json()` with `validate_demographics_pdf()`
- Validates: file existence, `.pdf` extension, `%PDF` header bytes
- Matches `khda_schema.py` pattern exactly

### Task 2: Rewrite normalize_demographics.py for PDF extraction
- **Commit:** e868fcd
- Complete rewrite: JSON field extraction replaced with pdfplumber PDF table extraction
- `clean_number()` helper handles None, embedded spaces, commas, percentage symbols
- `extract_reference_year()`: gets year from PDF title page (page 1)
- `extract_population_from_page2()`: finds Total row, extracts last two large numbers (current + prior year)
- `extract_working_age_from_page4()`: sums 25-54 age groups, calculates percentage of total
- Growth rate calculated from current vs prior year: `(4,248,200 - 3,974,300) / 3,974,300 * 100 = 6.9%`
- Removed `dsc_expat_population` and `dsc_national_population` metrics (not in 2024 bulletin)

### Task 3: Verify against actual raw PDF
- Ran normalizer against `/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf`
- All 7 verification criteria PASS:
  1. 3 records returned (>= 2 required)
  2. All source = "fcsa-demographics"
  3. `dubai|dsc_total_population` = 4,248,200 (exact)
  4. `dubai|dsc_population_growth_pct` = 6.9 (exact)
  5. measurement_date = 2024-01-01 (from PDF title year)
  6. No expat/national metrics in output
  7. `dubai|dsc_working_age_pct` = 69.2% (reasonable for Dubai)

## Verification Output

```json
[
  {"measurement_date": "2024-01-01", "metric_name": "dubai|dsc_total_population", "value": 4248200, "available_date": "2026-03-17T10:00:00.000Z", "source": "fcsa-demographics"},
  {"measurement_date": "2024-01-01", "metric_name": "dubai|dsc_population_growth_pct", "value": 6.9, "available_date": "2026-03-17T10:00:00.000Z", "source": "fcsa-demographics"},
  {"measurement_date": "2024-01-01", "metric_name": "dubai|dsc_working_age_pct", "value": 69.2, "available_date": "2026-03-17T10:00:00.000Z", "source": "fcsa-demographics"}
]
```

## Deviations from Plan

None - plan executed exactly as written.

## Notes

- Raw PDF file exists as both `.binary` and `.pdf` (identical, same md5sum)
- Working age percentage (69.2%) is higher than the plan estimate of 56-60% -- this is correct for Dubai's demographics where the 25-54 age bracket dominates due to the expatriate workforce
- The `packages/uae-re/` directory is gitignored; commits use `git add -f`

## Self-Check: PASSED

- FOUND: packages/uae-re/python/uae_re/schemas/demographics_schema.py
- FOUND: packages/uae-re/python/uae_re/normalize_demographics.py
- FOUND: .planning/phases/13-normalizer-fixes/13-03-SUMMARY.md
- FOUND: commit 9f63287 (Task 1)
- FOUND: commit e868fcd (Task 2)
