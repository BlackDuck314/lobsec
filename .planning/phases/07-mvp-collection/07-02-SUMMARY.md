---
phase: 07-mvp-collection
plan: 02
subsystem: database
tags: [csv-collectors, dubai-pulse, dld, ejari, building-permits, pandera, normalization]

# Dependency graph
requires:
  - phase: 07-mvp-collection-01
    provides: Normalization orchestrator, area mapping, pandera validation infrastructure
provides:
  - DLD sales collector with 7 metrics (volume, median price, price per sqft, percentiles, YoY, MoM)
  - Ejari rentals collector with rental-specific metrics (volume, avg rent, renewal rate, rent YoY)
  - Building permits collector with residential/commercial classification
  - 3 pandera schemas (dld_schema, ejari_schema, permits_schema)
  - 3 Python normalization modules (normalize_dld, normalize_ejari, normalize_permits)
affects: [07-03, 07-04, 08-tier-b-collection, 10-statistical-analysis]

# Tech tracking
tech-stack:
  added: []
  patterns: [shared CSV download pattern, multi-field keyword classification, YoY/MoM delta computation]

key-files:
  created:
    - packages/uae-re/src/collectors/dld-sales.ts
    - packages/uae-re/src/collectors/ejari-rentals.ts
    - packages/uae-re/src/collectors/building-permits.ts
    - packages/uae-re/python/uae_re/schemas/dld_schema.py
    - packages/uae-re/python/uae_re/schemas/ejari_schema.py
    - packages/uae-re/python/uae_re/schemas/permits_schema.py
    - packages/uae-re/python/uae_re/normalize_dld.py
    - packages/uae-re/python/uae_re/normalize_ejari.py
    - packages/uae-re/python/uae_re/normalize_permits.py
  modified: []

key-decisions:
  - "DLD and Ejari collectors download same Dubai Pulse CSV independently (trans_group_en filtering happens in normalization)"
  - "YoY metrics return null until 12+ months of history exist; MoM until 2+ months (no false zeros)"
  - "Building permits classification uses multi-field keyword matching (permit_type, building_type, usage, project_type)"
  - "Permits schema uses strict=False to allow dataset column variations"
  - "Renewal rate estimated by comparing volume overlap between consecutive months"

patterns-established:
  - "Shared source pattern: Multiple collectors can download same CSV and filter during normalization"
  - "Delta computation pattern: YoY/MoM computed from sorted time series with minimum history thresholds"
  - "Multi-field classification pattern: Combine multiple CSV fields for robust categorization"

requirements-completed: [COLL-01, COLL-02, COLL-03]

# Metrics
duration: 25min
completed: 2026-03-11
---

# Phase 7 Plan 02: DLD Sales + Ejari Rentals + Building Permits Summary

**CSV-based Dubai Pulse collectors (DLD sales, Ejari rentals, building permits) with pandera validation, extended metrics (YoY/MoM deltas), and residential/commercial classification**

## Performance

- **Duration:** 25 min
- **Started:** 2026-03-11T18:39:00Z
- **Completed:** 2026-03-11T19:04:00Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments

- DLD sales collector downloads weekly CSV from Dubai Pulse, aggregates by (area, property_type) with 7 metrics: volume, median_price, median_price_per_sqft, total_value, price_p25, price_p75, plus YoY and MoM changes
- Ejari rentals collector shares same Dubai Pulse source, filters to trans_group_en=Rent, derives rental_volume, avg_rent, avg_rent_per_sqft, renewal_rate (volume overlap approximation), and rent_yoy_change
- Building permits collector (monthly) classifies residential vs commercial using multi-field keyword matching, tracks permits_issued_{residential|commercial}, permits_withdrawn, permits_expired, and per-area counts
- pandera schemas validate CSV structure with coerce=True for type flexibility and hard error on validation failure (NORM-04)
- Delta metrics (YoY/MoM) only output when sufficient history exists (12+ months for YoY, 2+ months for MoM) to avoid false zeros

## Task Commits

Each task was committed atomically:

1. **Task 1: Build DLD sales and Ejari rentals collectors with shared download** - `4a5a394` (feat)
2. **Task 2: Build building permits collector with Python normalization** - `abb033b` (feat)

## Files Created/Modified

Created:
- `packages/uae-re/src/collectors/dld-sales.ts` - DLD sales collector (weekly, priority 1)
- `packages/uae-re/src/collectors/ejari-rentals.ts` - Ejari rentals collector (weekly, priority 1)
- `packages/uae-re/src/collectors/building-permits.ts` - Building permits collector (monthly, priority 2)
- `packages/uae-re/python/uae_re/schemas/dld_schema.py` - pandera schema for DLD transactions (trans_group_en validation)
- `packages/uae-re/python/uae_re/schemas/ejari_schema.py` - Re-exports dld_schema (same source CSV)
- `packages/uae-re/python/uae_re/schemas/permits_schema.py` - pandera schema for building permits (strict=False for flexibility)
- `packages/uae-re/python/uae_re/normalize_dld.py` - DLD normalization with price metrics and YoY/MoM deltas
- `packages/uae-re/python/uae_re/normalize_ejari.py` - Ejari normalization with rental metrics and renewal rate
- `packages/uae-re/python/uae_re/normalize_permits.py` - Permits normalization with residential/commercial classification

## Decisions Made

1. **Shared CSV download strategy**: DLD and Ejari collectors both download the same Dubai Pulse CSV (dld_transactions-open) independently. This simplifies collector logic and ensures each collector has its own audit trail. Filtering by trans_group_en (Sales vs Rent) happens during Python normalization.

2. **Null handling for delta metrics**: YoY metrics return null/omit records until 12+ months of history exist for a given (area, property_type) combination. MoM metrics require 2+ months. This prevents false zeros in the database and clearly signals insufficient data rather than zero change.

3. **Building permits classification**: Uses multi-field keyword matching across permit_type, building_type, usage, and project_type fields. This robust approach handles variations in how Dubai Pulse categorizes permits and increases classification accuracy.

4. **Schema flexibility**: permits_schema uses strict=False to allow additional columns beyond the schema definition. This accommodates Dubai Pulse dataset variations without failing validation on extra fields.

5. **Renewal rate approximation**: Since the DLD CSV doesn't distinguish new vs renewal transactions, renewal_rate is estimated by comparing rental volume overlap between consecutive months (min(current, previous) / previous). This is an approximation until better data becomes available.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Ready for Plan 03 (ADREC Abu Dhabi, Bayut, PropertyFinder collectors, wave 2). All 3 CSV-based collectors (DLD, Ejari, building permits) complete and verified. These establish the simplest collection pattern (HTTP GET, no browser automation) and validate the end-to-end collection-to-normalization pipeline.

Wave 2 (Plans 02-03, parallel) in progress. Plan 02 complete.

---
*Phase: 07-mvp-collection*
*Completed: 2026-03-11*
