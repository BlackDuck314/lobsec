---
phase: 07-mvp-collection
plan: 01
subsystem: database
tags: [sqlite, area-mapping, normalization, pandera, data-quality]

# Dependency graph
requires:
  - phase: 06-foundation-infrastructure
    provides: Database schema, collector framework, Python analytics bridge
provides:
  - Area name mapping table with ~150 canonical UAE areas
  - Normalization orchestrator with upsert semantics
  - Gap detection and volume validation
  - pandera schemas package for raw data validation
affects: [07-02, 07-03, 07-04, 08-tier-b-collection, 09-tier-c-collection]

# Tech tracking
tech-stack:
  added: [pandera 0.20.4, beautifulsoup4 4.12.3]
  patterns: [area name canonicalization, normalization upsert semantics, gap detection, volume validation]

key-files:
  created:
    - packages/uae-re/src/areas/seed-areas.ts
    - packages/uae-re/src/areas/mapping.ts
    - packages/uae-re/src/normalization/types.ts
    - packages/uae-re/src/normalization/orchestrator.ts
    - packages/uae-re/src/normalization/gap-detection.ts
    - packages/uae-re/src/normalization/volume-validation.ts
    - packages/uae-re/python/uae_re/schemas/__init__.py
  modified:
    - packages/uae-re/src/db/schema.ts
    - packages/uae-re/src/db/queries.ts
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/src/index.ts
    - packages/uae-re/python/requirements.txt

key-decisions:
  - "Area lookup uses case-insensitive exact match against canonical names, aliases, and source variants (no fuzzy matching until QUAL-04)"
  - "Normalization upsert deletes existing data in measurement_date range before inserting normalized records"
  - "Gap detection flags STALE when gap exceeds 2x expected frequency"
  - "Volume validation requires 4 successful collections as baseline before alerting"
  - "schemas/__init__.py created in wave 1 to prevent merge conflicts in parallel Plans 02-03"

patterns-established:
  - "Area name canonicalization pattern: seed data with aliases and source variants in JSON columns"
  - "Normalization orchestrator pattern: Python bridge call → upsert transaction → gap/volume validation"
  - "Validation baseline pattern: rolling window of N past collections for anomaly detection"

requirements-completed: [NORM-01, NORM-02, NORM-03, NORM-04, NORM-05]

# Metrics
duration: 32min
completed: 2026-03-11
---

# Phase 7 Plan 01: Normalization Pipeline Foundation Summary

**Area name mapping table with ~150 canonical UAE areas, normalization orchestrator with upsert semantics, gap detection, volume validation, and pandera validation infrastructure**

## Performance

- **Duration:** 32 min
- **Started:** 2026-03-11T22:15:00Z
- **Completed:** 2026-03-11T22:47:00Z
- **Tasks:** 2
- **Files modified:** 12

## Accomplishments

- Area name mapping infrastructure with 150+ canonical areas (100 Dubai + 50 Abu Dhabi) with aliases and source variants
- Normalization orchestrator auto-triggers after collection, calls per-source Python modules, and upserts to normalized_monthly
- Gap detection flags sources as STALE when collection gap exceeds 2x expected frequency
- Volume validation compares current row count to rolling 4-collection baseline, warns when <50%
- pandera and beautifulsoup4 installed in analytics venv for data validation and web scraping
- Python schemas package created as wave 1 prerequisite for parallel Plans 02-03

## Task Commits

Each task was committed atomically:

1. **Task 1: Create area name mapping table and seed data** - `96f4ae1` (feat)
2. **Task 2: Build normalization orchestrator, gap detection, and volume validation** - `762a09e` (feat)

## Files Created/Modified

Created:
- `packages/uae-re/src/areas/seed-areas.ts` - 150+ area seeds with canonical names, aliases, source variants
- `packages/uae-re/src/areas/mapping.ts` - Area lookup and canonicalization functions
- `packages/uae-re/src/normalization/types.ts` - Normalization pipeline type definitions
- `packages/uae-re/src/normalization/orchestrator.ts` - Auto-trigger orchestrator with upsert semantics
- `packages/uae-re/src/normalization/gap-detection.ts` - STALE source detection when gap > 2x frequency
- `packages/uae-re/src/normalization/volume-validation.ts` - Rolling baseline volume anomaly detection
- `packages/uae-re/python/uae_re/schemas/__init__.py` - pandera validation package stub

Modified:
- `packages/uae-re/src/db/schema.ts` - Added area_names table with canonical names and JSON columns
- `packages/uae-re/src/db/queries.ts` - Added area queries and deleteNormalizedRange for upsert
- `packages/uae-re/src/analytics/types.ts` - Expanded PythonScriptName with 7 normalize_* modules
- `packages/uae-re/src/index.ts` - Exported area mapping and normalization modules
- `packages/uae-re/python/requirements.txt` - Added pandera 0.20.4 and beautifulsoup4 4.12.3

## Decisions Made

1. **Area lookup strategy**: Case-insensitive exact match against canonical names, aliases, and source variants. No fuzzy matching at this stage (deferred to QUAL-04 in Phase 12). This keeps normalization deterministic and fast.

2. **Normalization upsert semantics**: DELETE existing records for measurement_date range, then INSERT normalized records. This allows re-running normalization without duplicates and supports late-arriving corrections.

3. **Gap detection threshold**: 2x expected frequency (daily=2d, weekly=14d, monthly=60d, quarterly=180d). This tolerates occasional delays while catching persistent staleness.

4. **Volume validation baseline**: Requires 4 successful collections before alerting. Warns when current row count <50% of rolling average. N=4 balances sensitivity with false positive reduction.

5. **schemas package created early**: Python schemas/__init__.py created in Plan 01 (wave 1) so Plans 02 and 03 (wave 2, parallel) can both add schema files without merge conflicts on package initialization.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Ready for Plan 02 (DLD + Ejari collectors, wave 2). Area mapping and normalization infrastructure complete. All 7 collectors in Plans 02-04 will use this foundation.

Wave 1 foundation complete. Wave 2 (Plans 02-03, parallel) can proceed.

---
*Phase: 07-mvp-collection*
*Completed: 2026-03-11*
