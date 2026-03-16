---
phase: 11-intelligence-products
plan: 01
subsystem: analytics
tags: [python, statsmodels, sqlite, granger, validation, out-of-sample, composite-index, telegram]

# Dependency graph
requires:
  - phase: 10-statistical-analysis
    provides: Granger results in granger_results table, 6 Python analysis modules, pipeline.ts

provides:
  - Out-of-sample Granger validation (validation_results table + analyze_validation.py)
  - Composite index downweighting via LEFT JOIN on validation_results
  - Shared Telegram formatting utilities (products/format.ts)
  - Pipeline runs 7 steps (added validation between granger and composite)

affects:
  - 11-intelligence-products (Plans 02-04 all use format.ts, rely on composite downweighting)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Chronological 70/30 train/test split for time-series out-of-sample validation"
    - "LEFT JOIN with COALESCE(downweight_factor, 1.0) for backward-compatible weight adjustment"
    - "Shared formatting module pattern for product formatters"

key-files:
  created:
    - packages/uae-re/python/uae_re/analyze_validation.py
    - packages/uae-re/src/products/format.ts
  modified:
    - packages/uae-re/src/db/schema.ts
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/src/analytics/pipeline.ts
    - packages/uae-re/python/uae_re/analyze_composite.py

key-decisions:
  - "Chronological 70/30 split only — no random splitting, no sklearn. Series[:train_n] and series[train_n:]."
  - "COALESCE(downweight_factor, 1.0) in composite ensures backward compatibility before validation has run"
  - "Signals with < 12 observations or insufficient split size are skipped (validated=1, factor=1.0) — not penalized"
  - "QUAL-03 fulfilled by verification: only ffill in normalize.py:38 already has limit=1; no unbounded ffill found"
  - "Validation subquery uses string concatenation as row key workaround for SQLite's lack of tuple IN syntax"

patterns-established:
  - "Out-of-sample validation: run Granger on train subset at same best_lag, check significance at same bonferroni_alpha"
  - "Pipeline step numbering: Step 2.5 inserted between existing steps without renumbering downstream steps"

requirements-completed: [QUAL-01, QUAL-03]

# Metrics
duration: 5min
completed: 2026-03-16
---

# Phase 11 Plan 01: Validation & Format Utilities Summary

**Out-of-sample Granger validation with chronological 70/30 split, composite downweighting via LEFT JOIN, and 5 shared Telegram formatting utilities**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-16T14:02:05Z
- **Completed:** 2026-03-16T14:07:00Z
- **Tasks:** 3
- **Files modified:** 6 (4 modified, 2 created)

## Accomplishments

- QUAL-01: validation_results table (Table 11), analyze_validation.py with chronological 70/30 split, pipeline integration as Step 2.5 after granger
- QUAL-01: Composite index now LEFT JOINs validation_results to apply downweight_factor=0.5 for signals that fail out-of-sample test
- QUAL-03: Audited all 28 normalize_*.py files — only ffill is in normalize.py:38 with limit=1; no unbounded forward-fill exists anywhere
- Format utilities: truncate4K, freshnessFooter, stalenessWarning, trendArrow, zoneLabel — shared foundation for all 8 intelligence products in Plans 02-04

## Task Commits

Each task was committed atomically:

1. **Task 1: validation_results table, analyze_validation.py, pipeline integration** - `3cfb8eb` (feat)
2. **Task 2: composite downweighting, ffill audit** - `2f2537b` (feat)
3. **Task 3: shared format.ts utilities** - `56f75cd` (feat)

**Plan metadata:** `c0fed83` (docs: complete plan)

## Files Created/Modified

- `packages/uae-re/python/uae_re/analyze_validation.py` - Out-of-sample Granger validation; chronological 70/30 split; writes to validation_results
- `packages/uae-re/src/products/format.ts` - Shared Telegram formatting utilities for all 8 products
- `packages/uae-re/src/db/schema.ts` - Added Table 11 validation_results with downweight_factor column and idx_validation_signal index
- `packages/uae-re/src/analytics/types.ts` - Added "analyze_validation" to PythonScriptName union
- `packages/uae-re/src/analytics/pipeline.ts` - Inserted Step 2.5 (validation) between granger and composite
- `packages/uae-re/python/uae_re/analyze_composite.py` - fetch_significant_signals() LEFT JOINs validation_results for downweighting

## Decisions Made

- Chronological split only: `series[:train_n]` and `series[train_n:]` with no random or sklearn-based splitting. Monthly time-series data is not IID — shuffling would introduce look-ahead bias.
- `COALESCE(downweight_factor, 1.0)` in composite query: ensures composite behavior is unchanged on first run when validation_results is empty. Critical for backward compatibility.
- Signals with < 12 total observations are skipped (not penalized): set validated=1 and downweight_factor=1.0. Insufficient history makes out-of-sample testing meaningless.
- QUAL-03 fulfilled by verification: research confirmed normalize.py has `ffill(limit=1)` and no other normalizer uses ffill at all. Zero code changes required.
- SQLite row key workaround: used string concatenation `signal_source || '|' || signal_metric || '|' || target` in the validation_results subquery because SQLite doesn't support tuple/row constructors in IN clauses.

## Deviations from Plan

None - plan executed exactly as written.

The plan's SQL for the validation_results subquery used a multi-column IN syntax (`WHERE (signal_source, signal_metric, target, tested_at) IN (...)`) that SQLite does not support. This was replaced with the string concatenation workaround while preserving the same logical result. This is a correctness fix, not a deviation.

## Issues Encountered

None. The SQL multi-column IN clause was rewritten to use SQLite-compatible string key concatenation.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- QUAL-01 and QUAL-03 complete: validation foundation and ffill compliance verified
- Pipeline now runs 7 steps: stationarity → granger → validation → composite → anomalies → affordability → expat_funnel
- format.ts available for all 8 intelligence products (Plans 02-04)
- Ready for Plan 11-02: first intelligence product implementations

---
*Phase: 11-intelligence-products*
*Completed: 2026-03-16*

## Self-Check: PASSED

Files verified:
- FOUND: packages/uae-re/python/uae_re/analyze_validation.py
- FOUND: packages/uae-re/src/products/format.ts
- FOUND: .planning/phases/11-intelligence-products/11-01-SUMMARY.md

Commits verified:
- FOUND: 3cfb8eb (Task 1: validation table, module, pipeline)
- FOUND: 2f2537b (Task 2: composite downweighting, ffill audit)
- FOUND: 56f75cd (Task 3: format.ts utilities)
- FOUND: c0fed83 (Plan metadata)
