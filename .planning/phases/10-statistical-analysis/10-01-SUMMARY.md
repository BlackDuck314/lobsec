---
phase: 10-statistical-analysis
plan: 01
subsystem: database
tags: [sqlite, statsmodels, scipy, python, stationarity, granger, adf, kpss, bonferroni]

# Dependency graph
requires:
  - phase: 06-foundation-infrastructure
    provides: SQLite schema (normalized_monthly, initSchema), Python analytics venv, bridge pattern
  - phase: 09-tier-c-collection
    provides: Tier A+B+C collectors writing to normalized_monthly
provides:
  - 5 new SQLite analysis tables (stationarity_results, granger_results, composite_scores, anomaly_flags, analysis_log)
  - analyze_stationarity.py — batch ADF+KPSS testing with auto-differencing, direct DB write
  - analyze_granger.py — batch Granger causality with Bonferroni correction, cross-correlation, direct DB write
  - PythonScriptName extended with 6 new batch analysis module names
affects:
  - 10-02 (composite index uses granger_results weights)
  - 10-03 (orchestrator calls analyze_stationarity and analyze_granger)
  - 11-intelligence-products (reads granger_results, composite_scores for query responses)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Batch analysis modules write directly to SQLite (not via stdout) — stdout carries summary only
    - Bonferroni N computed from total test pairs BEFORE test loop (not per-signal maxlag)
    - Stationarity hard gate: non-stationary series auto-differenced and retested before Granger
    - Cross-correlation lag (1-12m) via scipy.stats.pearsonr stored as best_lag in granger_results
    - Analysis log entries contain only metadata counts (signals_processed, signals_skipped) — never raw data values (SEC-07)
    - All DB writes use parameterized ? placeholders throughout (SEC-06)

key-files:
  created:
    - packages/uae-re/python/uae_re/analyze_stationarity.py
    - packages/uae-re/python/uae_re/analyze_granger.py
  modified:
    - packages/uae-re/src/db/schema.ts
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/python/uae_re/__init__.py

key-decisions:
  - "Batch analysis modules write directly to SQLite (sqlite3 stdlib) — bridge stdout carries summary JSON only, not full result sets"
  - "Cross-correlation lag used as best_lag in granger_results (overrides Granger best lag) — more interpretable for downstream composite weighting"
  - "Tier A+B sources: ejari, permits, adrec, bayut, propertyfinder, dewa (A) + mohre, dxb, gdrfa, khda, rta, jobs, salary, remittances (B) — DLD source excluded (it IS the target)"

patterns-established:
  - "Direct DB write pattern: heavy analysis writes to SQLite directly, bridge returns summary count not full data"
  - "Bonferroni scope: N = total (signal, target) pairs before loop — prevents multiple testing inflation"
  - "Auto-differencing gate: non-stationary → first-difference → retest → skip if still non-stationary"

requirements-completed: [STAT-01, STAT-02, STAT-03, STAT-04, SEC-06, SEC-07]

# Metrics
duration: 4min
completed: 2026-03-16
---

# Phase 10 Plan 01: Statistical Analysis Schema and Batch Analysis Modules Summary

**SQLite schema extended to 10 tables, analyze_stationarity.py and analyze_granger.py implement batch ADF+KPSS with auto-differencing and Bonferroni-corrected Granger causality with cross-correlation lag detection, all with direct DB writes and parameterized SQL**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-16T11:04:51Z
- **Completed:** 2026-03-16T11:08:47Z
- **Tasks:** 2/2
- **Files modified:** 5

## Accomplishments
- 5 new SQLite tables added to initSchema(): stationarity_results, granger_results, composite_scores, anomaly_flags, analysis_log — each with correct columns, CHECK constraints, and indices
- analyze_stationarity.py batch-tests all normalized_monthly series via ADF+KPSS (test_stationarity from stationarity.py), auto-differences non-stationary series and retests, skips series with < 12 observations gracefully
- analyze_granger.py tests all Tier A+B signals against dld_price and dld_volume with Bonferroni correction (N = total test pairs), includes cross-correlation lag detection via scipy.stats.pearsonr, computes weight = 1/pvalue for significant signals
- Both modules write directly to SQLite (not via bridge stdout), use parameterized SQL throughout (SEC-06), and log only metadata counts to analysis_log (SEC-07)
- PythonScriptName union extended with 6 new batch analysis module names: analyze_stationarity, analyze_granger, analyze_composite, analyze_anomalies, analyze_affordability, analyze_expat_funnel

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend database schema with 5 analysis tables and update PythonScriptName** - `f86ab86` (feat)
2. **Task 2: Build batch stationarity and Granger Python modules** - `f9d0c79` (feat)

## Files Created/Modified
- `packages/uae-re/src/db/schema.ts` - Added 5 new tables (6-10), updated JSDoc to say "Creates 10 tables"
- `packages/uae-re/src/analytics/types.ts` - Extended PythonScriptName with 6 batch analysis module names
- `packages/uae-re/python/uae_re/analyze_stationarity.py` - New: batch stationarity with auto-differencing and DB write (96 lines)
- `packages/uae-re/python/uae_re/analyze_granger.py` - New: batch Granger with Bonferroni, cross-correlation, DB write (288 lines)
- `packages/uae-re/python/uae_re/__init__.py` - Updated docstring to mention 6 new analysis modules

## Decisions Made
- **Direct DB write pattern**: analyze_stationarity.py and analyze_granger.py use sqlite3 stdlib to write results directly to the database. The bridge stdout carries only a summary (processed/skipped counts). This avoids passing large result sets through the JSON bridge channel.
- **Cross-correlation lag as best_lag**: For Granger-tested signals, best_lag stored in granger_results is the cross-correlation optimal lag (highest absolute Pearson correlation at lags 1-12), not the Granger test best lag. This is more interpretable for downstream composite index weighting.
- **Bonferroni N scope**: N = total (signal, target) pairs (len(test_pairs)) computed before the test loop — correct Bonferroni multiple testing correction. The existing granger.py used N = maxlag (incorrect for batch mode).

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Python import test initially failed because uae_re is not installed as a package in the venv — must run from `/root/lobsec/packages/uae-re/python/` (same pattern as all other bridge modules). This is expected behavior, not a defect.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- stationarity_results and granger_results tables are ready to receive data from the analysis pipeline
- analyze_stationarity.py and analyze_granger.py accept `{"db_path": "/opt/lobsec/data/uae-re.db"}` via stdin
- Plan 02 (composite index + anomaly detection) can read from granger_results for Granger-derived weights
- Plan 03 (orchestrator + systemd timer) will call these modules with extended timeout (5 minutes)

---
*Phase: 10-statistical-analysis*
*Completed: 2026-03-16*
