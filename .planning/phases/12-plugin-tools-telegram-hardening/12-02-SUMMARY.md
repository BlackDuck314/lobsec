---
phase: 12
plan: 02
subsystem: uae-re-plugin
tags: [tools, analytics, python, granger, correlation, staleness]
dependency_graph:
  requires: [12-01]
  provides: [TOOL-09, TOOL-10, TOOL-11, TOOL-12, TOOL-13, QUAL-02, QUAL-05]
  affects: [packages/uae-re/src/index.ts, packages/uae-re/src/analytics/]
tech_stack:
  added: [granger_ondemand.py, correlation_ondemand.py]
  patterns: [json-stdin-stdout bridge, fire-and-forget setImmediate, staleness detection]
key_files:
  created:
    - packages/uae-re/src/analytics/granger_ondemand.py
    - packages/uae-re/src/analytics/correlation_ondemand.py
  modified:
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/src/index.ts
decisions:
  - "detectGaps requires frequency arg — always pass info.metadata.frequency"
  - "13 total tools (not 14 as plan suggested) — existing uae_collection_status is one of the 5 operational, so 8+5=13"
  - "ADF stationarity test: difference once then retry — second diff if still non-stationary"
metrics:
  duration: "~15 minutes"
  completed: "2026-03-16"
  tasks_completed: 2
  files_modified: 4
---

# Phase 12 Plan 02: Operational & Analytical Tools Summary

5 operational/analytical tools registered via runPython bridge with on-demand Granger/correlation Python scripts and staleness-aware collection status.

## Tasks Completed

### Task 1: On-Demand Python Scripts and Type Update

Created `granger_ondemand.py` and `correlation_ondemand.py` — both accept JSON via stdin, return JSON via stdout, compatible with the `runPython()` bridge.

**granger_ondemand.py:**
- Parses `source|metric` for signal and target
- Opens SQLite DB read-only
- Aligns series on `measurement_date`, requires >= 24 observations
- ADF stationarity check with automatic differencing (1st then 2nd)
- Runs `grangercausalitytests(data, maxlag=max_lag)`, extracts SSR F-test p-values
- Reports best lag (minimum p-value), significance at 0.05 threshold
- Outputs formatted text + structured JSON

**correlation_ondemand.py:**
- Same data loading pattern as granger
- Requires >= 12 observations
- Computes `pearsonr(signal[:-lag], target[lag:])` for lag 0..max_lag
- Finds best lag by maximum absolute correlation
- Outputs formatted text + structured JSON

**types.ts:** Added `"granger_ondemand"` and `"correlation_ondemand"` to `PythonScriptName` union.

Commit: `0b7967e`

### Task 2: 5 Operational Tools Registered in index.ts

Added imports for `runPython`, `detectGaps`, and `path`. Registered 5 tools:

**TOOL-09: uae_raw_data**
- Validates source against registry, queries `raw_sources` table
- Defaults to last 12 months, formats as CSV with headers from first row keys
- Truncates to 4000 chars with continuation hint

**TOOL-10: uae_collection_status (enhanced)**
- Added `detectGaps(db, source, frequency)` for staleness detection
- Added normalized row count from `normalized_monthly`
- Added `nextScheduledRun(frequency)` helper for daily/weekly/monthly/quarterly schedules
- Formats `[STALE]` marker and `N days overdue` when gaps detected

**TOOL-11: uae_trigger_collection**
- Validates source if provided
- Uses `setImmediate()` for fire-and-forget (non-blocking)
- Catches and logs errors in background callback
- Returns immediately with status message

**TOOL-12: uae_granger_test**
- Validates `signal` and `target` contain `|`
- Calls `runPython("granger_ondemand", { signal, target, db_path, max_lag })`
- Returns formatted text output from Python script

**TOOL-13: uae_correlation**
- Same pattern as TOOL-12, calls `runPython("correlation_ondemand", ...)`
- Default max_lag: 12 months

Commit: `cf0f590`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] detectGaps requires 3 arguments**
- Found during: Task 2 TypeScript compilation
- Issue: Plan showed `detectGaps(db, source)` but actual signature requires `expectedFrequency` as third argument
- Fix: Pass `info.metadata.frequency` as third argument
- Files modified: packages/uae-re/src/index.ts
- Commit: cf0f590

**2. [Rule 1 - Bug] Array index access on possibly-undefined values**
- Found during: Task 2 TypeScript compilation
- Issue: TypeScript strict mode flags `gaps[0]` and `rows[0]` as possibly undefined
- Fix: Added undefined guards (`gaps[0] !== undefined`, early return for empty `rows`)
- Files modified: packages/uae-re/src/index.ts
- Commit: cf0f590

**3. Tool count: 13 not 14**
- Plan stated "14: 8 product + 5 operational + 1 existing status"
- Actual: uae_collection_status IS one of the 5 operational — enhanced, not added separately
- 8 product tools (from Plan 01) + 5 operational tools (this plan) = 13 total
- Plan's arithmetic was off by 1; action section is authoritative

## Self-Check

Verified:
- `packages/uae-re/src/analytics/granger_ondemand.py` — EXISTS, syntax valid
- `packages/uae-re/src/analytics/correlation_ondemand.py` — EXISTS, syntax valid
- `packages/uae-re/src/analytics/types.ts` — granger_ondemand and correlation_ondemand in union
- `packages/uae-re/src/index.ts` — 13 registerTool calls, tsc --noEmit clean
- Commit `0b7967e` — exists (Task 1)
- Commit `cf0f590` — exists (Task 2)

## Self-Check: PASSED
