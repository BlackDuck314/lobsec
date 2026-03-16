---
phase: 10-statistical-analysis
plan: 02
subsystem: analytics
tags: [python, sqlite, pandas, numpy, granger, ewma, composite-index, affordability, expat-funnel, intelligence-cache]

# Dependency graph
requires:
  - phase: 10-01
    provides: "granger_results table with significant signals and weights, composite_scores/anomaly_flags/intelligence_cache/analysis_log tables in schema"

provides:
  - "analyze_composite.py: Granger-weighted composite index per-area (20 areas) + city-wide with tanh[-1,+1] scaling and strong_sell/neutral/strong_buy zones"
  - "analyze_anomalies.py: EWMA anomaly detection for DEWA closures, GDRFA visa cancellations, and Bayut/PropertyFinder listing volumes"
  - "analyze_affordability.py: salary-to-rent ratio model for 5 income brackets x 20 areas stored in intelligence_cache"
  - "analyze_expat_funnel.py: 10-stage lifecycle funnel (Awareness through Exit) with z-score aggregation, flow rates, trend indicators, and Telegram digest"

affects: [11-intelligence-products, 12-plugin-tools]

# Tech tracking
tech-stack:
  added: [pandas (EWMA via ewm()), numpy (tanh/zscore), math (tanh)]
  patterns:
    - "Bridge pattern: all 4 modules read JSON stdin, compute, write JSON stdout"
    - "intelligence_cache TTL: expires_at = next 25th of month at 02:00 UTC"
    - "EWMA anomaly detection: span=12, threshold=2 std devs, clear-then-insert pattern"
    - "Composite weighting: Granger 1/p-value weights, tanh(raw/2) saturation"
    - "Z-score per signal: last 12 months DESC, reverse to chronological, compute on full window"

key-files:
  created:
    - packages/uae-re/python/uae_re/analyze_composite.py
    - packages/uae-re/python/uae_re/analyze_anomalies.py
    - packages/uae-re/python/uae_re/analyze_affordability.py
    - packages/uae-re/python/uae_re/analyze_expat_funnel.py

key-decisions:
  - "Area-level vs city-wide signal split: bayut/propertyfinder/ejari contribute per-area; all other sources contribute city-wide (to both area and city composite)"
  - "Affordability rent normalization: ejari avg_rent_per_sqft * 750 sqft / 12 for monthly 1BR estimate (typical Dubai 1BR)"
  - "Flow rate denominator floor: abs(from_score) < 0.01 = undefined (None) to avoid division instability"
  - "Salary fallback: bracket midpoint used when salary data not yet available in normalized_monthly"
  - "Trend threshold: delta > 0.05 = up, < -0.05 = down, else flat (avoids noise from near-zero moves)"
  - "PropertFinder listing anomalies counted under bayut bucket in output (both are listing volume signals)"

patterns-established:
  - "intelligence_cache INSERT OR REPLACE pattern: cache_key='X_latest', params_hash for deduplication"
  - "Previous-month comparison: query intelligence_cache for prior run before computing current run"
  - "EWMA anomaly: DELETE existing flags for source before re-inserting (idempotent reruns)"
  - "Composite coverage reporting: component_count/total_components per area in composite_scores"

requirements-completed: [STAT-05, STAT-06, STAT-07, STAT-08, SEC-06, SEC-07]

# Metrics
duration: 4min
completed: 2026-03-16
---

# Phase 10 Plan 02: Statistical Analysis — Derived Models Summary

**Composite index (Granger-weighted tanh scaling), EWMA anomaly detection (span=12), affordability model (5 brackets x 20 areas), and expat lifecycle funnel (10 stages, flow rates, Telegram digest) — all writing via parameterized SQL to SQLite**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-16T11:11:43Z
- **Completed:** 2026-03-16T11:15:46Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Built composite index that reads significant Granger signals, z-score normalizes last 12 months, computes per-area and city-wide weighted averages with tanh(raw/2) saturation to [-1,+1], assigns strong_sell/neutral/strong_buy zones, and writes coverage-tracked results to composite_scores
- Built EWMA anomaly detector monitoring 4 signals (DEWA disconnections, GDRFA visa cancellations, Bayut listing_count, PropertyFinder listing_count) with span=12, threshold=2 std devs, idempotent clear-then-insert pattern
- Built affordability model computing salary-to-rent ratio for 5 income brackets across 20 Dubai areas using ejari avg_rent_per_sqft normalized to monthly 1BR (750 sqft), with unaffordable/stretched/comfortable classification and intelligence_cache storage
- Built 10-stage expat lifecycle funnel with signal mappings locked from CONTEXT.md, z-score stage aggregation, stage-to-stage flow rates, trend indicators vs previous month, and Telegram-friendly digest_text — all stored in intelligence_cache with TTL until next 25th

## Task Commits

Each task was committed atomically:

1. **Task 1: Build composite index and anomaly detection modules** - `94ee794` (feat)
2. **Task 2: Build affordability model and expat lifecycle funnel modules** - `18687d1` (feat)

## Files Created/Modified

- `packages/uae-re/python/uae_re/analyze_composite.py` - Granger-weighted composite index per-area + city-wide with tanh scaling and zone classification (302 lines)
- `packages/uae-re/python/uae_re/analyze_anomalies.py` - EWMA span=12 anomaly detection for 4 monitored signals, writes anomaly_flags table (213 lines)
- `packages/uae-re/python/uae_re/analyze_affordability.py` - Salary-to-rent ratio model, 5 brackets x 20 areas, intelligence_cache storage (339 lines)
- `packages/uae-re/python/uae_re/analyze_expat_funnel.py` - 10-stage lifecycle funnel, flow rates, trend indicators, Telegram digest, intelligence_cache storage (420 lines)

## Decisions Made

- **Area signal split**: bayut/propertyfinder/ejari = area-level signals (filtered by area_name in normalized_monthly); all other sources = city-wide signals. City-wide signals contribute to every area composite AND the standalone city-wide "dubai" composite.
- **Affordability rent normalization**: ejari avg_rent_per_sqft * 750 sqft / 12 months converts annual per-sqft rate to monthly 1BR cost. This is Claude's discretion from the plan — the plan specified using avg_rent_per_sqft but not the sqft conversion.
- **Salary fallback**: When median_salary_{bracket} not yet in normalized_monthly, the bracket midpoint is used as default. This allows affordability to produce useful output before salary data is collected.
- **Flow rate stability**: Denominator floor of 0.01 — if abs(from_stage_score) < 0.01, flow rate reported as None. Avoids nonsensical ratios near zero.
- **Trend sensitivity**: Threshold of ±0.05 z-score delta distinguishes meaningful movement from noise in monthly updates.
- **PropertFinder anomalies under bayut bucket**: Output structure has dewa/gdrfa/bayut keys; PropertyFinder listing anomalies are grouped under "bayut" since both are listing volume signals.

## Deviations from Plan

None — plan executed exactly as written. All 4 modules follow the bridge pattern, use parameterized SQL (SEC-06), log only metadata (SEC-07), and implement the specified algorithms (tanh scaling, EWMA span=12, 5 income brackets, 10-stage funnel with locked signal mappings).

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required. Modules require data in normalized_monthly table before producing non-trivial output, but they handle the empty case gracefully (fallback values, coverage reporting).

## Next Phase Readiness

- All 4 analysis modules ready for Phase 10 Plans 03-04 (scheduling + orchestration)
- intelligence_cache schema stable: affordability_latest and expat_funnel_latest cache keys established
- composite_scores table populated per-run (upsert semantics)
- Phase 11 (Intelligence Products) can read from intelligence_cache with confidence in schema

---
*Phase: 10-statistical-analysis*
*Completed: 2026-03-16*
