---
phase: 11-intelligence-products
plan: 02
subsystem: analytics
tags: [typescript, sqlite, intelligence-products, distress-detection, composite-signal, telegram]

# Dependency graph
requires:
  - phase: 11-intelligence-products
    plan: 01
    provides: format.ts shared utilities (truncate4K, freshnessFooter, trendArrow, zoneLabel)
  - phase: 10-statistical-analysis
    provides: composite_scores, granger_results, normalized_monthly, intelligence_cache tables

provides:
  - PROD-01: Area Buy/Sell Signal Score (queryAreaSignal, AreaSignalResult)
  - PROD-02: Distress Detection System (queryDistress, DistressResult)

affects:
  - 12-plugin-tools-hardening (Phase 12 tools will import queryAreaSignal and queryDistress)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Granger-derived 1/p-value weighting with equal-weight fallback"
    - "tanh(weighted_avg_z / 2) composite distress scaling"
    - "SEC-06 parameterized area validation gate on every query function"

key-files:
  created:
    - packages/uae-re/src/products/prod01-area-signal.ts
    - packages/uae-re/src/products/prod02-distress.ts
  modified: []

key-decisions:
  - "Area validation uses LOWER(canonical_name) = LOWER(?) for case-insensitive matching"
  - "PROD-01 trend computed from LIMIT 2 composite_scores rows, compared current vs previous"
  - "PROD-02 distress z-scores inverted where raw signal direction is inverse (price YoY, lifecycle z)"
  - "PROD-02 alert threshold >= 0.6 at area level ONLY — locked decision, no city-wide threshold"
  - "Granger weight lookup uses any significant signal (significant=1) not only area-specific targets"
  - "listing-to-transaction ratio derived inline via LEFT JOIN at query time (not precomputed)"

requirements-completed: [PROD-01, PROD-02]

# Metrics
duration: 4min
completed: 2026-03-16
---

# Phase 11 Plan 02: Area Signal (PROD-01) and Distress Detection (PROD-02) Summary

**PROD-01 queries composite_scores for area buy/sell signal with trend and top components; PROD-02 computes 17-signal distress score using Granger-derived weights with tanh scaling and 0.6 alert threshold**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-16T14:11:00Z
- **Completed:** 2026-03-16T14:14:19Z
- **Tasks:** 2
- **Files modified:** 2 created

## Accomplishments

- PROD-01: `queryAreaSignal(db, area)` queries `composite_scores WHERE area = ?`, parses `components_json`, sorts top 5 by abs(zscore), computes trend arrow vs prior period, formats Telegram message with header/score/zone/coverage/signals/freshness footer. Returns `AreaSignalResult | null`.
- PROD-02: `queryDistress(db, area)` computes 8 market signals from `normalized_monthly` (price YoY, DOM, price reductions, permit withdrawals, DEWA disconnections, F&B closures, mortgage rate, listing-to-transaction ratio) and 9 lifecycle signals from `intelligence_cache expat_funnel_latest`. Applies Granger-derived `1/pvalue` weights where available (equal weight otherwise). Score = `tanh(weighted_avg / 2)`, clamped positive. Zone: normal/elevated/critical. Alert at >= 0.6 area level only. Returns `DistressResult | null`.
- Both products: SEC-06 area validation gate (parameterized SQL on `area_names`), null returned gracefully when area not found or data absent, `truncate4K()` applied, `freshnessFooter()` in output.

## Task Commits

Each task was committed atomically:

1. **Task 1: PROD-01 area signal module** - `9f1f91a` (feat)
2. **Task 2: PROD-02 distress detection module** - `525e724` (feat)

## Files Created/Modified

- `packages/uae-re/src/products/prod01-area-signal.ts` - PROD-01: queryAreaSignal, AreaSignalResult, AreaSignalComponent interfaces
- `packages/uae-re/src/products/prod02-distress.ts` - PROD-02: queryDistress, DistressResult, MarketSignal, LifecycleSignal interfaces

## Decisions Made

- Area validation uses case-insensitive match (`LOWER(canonical_name) = LOWER(?)`) to handle user input without enforcing exact case.
- PROD-01 trend uses `LIMIT 2` query on `composite_scores` sorted by `computed_at DESC`, comparing `rows[0].score` vs `rows[1].score`.
- PROD-02 distress z-scores inverted where raw signal direction is "inverse" to distress: price YoY decline means positive distress, so `dldPriceDistressZ = -z`. Lifecycle negative z-scores indicate deterioration, so lifecycle contribution uses `-ls.zscore`.
- Alert threshold `>= 0.6` applied only after clamping score to `[0, +1]` range. Locked design: area level only, no city-wide threshold.
- Granger weight lookup queries `granger_results WHERE signal_source = ? AND signal_metric = ? AND significant = 1`. Falls back to weight `1.0` when absent.
- Listing-to-transaction ratio is derived inline via `LEFT JOIN` between `normalized_monthly bayut listing_count` and `dld-sales transaction_count` rows at matching `measurement_date`. Rolling 12-month z-score computed in TypeScript.

## Deviations from Plan

None - plan executed exactly as written.

The plan specified area-key metric lookups using LIKE pattern `%{area}%|metric_name`. Implemented using `areaKey = canonicalArea.toLowerCase().replace(/\s+/g, '_')` as pattern prefix for consistency with how the Python normalizers write metric names.

## Issues Encountered

TypeScript strict mode required `rows[0]` guard to be an explicit `if (!current)` check rather than `rows.length === 0` due to array index access typing. Fixed inline (Rule 1 auto-fix, trivial).

## User Setup Required

None - products are query-only modules. No external service configuration required.

## Next Phase Readiness

- PROD-01 and PROD-02 complete: core signal and risk management products available
- Both export typed interfaces for Phase 12 tool integration
- PROD-03 through PROD-08 follow same pattern (query + format wrapper)
- Ready for Plan 11-03: additional intelligence product implementations

---
*Phase: 11-intelligence-products*
*Completed: 2026-03-16*

## Self-Check: PASSED

Files verified:
- FOUND: packages/uae-re/src/products/prod01-area-signal.ts
- FOUND: packages/uae-re/src/products/prod02-distress.ts
- FOUND: .planning/phases/11-intelligence-products/11-02-SUMMARY.md

Commits verified:
- FOUND: 9f1f91a (Task 1: PROD-01 area signal)
- FOUND: 525e724 (Task 2: PROD-02 distress detection)
