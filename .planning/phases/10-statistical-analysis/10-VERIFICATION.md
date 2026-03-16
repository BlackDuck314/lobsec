---
phase: 10-statistical-analysis
verified: 2026-03-16T12:30:00Z
status: passed
score: 5/5 must-haves verified
re_verification: false
---

# Phase 10: Statistical Analysis Pipeline Verification Report

**Phase Goal:** Statistical Analysis Pipeline — Stationarity testing, Granger causality, correlations, composite indices, and derived models
**Verified:** 2026-03-16T12:30:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (from ROADMAP.md Success Criteria)

| #  | Truth                                                                                                                              | Status     | Evidence                                                                                                                          |
|----|------------------------------------------------------------------------------------------------------------------------------------|------------|-----------------------------------------------------------------------------------------------------------------------------------|
| 1  | ADF stationarity test runs on all normalized series with results logged to stationarity_results table; KPSS cross-check flags disagreements | VERIFIED | `analyze_stationarity.py` (194 lines) calls `test_stationarity()` (ADF+KPSS) on every `normalized_monthly` pair, writes to `stationarity_results` with `INSERT OR REPLACE`, logs to `analysis_log` |
| 2  | Granger causality tests all Tier A+B signals against DLD price/volume with Bonferroni correction; cross-correlation detects optimal lag (1-12 months) per validated signal | VERIFIED | `analyze_granger.py` (416 lines) builds test_pairs before loop, computes `bonferroni_alpha = 0.05 / n_total`, runs `grangercausalitytests` maxlag=12, then `compute_cross_correlation_lag()` via `scipy.stats.pearsonr` for best_lag |
| 3  | Composite index constructed from z-score normalized validated signals with Granger-derived weights scaled to [-1, +1]              | VERIFIED | `analyze_composite.py` reads `granger_results WHERE significant = 1`, z-score normalizes via `zscore_normalize()`, computes `tanh(raw/2)` saturation at line 186, writes per-area and city-wide to `composite_scores` |
| 4  | EWMA anomaly detection flags outliers for DEWA closures, visa cancellations, listing volume; affordability model computes salary-to-rent ratio by bracket and area; expat pipeline 10-stage funnel aggregates z-scores per stage | VERIFIED | `analyze_anomalies.py` span=12, threshold=2.0 for 4 monitored signals; `analyze_affordability.py` 5 brackets x areas with `unaffordable/stretched/comfortable` classification; `analyze_expat_funnel.py` STAGES locked from CONTEXT.md, all 10 stages confirmed at lines 35-44 |
| 5  | Pipeline timer (25th 06:00 GST) recomputes all analysis after monthly data lands; all queries use parameterized SQL; raw PII never logged | VERIFIED | `lobsec-uae-analyze.timer` active with `OnCalendar=*-*-25 02:00:00`; every DB query uses `?` placeholders; `analysis_log` stores only counts (signals_processed, signals_skipped, duration_ms) |

**Score:** 5/5 truths verified

---

### Required Artifacts

| Artifact | Plan | Expected | Exists | Lines | Status |
|---|---|---|---|---|---|
| `packages/uae-re/src/db/schema.ts` | 01 | 5 new tables (stationarity_results, granger_results, composite_scores, anomaly_flags, analysis_log) | Yes | 196 | VERIFIED |
| `packages/uae-re/python/uae_re/analyze_stationarity.py` | 01 | Batch ADF+KPSS with auto-differencing; min 80 lines | Yes | 194 | VERIFIED |
| `packages/uae-re/python/uae_re/analyze_granger.py` | 01 | Batch Granger with Bonferroni + cross-correlation; min 120 lines | Yes | 416 | VERIFIED |
| `packages/uae-re/src/analytics/types.ts` | 01 | PythonScriptName extended with 6 new names including `analyze_stationarity` | Yes | 81 | VERIFIED |
| `packages/uae-re/python/uae_re/analyze_composite.py` | 02 | Granger-weighted composite index; min 100 lines | Yes | 393 | VERIFIED |
| `packages/uae-re/python/uae_re/analyze_anomalies.py` | 02 | EWMA anomaly detection for 3 signal types; min 60 lines | Yes | 229 | VERIFIED |
| `packages/uae-re/python/uae_re/analyze_affordability.py` | 02 | Salary-to-rent ratio by bracket and area; min 80 lines | Yes | 341 | VERIFIED |
| `packages/uae-re/python/uae_re/analyze_expat_funnel.py` | 02 | 10-stage lifecycle funnel; min 120 lines | Yes | 431 | VERIFIED |
| `packages/uae-re/src/analytics/pipeline.ts` | 03 | Exports `runAnalysisPipeline`, `getNextAnalysisDate`; min 120 lines | Yes | 339 | VERIFIED |
| `packages/uae-re/src/analytics/digest.ts` | 03 | Exports `generateDigest`, `formatDigestMessage`; min 60 lines | Yes | 284 | VERIFIED |
| `packages/uae-re/src/cli.ts` | 03 | `analyze` subcommand present, calls `runAnalysisPipeline` | Yes | — | VERIFIED |
| `/opt/lobsec/bin/analyze.sh` | 04 | Pipeline orchestrator shell script; min 10 lines | Yes | 25 | VERIFIED |
| `/etc/systemd/system/lobsec-uae-analyze.timer` | 04 | Monthly timer, `OnCalendar=*-*-25 02:00:00` | Yes | 12 | VERIFIED |
| `/etc/systemd/system/lobsec-uae-analyze.service` | 04 | Oneshot service, `ExecStart=/opt/lobsec/bin/analyze.sh` | Yes | 19 | VERIFIED |

All 14 artifacts exist and are substantive. No stubs detected.

---

### Key Link Verification

**Plan 01 Key Links**

| From | To | Via | Status | Evidence |
|---|---|---|---|---|
| `analyze_granger.py` | `stationarity.py` | `from .stationarity import test_stationarity` | WIRED | Line 32: `from .stationarity import test_stationarity` — used in hard gate at line 277 |
| `analyze_stationarity.py` | `stationarity_results` table | `INSERT OR REPLACE INTO stationarity_results` with `?` params | WIRED | Line 80: `INSERT OR REPLACE INTO stationarity_results` confirmed |
| `analyze_granger.py` | `granger_results` table | `INSERT OR REPLACE INTO granger_results` with `?` params | WIRED | Line 330: `INSERT OR REPLACE INTO granger_results` confirmed |

**Plan 02 Key Links**

| From | To | Via | Status | Evidence |
|---|---|---|---|---|
| `analyze_composite.py` | `granger_results` table | reads significant signals and weights | WIRED | Lines 133-147: `SELECT ... FROM granger_results ... WHERE significant = 1` |
| `analyze_composite.py` | `composite_scores` table | writes per-area and city-wide scores | WIRED | Lines 262, 317: `INSERT OR REPLACE INTO composite_scores` |
| `analyze_expat_funnel.py` | `intelligence_cache` table | stores funnel results with TTL | WIRED | Line 368: `INSERT OR REPLACE INTO intelligence_cache` |
| `analyze_affordability.py` | `intelligence_cache` table | stores affordability results with TTL | WIRED | Line 285: `INSERT OR REPLACE INTO intelligence_cache` |

**Plan 03 Key Links**

| From | To | Via | Status | Evidence |
|---|---|---|---|---|
| `pipeline.ts` | `bridge.ts` | 6 `runPython()` calls with `analyze_*` script names | WIRED | Lines 254, 262, 269, 272, 275, 278: all 6 steps call `runStep()` which calls `runPython()` |
| `pipeline.ts` | `analysis_log` table | `INSERT INTO analysis_log` prepared statements | WIRED | Lines 157-171: 4 prepared statements (`insertLog`, `updateLogSuccess`, `updateLogFailed`, `insertSkipped`) |
| `cli.ts` | `pipeline.ts` | `analyze` subcommand calls `runAnalysisPipeline` | WIRED | `cli.ts` line 392 `case "analyze"`, line 334 calls `runAnalysisPipeline(db)` |
| `digest.ts` | `composite_scores` table | reads latest composite for digest summary | WIRED | Lines 93, 109: `SELECT ... FROM composite_scores` |

**Plan 04 Key Links**

| From | To | Via | Status | Evidence |
|---|---|---|---|---|
| `lobsec-uae-analyze.timer` | `lobsec-uae-analyze.service` | `Unit=lobsec-uae-analyze.service` | WIRED | Timer file line 8: `Unit=lobsec-uae-analyze.service` confirmed |
| `lobsec-uae-analyze.service` | `/opt/lobsec/bin/analyze.sh` | `ExecStart=...analyze.sh` | WIRED | Service file line 9: `ExecStart=/opt/lobsec/bin/analyze.sh` confirmed |
| `analyze.sh` | `cli.js analyze` | `node "$NODE_BIN" analyze` | WIRED | `analyze.sh` line 21: `node "$NODE_BIN" analyze 2>&1` confirmed |

All 13 key links verified as WIRED.

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|---|---|---|---|---|
| STAT-01 | 10-01 | Stationarity testing — ADF test on all normalized series, log to `stationarity_results` | SATISFIED | `analyze_stationarity.py` processes all `normalized_monthly` pairs, writes to `stationarity_results` |
| STAT-02 | 10-01 | KPSS cross-check alongside ADF, flag disagreements | SATISFIED | `test_stationarity()` returns both ADF and KPSS results; `analyze_stationarity.py` stores `kpss_statistic`, `kpss_pvalue`; `verdict` field captures disagreements (inconclusive) |
| STAT-03 | 10-01 | Granger causality — Tier A+B signals vs DLD price/volume, Bonferroni correction | SATISFIED | `analyze_granger.py` tests 16 Tier A+B sources against 2 DLD targets; `bonferroni_alpha = 0.05 / n_total` computed before test loop |
| STAT-04 | 10-01 | Cross-correlation lag detection (1-12 months) per validated signal | SATISFIED | `compute_cross_correlation_lag()` runs `pearsonr` for lags 1-12; `best_lag` stored in `granger_results` is the cross-correlation optimal lag |
| STAT-05 | 10-02 | Composite index — z-score normalized signals, Granger-derived weights, [-1, +1] | SATISFIED | `analyze_composite.py` z-score normalizes via `zscore_normalize()`, weights = `granger_results.weight` (= 1/pvalue), `math.tanh(raw/2)` scales to [-1, +1] |
| STAT-06 | 10-02 | EWMA anomaly detection for DEWA closures, visa cancellations, listing volume | SATISFIED | `analyze_anomalies.py` monitors 4 signals (dewa/disconnections, gdrfa/visa_cancellations, bayut/listing_count, propertyfinder/listing_count); `ewm(span=12, adjust=False)` |
| STAT-07 | 10-02 | Affordability model — salary-to-rent ratio by income bracket and area | SATISFIED | `analyze_affordability.py` defines 5 `INCOME_BRACKETS`; computes ratio per (bracket, area); writes to `intelligence_cache` |
| STAT-08 | 10-02 | Expat pipeline 10-stage funnel, z-score aggregation per stage | SATISFIED | `analyze_expat_funnel.py` `STAGES` list has all 10 stages matching CONTEXT.md; z-score per stage, flow rates, trend indicators, Telegram digest |
| SCHED-06 | 10-04 | Pipeline timer (25th 06:00 GST) — recompute all analysis after monthly data | SATISFIED | `lobsec-uae-analyze.timer` active; `OnCalendar=*-*-25 02:00:00` (02:00 UTC = 06:00 GST); `Persistent=true`; next run confirmed 2026-03-25 |
| SEC-06 | 10-01/02/03 | SQL injection prevention — parameterized queries for all user-supplied area names | SATISFIED | All Python modules use `?` placeholders throughout; `pipeline.ts` uses `db.prepare()` prepared statements; TypeScript compiles clean |
| SEC-07 | 10-01/02/03 | PII protection — log only metadata (row count, status), never raw visa/employment data | SATISFIED | All `analysis_log` inserts log only `signals_processed`, `signals_skipped`, `duration_ms`; error sanitizer in `pipeline.ts` strips 4-digit+ numeric sequences (line 82); `analyze_composite.py` analysis_log logs area count only |

**All 11 requirements SATISFIED.** No orphaned requirements detected.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `analyze_stationarity.py` | 176 | `pass` in `except Exception` | Info | Legitimate: failure to write the failure-log itself is silently swallowed to avoid masking the original error. Not a stub. |
| `analyze_anomalies.py` | 69 | `return []` | Info | Legitimate: returns empty list when signal has insufficient observations (< MIN_OBSERVATIONS). Guard clause, not a stub. |
| `analyze_granger.py` | 397 | `pass` in nested `except` | Info | Same pattern: outer exception handler writing to analysis_log; inner `except Exception: pass` prevents double-fault. Not a stub. |

No blockers or warnings. All `pass` statements are in nested exception handlers protecting the error-logging path — a sound defensive pattern. The `return []` is an explicit "insufficient data" guard, not a stub.

TypeScript compilation: CLEAN (no errors).

---

### Human Verification Required

None required. All critical behaviors were verified programmatically:

- Timer active and scheduled (confirmed via `systemctl list-timers`)
- 5 new SQLite tables confirmed present in production database
- 26 `analysis_log` entries confirmed from end-to-end pipeline execution (all 6 steps succeeded with graceful skip on insufficient data, which is expected behavior at this early stage of collection)
- All key wiring confirmed via code inspection
- Commit hashes for all 7 feature commits verified in git history

---

### Gaps Summary

No gaps found. All 5 success criteria, 11 requirements, and 13 key links verified.

One noteworthy operational fact: the affordability step showed `failed` in the first 2 pipeline runs (before the `area_name` column bug fix), then `success` in subsequent runs. The fix was applied in commit `f78bbb0` (Plan 04 Task 1). The most recent pipeline run shows all 6 steps succeeding, confirming the bug was resolved.

---

## Production Deployment Confirmation

| Check | Status | Detail |
|---|---|---|
| Timer active | CONFIRMED | `systemctl is-active lobsec-uae-analyze.timer` returns `active` |
| Next run | 2026-03-25 02:00 UTC | Confirmed via `systemctl list-timers` |
| Python modules deployed | CONFIRMED | 6 `analyze_*.py` files at `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/`, owned `lobsec:lobsec` |
| 5 new DB tables | CONFIRMED | `sqlite3 .tables` shows `stationarity_results`, `granger_results`, `composite_scores`, `anomaly_flags`, `analysis_log` |
| Pipeline end-to-end | CONFIRMED | 26 `analysis_log` rows; most recent full run shows all steps `success` |

---

_Verified: 2026-03-16T12:30:00Z_
_Verifier: Claude (gsd-verifier)_
