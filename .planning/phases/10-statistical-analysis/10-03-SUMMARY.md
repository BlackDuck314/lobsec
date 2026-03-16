---
phase: 10-statistical-analysis
plan: 03
subsystem: analytics
tags: [typescript, pipeline, orchestrator, digest, telegram, sqlite, granger, anomaly]

# Dependency graph
requires:
  - phase: 10-01
    provides: analyze_stationarity.py, analyze_granger.py, analysis_log table, granger_results table
  - phase: 10-02
    provides: analyze_composite.py, analyze_anomalies.py, analyze_affordability.py, analyze_expat_funnel.py (called by pipeline)
provides:
  - TypeScript pipeline orchestrator (runAnalysisPipeline, getNextAnalysisDate)
  - Telegram monthly digest formatter (generateDigest, formatDigestMessage)
  - CLI 'analyze' subcommand
affects:
  - 10-04 (analyze.sh systemd timer calls `node cli.js analyze`)
  - 11-intelligence-products (pipeline populates composite_scores, anomaly_flags used for queries)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Pipeline orchestrator uses inner runStep() helper — single runPython call site, 6 step invocations
    - Analysis log records 'in_progress' on step start, then updates to 'success'/'failed' on completion
    - Error sanitization strips numeric sequences >= 4 digits before storage (SEC-07)
    - Cache TTL batch-updated after pipeline completes (not per step)
    - Telegram dispatch gated on >= 3 Granger-validated signals from last 24h
    - Digest message truncated to 3990+[truncated] when over 4000 chars (Telegram limit)

key-files:
  created:
    - packages/uae-re/src/analytics/pipeline.ts
    - packages/uae-re/src/analytics/digest.ts
  modified:
    - packages/uae-re/src/cli.ts

key-decisions:
  - "runStep() helper centralizes runPython call, analysis_log writes, and error handling — called 6 times for 6 pipeline steps"
  - "Digest gated on >= 3 Granger signals from last 24h — ensures digest only sent after a fresh pipeline run with validated signals"
  - "Digest insert to analysis_log on skip — audit trail shows why digest was not sent"

# Metrics
duration: 3min
completed: 2026-03-16
---

# Phase 10 Plan 03: Pipeline Orchestrator, Digest Formatter, CLI Entry Point Summary

**TypeScript pipeline orchestrator sequences 6 Python analysis modules with dependency-aware error handling, 5-minute timeout, analysis_log audit trail, and conditional Telegram digest dispatch**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-16T11:12:30Z
- **Completed:** 2026-03-16T11:15:35Z
- **Tasks:** 2/2
- **Files modified:** 3

## Accomplishments

- pipeline.ts exports `runAnalysisPipeline(db)` that runs 6 Python modules: stationarity → granger → composite (serial chain), anomalies/affordability/expat_funnel (parallel-independent, run always)
- Dependency gates enforced: Granger skipped if stationarity fails; composite skipped if Granger fails or skipped
- `getNextAnalysisDate()` returns next 25th at 02:00 UTC with correct month rollover via Date.UTC arithmetic
- Each step logged to analysis_log via 6 prepared statements (SEC-06): insertLog (in_progress), updateLogSuccess, updateLogFailed, insertSkipped — no raw data values stored (SEC-07)
- Error sanitizer strips numeric sequences >= 4 digits before storage (SEC-07)
- 5-minute timeout (300_000ms) passed to every runPython call via BATCH_TIMEOUT_MS constant
- Cache TTL batch-updated after all steps complete, expires_at = next analysis date
- Telegram digest dispatched if >= 3 significant Granger signals from last 24h; skip logged to analysis_log with reason
- digest.ts exports `generateDigest(db)` reading composite_scores, granger_results, anomaly_flags, intelligence_cache
- `formatDigestMessage(data)` produces magazine-style Telegram message, enforces 4000 char hard limit
- cli.ts extended with `analyze` subcommand that calls runAnalysisPipeline, emits JSON result to stdout, exits 1 on failure, handles SIGTERM

## Task Commits

Each task was committed atomically:

1. **Task 1: Build TypeScript pipeline orchestrator and digest formatter** - `57204d5` (feat)
2. **Task 2: Add 'analyze' subcommand to CLI entry point** - `e1d56d6` (feat)

## Files Created/Modified

- `packages/uae-re/src/analytics/pipeline.ts` — New: runAnalysisPipeline, getNextAnalysisDate, sendTelegramMessage (337 lines)
- `packages/uae-re/src/analytics/digest.ts` — New: generateDigest, formatDigestMessage, DigestData (286 lines)
- `packages/uae-re/src/cli.ts` — Added analyze subcommand, import for runAnalysisPipeline

## Decisions Made

- **runStep() helper pattern**: Single call site for runPython, insertLog, updateLog logic. Called 6 times for 6 steps. Avoids repetition and ensures consistent logging across all steps.
- **Digest gate on 24h window**: Granger signals must be from last 24 hours (`tested_at > datetime('now', '-1 day')`) — ensures we only send digest after a fresh pipeline run, not stale historical results.
- **Digest skip logged to analysis_log**: When < 3 signals exist, an explicit 'skipped' entry with the reason is written to analysis_log so operators can see why the digest was not dispatched.

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check: PASSED

- [x] `/root/lobsec/packages/uae-re/src/analytics/pipeline.ts` — FOUND
- [x] `/root/lobsec/packages/uae-re/src/analytics/digest.ts` — FOUND
- [x] `/root/lobsec/packages/uae-re/src/cli.ts` — FOUND (modified)
- [x] Commit `57204d5` — FOUND
- [x] Commit `e1d56d6` — FOUND
- [x] TypeScript compiles clean — VERIFIED
