---
phase: 06-foundation-infrastructure
plan: 02
subsystem: infra
tags: [collector-framework, python-bridge, resilience, concurrency, subprocess]

# Dependency graph
requires:
  - phase: 06-01
    provides: SQLite database layer and Python analytics modules
provides:
  - Abstract SourceCollector base class with retry + circuit breaker
  - CollectorRegistry with max-3 concurrency control
  - Python subprocess bridge with JSON I/O and timeout enforcement
  - Health check utilities for Python venv and dependencies
affects: [07-mvp-collection, 08-tier-b-collection, 09-tier-c-collection, 10-statistical-analysis]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Abstract base class pattern for collector implementations
    - Semaphore-based concurrency control with wait queue
    - Python subprocess bridge with JSON stdin/stdout
    - Graceful timeout handling (SIGTERM → SIGKILL fallback)

key-files:
  created:
    - packages/uae-re/src/collectors/types.ts
    - packages/uae-re/src/collectors/base.ts
    - packages/uae-re/src/collectors/registry.ts
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/src/analytics/bridge.ts
  modified:
    - packages/uae-re/src/index.ts

key-decisions:
  - "Circuit breaker config: 3 failures to open, 30s reset timeout, 1 success to close"
  - "Stale status after 2 consecutive failures (not just 'failed')"
  - "Semaphore pattern for concurrency (not polling with setTimeout)"
  - "Empty collection (rowCount=0) treated as validation error"
  - "SIGTERM graceful kill followed by SIGKILL after 5s if process survives"
  - "Python venv default at /opt/lobsec/analytics-venv (configurable)"

patterns-established:
  - "Collectors implement abstract collect() method, inherit resilience from run()"
  - "Registry sorts by priority (1=highest) before execution"
  - "Wait queue releases next waiter immediately when slot freed"
  - "Python bridge resolves pythonPkgDir relative to bridge.ts location"

requirements-completed: [INFRA-03, INFRA-04, INFRA-05]

# Metrics
duration: 3min
completed: 2026-03-11
---

# Phase 6 Plan 02: Collector Framework & Python Bridge Summary

**SourceCollector abstract base with retry+circuit breaker, CollectorRegistry with semaphore-based max-3 concurrency, and runPython() bridge with JSON stdin/stdout I/O**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-11T17:02:00Z
- **Completed:** 2026-03-11T17:04:50Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Created abstract SourceCollector base class with collect(), run(), and validateResult() methods
- Implemented retry with exponential backoff (3 retries) and circuit breaker (3 failures to open)
- Built CollectorRegistry with semaphore-based concurrency control (max 3 concurrent executions)
- Developed Python subprocess bridge with JSON I/O, timeout enforcement, and graceful termination
- Added health check utilities for Python venv availability and dependency verification

## Task Commits

Each task was committed atomically:

1. **Task 1: Build SourceCollector abstract base class and CollectorRegistry** - `258fab2` (feat)
2. **Task 2: Build Python subprocess bridge (runPython)** - `40e1d90` (feat)

## Files Created/Modified

### Collector Framework
- `packages/uae-re/src/collectors/types.ts` - Type definitions for metadata, results, status, and registry outcomes
- `packages/uae-re/src/collectors/base.ts` - Abstract SourceCollector with retry+circuit breaker+validation
- `packages/uae-re/src/collectors/registry.ts` - CollectorRegistry with semaphore-based concurrency control

### Analytics Bridge
- `packages/uae-re/src/analytics/types.ts` - PythonResult, PythonScriptName, BridgeConfig types
- `packages/uae-re/src/analytics/bridge.ts` - runPython(), checkPythonAvailable(), checkDependencies()

### Package Entry Point
- `packages/uae-re/src/index.ts` - Export all collector and analytics types/functions

## Decisions Made

1. **Circuit breaker thresholds**: Configured with failureThreshold=3, resetTimeoutMs=30000, halfOpenSuccesses=1. This provides reasonable tolerance for transient failures while preventing cascading issues.

2. **Stale status tracking**: Collectors marked "stale" after 2 consecutive failures (not just "failed"). This distinguishes persistent issues from one-off failures.

3. **Semaphore concurrency control**: Used wait queue with immediate release (not setTimeout polling). More efficient and avoids race conditions in slot allocation.

4. **Empty collection validation**: rowCount=0 throws validation error. Empty collections are unusual and likely indicate upstream issues worth surfacing.

5. **Graceful process termination**: SIGTERM first, then SIGKILL after 5s if process survives timeout. Gives Python scripts chance to clean up resources.

6. **Python venv location**: Default path /opt/lobsec/analytics-venv matches production deployment layout, but configurable via BridgeConfig.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all tasks completed without errors. Package compiles cleanly, all verifications pass.

## User Setup Required

None - no external service configuration required. Python venv creation happens in Plan 03 deployment phase.

## Next Phase Readiness

- Collector framework complete and ready for Phase 7 MVP implementations
- Python bridge operational and ready for analytics module invocation
- All 3 requirements (INFRA-03, INFRA-04, INFRA-05) completed
- CollectorRegistry tested and verified with concurrency control
- Health check utilities available for deployment validation

**Ready to proceed to Plan 03 (Deployment & Integration).**

---
*Phase: 06-foundation-infrastructure*
*Plan: 02*
*Completed: 2026-03-11*
