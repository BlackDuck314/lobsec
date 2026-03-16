---
phase: 10-statistical-analysis
plan: 04
subsystem: infra
tags: [systemd, bash, analyze, timer, deployment, python, typescript, sqlite]

# Dependency graph
requires:
  - phase: 10-01
    provides: analyze_stationarity.py, analyze_granger.py, 5 new DB tables
  - phase: 10-02
    provides: analyze_composite.py, analyze_anomalies.py, analyze_affordability.py, analyze_expat_funnel.py
  - phase: 10-03
    provides: runAnalysisPipeline(), CLI 'analyze' subcommand, Telegram digest formatter
provides:
  - analyze.sh shell orchestrator (/opt/lobsec/bin/analyze.sh)
  - lobsec-uae-analyze.timer (25th 02:00 UTC, Persistent=true, SCHED-06)
  - lobsec-uae-analyze.service (oneshot, lobsec user, 3600s timeout)
  - Full production deployment: TS compiled, Python deployed, DB schema migrated, timer active
affects:
  - 11-intelligence-products (pipeline results in composite_scores/anomaly_flags/granger_results are queryable)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - analyze.sh follows collect.sh pattern — sources .env, invokes node CLI, logs to analyze.log
    - systemd oneshot service + monthly timer pattern (25th 02:00 UTC, Persistent=true)
    - Pipeline end-to-end: timer → service → analyze.sh → node cli.js analyze → Python modules
    - Security hardening on service: NoNewPrivileges, ProtectSystem=strict, ProtectHome, ReadWritePaths

key-files:
  created:
    - /opt/lobsec/bin/analyze.sh (pipeline orchestrator shell script)
    - /etc/systemd/system/lobsec-uae-analyze.timer (monthly 25th 02:00 UTC timer)
    - /etc/systemd/system/lobsec-uae-analyze.service (oneshot lobsec service)
  modified:
    - packages/uae-re/python/uae_re/analyze_affordability.py (removed area_name column ref)
    - packages/uae-re/python/uae_re/analyze_composite.py (removed area_name column ref)
    - packages/uae-re/src/db/schema.ts (added 'in_progress' to analysis_log CHECK constraint)

key-decisions:
  - "analyze.sh has no health check for Ninja Scraper — pipeline reads from SQLite, not the scraper"
  - "Pipeline graceful skip on insufficient data is expected — few months of collection history"
  - "TimeoutStartSec=3600 (1 hour) matches plan spec — analysis run time upper bound"

patterns-established:
  - "Shell orchestrator pattern: sources .env, runs node CLI, tee-appends to log file"
  - "systemd timer with Persistent=true ensures missed run recovery on server restart"

requirements-completed: [SCHED-06, SEC-06, SEC-07]

# Metrics
duration: 45min
completed: 2026-03-16
---

# Phase 10 Plan 04: Deploy Analysis Pipeline Summary

**analyze.sh + lobsec-uae-analyze.timer wiring the statistical analysis pipeline to run monthly on the 25th at 02:00 UTC, with all 6 Python modules deployed and pipeline verified end-to-end**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-03-16T10:40:00Z
- **Completed:** 2026-03-16T11:55:00Z
- **Tasks:** 2 (1 auto + 1 checkpoint:human-verify)
- **Files modified:** 3 source files + 3 production files created

## Accomplishments

- analyze.sh created at /opt/lobsec/bin/analyze.sh (lobsec-owned, executable, follows collect.sh pattern)
- lobsec-uae-analyze.timer enabled with OnCalendar=*-*-25 02:00:00 and Persistent=true (SCHED-06 fulfilled)
- Pipeline ran end-to-end: all 6 steps succeeded (graceful skip on insufficient data — expected and correct)
- 5 new database tables created (stationarity_results, granger_results, composite_scores, anomaly_flags, analysis_log)
- 26 analysis_log entries confirmed from manual pipeline run
- Next scheduled run: Wed 2026-03-25 02:00:00 UTC

## Task Commits

Each task was committed atomically:

1. **Task 1: Create analyze.sh, systemd units, build, deploy, and migrate** - `f78bbb0` (feat)
2. **Task 2: Verify production deployment** - checkpoint:human-verify, approved by user

**Plan metadata:** (see final docs commit)

## Files Created/Modified

- `/opt/lobsec/bin/analyze.sh` - Pipeline orchestrator shell script (lobsec user, executable)
- `/etc/systemd/system/lobsec-uae-analyze.timer` - Monthly timer, 25th 02:00 UTC, Persistent=true
- `/etc/systemd/system/lobsec-uae-analyze.service` - Oneshot service, lobsec user, 3600s timeout, security hardening
- `packages/uae-re/python/uae_re/analyze_affordability.py` - Removed area_name column ref (not in schema)
- `packages/uae-re/python/uae_re/analyze_composite.py` - Removed area_name column ref (same fix)
- `packages/uae-re/src/db/schema.ts` - Added 'in_progress' to analysis_log status CHECK constraint

## Decisions Made

- analyze.sh has no health check for Ninja Scraper — the analysis pipeline reads from SQLite, not from the scraper directly. No uptime dependency.
- Pipeline graceful skip on insufficient data is expected and correct behavior. Only a few months of collection history at time of deployment.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed analysis_log CHECK constraint missing 'in_progress' status**
- **Found during:** Task 1 (Step 5 — schema migration + pipeline run)
- **Issue:** schema.ts CHECK constraint on analysis_log.status allowed only ('success', 'failed', 'skipped') but pipeline.ts writes 'in_progress' as intermediate state before updating to final status
- **Fix:** Added 'in_progress' to the CHECK constraint values: `CHECK(status IN ('success','failed','skipped','in_progress'))`
- **Files modified:** packages/uae-re/src/db/schema.ts
- **Verification:** Pipeline completed all 6 steps without constraint error
- **Committed in:** f78bbb0 (Task 1 commit)

**2. [Rule 1 - Bug] Fixed analyze_affordability.py querying non-existent area_name column**
- **Found during:** Task 1 (Step 5 — pipeline run)
- **Issue:** analyze_affordability.py referenced area_name column in normalized_monthly table but that table has no such column (area_id is the key)
- **Fix:** Removed area_name column reference from query; affordability module uses area_id-based lookups
- **Files modified:** packages/uae-re/python/uae_re/analyze_affordability.py
- **Verification:** Affordability step ran successfully in pipeline
- **Committed in:** f78bbb0 (Task 1 commit)

**3. [Rule 1 - Bug] Fixed analyze_composite.py querying non-existent area_name column**
- **Found during:** Task 1 (Step 5 — pipeline run)
- **Issue:** analyze_composite.py had same area_name column reference bug as affordability module
- **Fix:** Removed area_name column reference; composite module uses area_id-based lookups
- **Files modified:** packages/uae-re/python/uae_re/analyze_composite.py
- **Verification:** Composite step ran successfully in pipeline
- **Committed in:** f78bbb0 (Task 1 commit)

---

**Total deviations:** 3 auto-fixed (3 Rule 1 bugs)
**Impact on plan:** All 3 fixes were required for the pipeline to run end-to-end. No scope creep.

## Issues Encountered

None beyond the 3 auto-fixed bugs above. Pipeline ran cleanly after fixes.

## User Setup Required

None — no external service configuration required. All deployment is on the local server.

## Next Phase Readiness

- Phase 10 (Statistical Analysis Pipeline) is fully complete — all 4 plans done
- analysis_log has 26 entries confirming all 6 pipeline steps ran
- Timer is active; next run 2026-03-25 02:00 UTC
- Phase 11 (Intelligence Products) can proceed — composite_scores, anomaly_flags, granger_results tables are queryable
- Note: Pipeline results will be sparse until more collection history accumulates (expected — most steps skip with insufficient data)

## Self-Check: PASSED

- FOUND: /root/lobsec/.planning/phases/10-statistical-analysis/10-04-SUMMARY.md
- FOUND: /opt/lobsec/bin/analyze.sh
- FOUND: /etc/systemd/system/lobsec-uae-analyze.timer
- FOUND: /etc/systemd/system/lobsec-uae-analyze.service
- FOUND: commit f78bbb0 (feat(10-04): deploy analysis pipeline)

---
*Phase: 10-statistical-analysis*
*Completed: 2026-03-16*
