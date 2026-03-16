---
phase: 09-tier-c-collection
plan: 04
subsystem: data-collection
tags: [collector-registry, systemd-timer, directpythoncollector, typescript, python, deployment, ninja-scraper]

# Dependency graph
requires:
  - phase: 09-tier-c-collection
    provides: "Plans 09-01/02/03: DirectPythonCollector class, 11 Ninja Scraper YAML missions, 13 Python normalizers, 13 pandera schemas, proxy+UA rotation infrastructure"
  - phase: 08-tier-b-collection
    provides: "SourceCollector base class, CollectorRegistry with createCollectors() factory, collect.sh orchestrator with frequency dispatch"

provides:
  - "Updated COLLECTOR_DEFINITIONS with 13 new Phase 9 entries (33 total collectors for 28 data sources)"
  - "createCollectors() dispatches google-trends and reddit-sentiment to DirectPythonCollector with pythonModule cast"
  - "SOURCE_MODULE_MAP extended with 13 Phase 9 entries (normalize_trends through normalize_office)"
  - "PythonScriptName union extended with 13 new normalizer names (34 total members)"
  - "lobsec-collect-daily.timer: fires 19:00 UTC (23:00 GST) for Google Trends + Reddit sentiment"
  - "lobsec-collect-daily.service: collect.sh daily, After=lobsec.service, TimeoutSec=600"
  - "lobsec-collect-weekly.service: TimeoutSec increased from 1800 to 43200 (12hr for Google Maps drip-feed)"
  - "All 31 YAML missions deployed to /opt/lobsec/scraper/missions/ (verified loaded by Ninja Scraper)"
  - "All 28 normalizers + 2 collect scripts + 13 schemas deployed to /opt/lobsec/plugins/lobsec-uae-re/"
  - "All 4 frequency-based collection timers active (daily, weekly, monthly, quarterly)"

affects:
  - 10-statistical-analysis (can now trigger normalize runs for all 28 sources)
  - 11-intelligence-products
  - collect.sh (daily dispatch path now exercised by systemd)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Registry DIRECT_PYTHON_SOURCES map: connects missionName string to PythonScriptName for DirectPythonCollector dispatch"
    - "PythonScriptName as cast type: string from DIRECT_PYTHON_SOURCES map cast to PythonScriptName for type-safe bridge calls"
    - "Daily timer: After=lobsec.service (Wants=, not Requires=) — soft dependency for environment, not hard startup dependency"

key-files:
  created:
    - /etc/systemd/system/lobsec-collect-daily.timer
    - /etc/systemd/system/lobsec-collect-daily.service
  modified:
    - packages/uae-re/src/collectors/registry.ts
    - packages/uae-re/src/normalization/types.ts
    - packages/uae-re/src/analytics/types.ts
    - /etc/systemd/system/lobsec-collect-weekly.service

key-decisions:
  - "13 entries added to COLLECTOR_DEFINITIONS (not 14 as stated in must_haves.truths) — action section listed 13 distinct sources; must_haves had an off-by-one; action is authoritative"
  - "DIRECT_PYTHON_SOURCES inline map in createCollectors() — avoids separate file, keeps dispatch logic colocated with factory"
  - "Daily service uses After=lobsec.service + Wants= (not Requires=) — DirectPythonCollector doesn't need lobsec gateway running, only needs environment; Wants= prevents timer failure if lobsec service unavailable"
  - "Weekly TimeoutSec 43200 (12hr) — Google Maps 50-location drip-feed pacing is 600-900s per location = up to 12.5hr total"

patterns-established:
  - "DIRECT_PYTHON_SOURCES pattern: inline Record<string, string> in createCollectors() maps missionName to pythonModule for DirectPythonCollector instantiation"

requirements-completed:
  - SCHED-05
  - COLL-14
  - COLL-16
  - COLL-17
  - COLL-18
  - COLL-19
  - COLL-20
  - COLL-21
  - COLL-22
  - COLL-23
  - COLL-24
  - COLL-25
  - COLL-26
  - COLL-27
  - COLL-28

# Metrics
duration: 6min
completed: 2026-03-16
---

# Phase 9 Plan 04: Registry Wiring, Type Extensions, Daily Timer, and Production Deployment Summary

**33-collector registry (13 new Phase 9 entries) with DirectPythonCollector dispatch, daily systemd timer at 19:00 UTC, and full Tier C asset deployment — all 4 frequency-based timers active, 31 missions loaded in Ninja Scraper**

## Performance

- **Duration:** ~6 minutes
- **Started:** 2026-03-16T06:31:12Z
- **Completed:** 2026-03-16T06:37:30Z
- **Tasks:** 2 of 2 (checkpoint:human-verify confirmed by user — deployment verified)
- **Files modified:** 7 (3 TypeScript + 2 systemd units + 1 systemd update + deployment)

## Accomplishments

- Extended COLLECTOR_DEFINITIONS from 20 to 33 entries; createCollectors() now dispatches google-trends and reddit-sentiment to DirectPythonCollector, all others to SourceCollector
- SOURCE_MODULE_MAP extended from 20 to 33 entries covering all Phase 9 normalizers; PythonScriptName union extended from 21 to 34 members
- Daily timer created and enabled (lobsec-collect-daily.timer at 19:00 UTC); all 4 frequency-based timers confirmed active in systemctl list-timers
- Full production deployment completed: 31 YAML missions + 28 normalizers + 2 collect scripts + 13 schemas + updated TypeScript dist deployed, Ninja Scraper restarted confirming 31 missions loaded

## Task Commits

Each task was committed atomically:

1. **Task 1: Registry wiring, type extensions, and daily timer** - `8aeca7c` (feat)
2. **Task 2: Deploy to production and verify** - checkpoint:human-verify approved by user

**Plan metadata:** (docs commit — see final commit below)

## Files Created/Modified

- `packages/uae-re/src/collectors/registry.ts` - Added DirectPythonCollector import + PythonScriptName import; updated COLLECTOR_DEFINITIONS with 13 Phase 9 entries; updated createCollectors() with DIRECT_PYTHON_SOURCES dispatch
- `packages/uae-re/src/normalization/types.ts` - Added 13 Phase 9 entries to SOURCE_MODULE_MAP (normalize_trends through normalize_office)
- `packages/uae-re/src/analytics/types.ts` - Extended PythonScriptName with 13 new normalizer names (normalize_trends through normalize_office)
- `/etc/systemd/system/lobsec-collect-daily.timer` - Daily timer: OnCalendar=*-*-* 19:00:00 UTC, Persistent=true
- `/etc/systemd/system/lobsec-collect-daily.service` - oneshot service: collect.sh daily, User=lobsec, After+Wants=lobsec.service
- `/etc/systemd/system/lobsec-collect-weekly.service` - TimeoutSec increased from 1800 to 43200 (12 hours)

## Decisions Made

- **13 vs 14 in COLLECTOR_DEFINITIONS**: The must_haves.truths said 14 new entries but the action section listed exactly 13 (2 daily + 1 weekly + 5 monthly + 5 quarterly). Followed the action section as authoritative. 20 + 13 = 33 total collectors.
- **After=lobsec.service + Wants= (not Requires=)**: Daily sources use DirectPythonCollector which calls Python directly via subprocess — not the Ninja Scraper HTTP API. The main lobsec service is not strictly required. Wants= provides soft ordering without failing the timer if lobsec is down.
- **DIRECT_PYTHON_SOURCES as inline Record**: Kept the dispatch map inline in createCollectors() for readability and locality. Two entries only — no need for a separate module or config file.

## Deviations from Plan

### Minor Discrepancy

**1. [Plan Inconsistency] 13 vs 14 collector entries**
- **Found during:** Task 1 (COLLECTOR_DEFINITIONS update)
- **Issue:** must_haves.truths specified "14 new entries" but the action section explicitly listed 13 entries across all frequencies
- **Resolution:** Followed the action section (authoritative list). Total = 33 collectors, not 34.
- **Impact:** None — all 15 requirements from the plan frontmatter are covered by the 13 new entries. The plan's own source list had 13 entries; must_haves appears to have an off-by-one.

---

**Total deviations:** 1 (plan internal inconsistency, resolved by following action section)
**Impact on plan:** No scope creep. All 15 requirements addressed.

## Issues Encountered

None — TypeScript compiled cleanly on first attempt. All deployment steps succeeded. Ninja Scraper loaded 31 missions on restart.

## User Setup Required

Reddit API credentials are needed before collect_sentiment.py can run in production:
- `REDDIT_CLIENT_ID` and `REDDIT_CLIENT_SECRET` must be stored in HSM (see Plan 09-01 documentation)
- Google Trends (collect_trends.py) works without credentials

Google Maps foot traffic requires a residential proxy for production operation:
- Set `NINJA_PROXY_URL` in environment when proxy service is available (see 09-CONTEXT.md)

## Next Phase Readiness

- Phase 9 Tier C Collection complete: all 28 data sources have YAML missions + Python normalizers + pandera schemas + registry entries
- Phase 10 (Statistical Analysis Pipeline) can begin: all sources registered, normalization pipeline ready
- 4 frequency-based timers all active: daily (Google Trends, Reddit), weekly (8 sources), monthly (9 sources), quarterly (6 sources)
- Remaining setup: Reddit HSM credentials, residential proxy service for Google Maps foot traffic

## Checkpoint Verification (Task 2)

User confirmed deployment verification:
- 4 timers active: `lobsec-collect-daily`, `lobsec-collect-weekly`, `lobsec-collect-monthly`, `lobsec-collect-quarterly`
- 31 YAML missions loaded by Ninja Scraper
- 28 normalizers + 2 collect scripts + 13 pandera schemas deployed to `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/`
- Weekly service `TimeoutSec` updated to 43200

## Self-Check: PASSED

- `/root/lobsec/.planning/phases/09-tier-c-collection/09-04-SUMMARY.md`: FOUND
- `/etc/systemd/system/lobsec-collect-daily.timer`: FOUND
- `/etc/systemd/system/lobsec-collect-daily.service`: FOUND
- Commit `8aeca7c`: FOUND in git log
- TypeScript compilation: CLEAN (0 errors)
- COLLECTOR_DEFINITIONS: 33 entries confirmed
- SOURCE_MODULE_MAP: 33 entries confirmed
- PythonScriptName: 34 union members confirmed
- Ninja Scraper: 31 missions loaded (status: ok)
- 4 collection timers: active in systemctl list-timers

---
*Phase: 09-tier-c-collection*
*Completed: 2026-03-16*
