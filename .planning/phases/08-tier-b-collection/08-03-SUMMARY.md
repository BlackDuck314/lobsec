---
phase: 08-tier-b-collection
plan: "03"
subsystem: scheduling-orchestration
tags:
  - collector-registry
  - orchestrator-script
  - typescript-framework
  - systemd-integration
requires:
  - Phase 8 Plan 01 (6 government sources + normalizers)
  - Phase 8 Plan 02 (7 job/salary sources + normalizers)
  - Phase 7.1 Ninja Scraper deployed
provides:
  - COLLECTOR_DEFINITIONS with 20 entries (7 Tier A + 13 Tier B)
  - SOURCE_MODULE_MAP with 20 entries
  - PythonScriptName with 8 new normalizer variants
  - collect.sh orchestrator script at /opt/lobsec/bin/
affects:
  - packages/uae-re/src/collectors/registry.ts
  - packages/uae-re/src/normalization/types.ts
  - packages/uae-re/src/analytics/types.ts
  - packages/uae-re/src/cli.ts
  - /opt/lobsec/bin/collect.sh
tech-stack:
  added: []
  patterns:
    - "Factory pattern: COLLECTOR_DEFINITIONS array drives createCollectors()"
    - "Many-to-one mapping: 4 job platforms → normalize_jobs, 3 salary firms → normalize_salary"
    - "Bash orchestrator pattern: env sourcing, health check, Node CLI invocation, log rotation"
key-files:
  created:
    - /opt/lobsec/bin/collect.sh
    - .planning/phases/08-tier-b-collection/deployment-artifacts.md
  modified:
    - packages/uae-re/src/collectors/registry.ts
    - packages/uae-re/src/normalization/types.ts
    - packages/uae-re/src/analytics/types.ts
    - packages/uae-re/src/cli.ts
key-decisions:
  - "COLLECTOR_DEFINITIONS now has 20 entries: 7 existing Tier A + 13 new Tier B (6 government + 4 job + 3 salary)"
  - "Job platforms (LinkedIn, Bayt, Indeed, GulfTalent) all map to normalize_jobs (platform detection in Python)"
  - "Salary surveys (Cooper Fitch, Hays, Robert Half) all map to normalize_salary (firm detection in Python)"
  - "Timeouts: 5min for HTML/API sources (300_000ms), 10min for browser-heavy job platforms (600_000ms)"
  - "Frequencies: weekly (7 sources), monthly (6 sources), quarterly (7 sources)"
  - "Priority: 1 (DLD/Ejari), 2 (government/salary surveys), 3 (job platforms/listing portals)"
  - "collect.sh deployed outside git repo, tracked via deployment-artifacts.md"
requirements-completed:
  - SCHED-02
  - SCHED-03
  - SCHED-04
  - SCHED-07
duration: 6 min
completed: 2026-03-13T07:17:00Z
---

# Phase 8 Plan 03: Wire Tier B Sources Into TypeScript Framework Summary

**Wired all 13 new Tier B data sources into the TS collector framework and created the collect.sh orchestrator script. COLLECTOR_DEFINITIONS expanded to 20 entries, SOURCE_MODULE_MAP updated with 13 new mappings, PythonScriptName type extended with 8 new normalizer variants.**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-13T07:11:00Z
- **Completed:** 2026-03-13T07:17:00Z
- **Tasks:** 2
- **Files modified:** 5 (4 TS files + 1 deployment tracking file)
- **Files deployed:** 1 (collect.sh)

## Accomplishments

- Updated COLLECTOR_DEFINITIONS with 13 new Tier B entries (total 20 collectors)
- Extended SOURCE_MODULE_MAP with 13 new source-to-module mappings (total 20 entries)
- Added 8 new PythonScriptName variants for Tier B normalizers
- Created collect.sh orchestrator script with health check and log rotation
- All TypeScript files compile cleanly with 0 errors
- Established many-to-one normalization mapping (4→1 for jobs, 3→1 for salary)

## Task Commits

Each task was committed atomically:

1. **Task 1: Update COLLECTOR_DEFINITIONS, SOURCE_MODULE_MAP, and PythonScriptName** - `6b80b67` (feat)
2. **Task 2: Create collect.sh orchestrator script and update CLI comments** - `8311414` (feat)

## Files Created/Modified

**TypeScript framework (4 files modified):**
- `packages/uae-re/src/collectors/registry.ts` - Added 13 new COLLECTOR_DEFINITIONS entries, updated JSDoc from "7 collectors" to "20 collectors"
- `packages/uae-re/src/normalization/types.ts` - Added 13 new SOURCE_MODULE_MAP entries with many-to-one mappings
- `packages/uae-re/src/analytics/types.ts` - Added 8 new PythonScriptName variants
- `packages/uae-re/src/cli.ts` - Updated comments from "Register all 7 collectors" to "Register all collectors (Tier A + Tier B)"

**Deployment artifacts (2 files created):**
- `/opt/lobsec/bin/collect.sh` - Bash orchestrator script (755 permissions, lobsec:lobsec ownership)
- `.planning/phases/08-tier-b-collection/deployment-artifacts.md` - Deployment tracking file

## Technical Implementation

### COLLECTOR_DEFINITIONS Structure

Added 13 new entries with correct frequency, priority, and timeout values:

**Government/Institutional (6 sources):**
- `mohre-permits`, `dxb-passengers`, `rta-vehicles` - Monthly, priority 2, 5min timeout
- `gdrfa-visas`, `khda-enrollment`, `cbuae-remittances` - Quarterly, priority 2, 5min timeout

**Job Platforms (4 sources):**
- `linkedin-jobs`, `bayt-jobs`, `indeed-jobs`, `gulftalent-jobs` - Weekly, priority 3, 10min timeout

**Salary Surveys (3 sources):**
- `cooper-fitch-salary`, `hays-salary`, `roberthalf-salary` - Quarterly, priority 2, 5min timeout

### Many-to-One Normalization Mapping

**Multiple sources → single normalizer:**
- 4 job platforms (linkedin, bayt, indeed, gulftalent) → `normalize_jobs.py` (platform detection from `source` field)
- 3 salary firms (cooper-fitch, hays, roberthalf) → `normalize_salary.py` (firm detection from `source` field)

This reduces code duplication while preserving independent failure modes per source.

### Orchestrator Script (collect.sh)

**Structure:**
1. Argument validation (weekly/monthly/quarterly/daily or source name)
2. Environment sourcing (`/opt/lobsec/.env` for SCRAPER_AUTH_TOKEN, UAE_RE_DATA_DIR)
3. Health check (curl http://127.0.0.1:18791/health)
4. Command routing (run-frequency vs run-one)
5. Node CLI invocation with output capture
6. Log rotation (append to /opt/lobsec/logs/collection.log)
7. Exit code propagation

**Usage:**
```bash
# Frequency-based (all collectors matching frequency)
collect.sh weekly
collect.sh monthly
collect.sh quarterly

# Single source (on-demand)
collect.sh mohre-permits
collect.sh linkedin-jobs
```

**Trigger chain:**
systemd timer → collect.sh → Node CLI → CollectorRegistry → Ninja Scraper → Python normalization → Telegram summary

### Timeout Enforcement (SCHED-07)

Timeouts enforced at 4 levels:
1. **YAML mission `timeout_ms`** - 300_000 (5min) for HTML/API, 600_000 (10min) for browser automation
2. **CollectorMetadata `timeout`** - Same values as YAML missions
3. **Scraper API `maxWaitMs`** - 600_000 (10min) default
4. **Python subprocess `defaultTimeoutMs`** - 120_000 (2min)

Hierarchy ensures: browser mission kills at 5/10min → scraper polling timeout at 10min → Python normalization timeout at 2min.

### Frequency Distribution

**Weekly (7 sources):** dld-sales, ejari-rentals, bayut-listings, propertyfinder-listings, linkedin-jobs, bayt-jobs, indeed-jobs, gulftalent-jobs

**Monthly (6 sources):** building-permits, adrec-abu-dhabi, dewa-connections, mohre-permits, dxb-passengers, rta-vehicles

**Quarterly (7 sources):** gdrfa-visas, khda-enrollment, cbuae-remittances, cooper-fitch-salary, hays-salary, roberthalf-salary

**Daily (0 sources):** Reserved for Phase 9 Tier C (Google Trends, social sentiment, foot traffic)

### Priority Ordering

**Priority 1 (highest):** dld-sales, ejari-rentals - Core transaction data

**Priority 2 (medium):** building-permits, adrec-abu-dhabi, dewa-connections, government sources (6), salary surveys (3)

**Priority 3 (lowest):** bayut-listings, propertyfinder-listings, job platforms (4)

CollectorRegistry executes collectors in priority order within concurrency limit (max 3 concurrent).

## Decisions Made

**COLLECTOR_DEFINITIONS expansion:**
- All 13 new Tier B sources added with correct metadata
- Timeouts match YAML mission timeout_ms values
- Frequencies align with data publication schedules (government sources quarterly, job platforms weekly)

**Many-to-one normalization:**
- Reduces 13 source entries to 8 unique normalizer modules
- Platform/firm detection handled in Python via `source` field inspection
- Simpler than creating 13 separate normalizers with duplicated logic

**Bash orchestrator pattern:**
- Matches existing gateway-chat.sh pattern for consistency
- Health check prevents collection runs when Ninja Scraper is down
- Log rotation appends to single file (not per-frequency logs)
- Exit code propagation enables systemd failure detection

**Deployment tracking:**
- collect.sh deployed directly to /opt/lobsec/bin/ (outside git repo)
- Tracked via deployment-artifacts.md for auditability
- Ownership set to lobsec:lobsec, permissions 755

## Deviations from Plan

None - plan executed exactly as written. All decisions within Claude's discretion.

## Issues Encountered

None - TypeScript compilation clean, all verifications passed.

## Verification Results

All verification criteria passed:

1. TypeScript compiles cleanly (`npx tsc --noEmit`) ✓
2. COLLECTOR_DEFINITIONS has 20 entries (`grep -c "missionName:"` returns 20) ✓
3. SOURCE_MODULE_MAP has 20 entries (`grep -c '":"'` returns 20) ✓
4. PythonScriptName includes 8 new variants (normalize_mohre, normalize_dxb, normalize_gdrfa, normalize_khda, normalize_rta, normalize_remittances, normalize_jobs, normalize_salary) ✓
5. collect.sh is executable (`test -x /opt/lobsec/bin/collect.sh`) ✓
6. collect.sh sources .env and calls Node CLI (`grep -q "source /opt/lobsec/.env"`) ✓

## Requirements Satisfied

**SCHED-02: Weekly Collection Timer**
- 8 weekly collectors registered (DLD, Ejari, Bayut, PropertyFinder, LinkedIn, Bayt, Indeed, GulfTalent)
- collect.sh supports `collect.sh weekly` invocation

**SCHED-03: Monthly Collection Timer**
- 6 monthly collectors registered (Building Permits, ADREC, DEWA, MOHRE, DXB, RTA)
- collect.sh supports `collect.sh monthly` invocation

**SCHED-04: Quarterly Collection Timer**
- 7 quarterly collectors registered (GDRFA, KHDA, CBUAE, Cooper Fitch, Hays, Robert Half)
- collect.sh supports `collect.sh quarterly` invocation

**SCHED-07: Timeout Enforcement**
- All collectors have timeout values (300_000ms or 600_000ms)
- Matches YAML mission timeout_ms values
- Hierarchy: browser mission → scraper API → Python subprocess

## Next Phase Readiness

**Ready for Plan 08-04 (deployment):**
- All TS framework wiring complete
- Orchestrator script created and executable
- All 20 YAML missions exist in packages/scraper/missions/
- All 8 Python normalizers exist in packages/uae-re/python/uae_re/

**Still needed for deployment:**
- systemd timer units (lobsec-collect-weekly.timer, lobsec-collect-monthly.timer, lobsec-collect-quarterly.timer)
- systemd service units (lobsec-collect-weekly.service, lobsec-collect-monthly.service, lobsec-collect-quarterly.service)
- Timer enable and activation
- Initial seed collection run
- End-to-end verification

**Blockers:**
- None for next plan

**Note:**
- GulfTalent credentials still needed for authenticated job scraping (user action item)
- Dubai Pulse API credentials still needed for DLD/Ejari/Building Permits/RTA (user action item)
- Collectors gracefully handle missing credentials (skip source, log warning)

## User Setup Required

None for this plan. Credentials and timer deployment deferred to Plan 08-04.

---
*Phase: 08-tier-b-collection*
*Completed: 2026-03-13*
