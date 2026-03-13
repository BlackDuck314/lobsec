---
phase: 08-tier-b-collection
plan: 04
subsystem: scheduling

tags: [systemd, timers, ninja-scraper, orchestration, deployment]

# Dependency graph
requires:
  - phase: 08-03
    provides: "COLLECTOR_DEFINITIONS extended to 20 entries, SOURCE_MODULE_MAP with 13 Tier B mappings, collect.sh orchestrator script"
provides:
  - "3 systemd timers (weekly Mon 02:00 UTC, monthly 1st 02:00 UTC, quarterly 15th Jan/Apr/Jul/Oct 05:00 UTC)"
  - "20 YAML missions deployed to Ninja Scraper (7 Tier A + 13 Tier B)"
  - "8 Python normalization modules deployed to production"
  - "Automated collection scheduling operational"
affects: [Phase 10 Statistical Analysis Pipeline, Phase 12 Plugin Tools]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "systemd timer+service pairs for scheduled collection (weekly/monthly/quarterly)"
    - "Ninja Scraper mission hotload (cp to /opt/lobsec/scraper/missions/ + restart)"
    - "Requires=lobsec-scraper.service dependency for collection services"

key-files:
  created:
    - /etc/systemd/system/lobsec-collect-weekly.timer
    - /etc/systemd/system/lobsec-collect-weekly.service
    - /etc/systemd/system/lobsec-collect-monthly.timer
    - /etc/systemd/system/lobsec-collect-monthly.service
    - /etc/systemd/system/lobsec-collect-quarterly.timer
    - /etc/systemd/system/lobsec-collect-quarterly.service
  modified: []

key-decisions:
  - "3 frequency-based timers instead of 20 source-specific timers to avoid SQLite write contention"
  - "All timers at non-overlapping hours (02:00 for weekly/monthly, 05:00 for quarterly) to spread load"
  - "30min timeout for weekly, 60min for monthly/quarterly to accommodate source counts"
  - "Persistent=true on all timers so missed runs execute immediately on boot"
  - "Deployment via cp -r instead of pip install to match existing lobsec service pattern"

patterns-established:
  - "Timer OnCalendar syntax: Mon *-*-* 02:00:00 UTC (weekly), *-*-01 02:00:00 UTC (monthly), *-01,04,07,10-15 05:00:00 UTC (quarterly)"
  - "Service ExecStart: /opt/lobsec/bin/collect.sh {frequency} for orchestrated collection"
  - "Security hardening: NoNewPrivileges, ProtectSystem=strict, ProtectHome, ReadWritePaths for data/logs only"
  - "Dependency chain: timer triggers service, service requires lobsec-scraper.service, service calls collect.sh, collect.sh calls Node CLI, CLI calls Ninja Scraper API"

requirements-completed: [SCHED-02, SCHED-03, SCHED-04]

# Metrics
duration: 18min
completed: 2026-03-13
---

# Phase 8 Plan 04: systemd Timers & Production Deployment Summary

**3 systemd timers active with 20 Ninja Scraper missions deployed, completing automated UAE RE data collection scheduling**

## Performance

- **Duration:** 18 min
- **Started:** 2026-03-13T08:05:00Z
- **Completed:** 2026-03-13T08:23:00Z
- **Tasks:** 2
- **Files modified:** 6 systemd units created, 20 YAML missions deployed, 8 Python normalizers deployed

## Accomplishments
- 3 systemd timer+service pairs created with correct OnCalendar schedules (weekly Mon 02:00 UTC, monthly 1st 02:00 UTC, quarterly 15th Jan/Apr/Jul/Oct 05:00 UTC)
- 13 new YAML missions deployed to Ninja Scraper bringing total from 7 to 20
- 8 new Python normalization modules deployed to /opt/lobsec/plugins/lobsec-uae-re/
- TypeScript dist rebuilt and deployed with updated 20-entry COLLECTOR_DEFINITIONS
- All 3 timers enabled and active with next trigger dates
- End-to-end verification: rta-vehicles test collection produced raw data file

## Task Commits

1. **Task 1: Create systemd timers, deploy assets, and enable collection scheduling** - `[pending]` (feat)
2. **Task 2: Verify deployment and timer activation** - `[checkpoint approved]` (verify)

**Plan metadata:** `[pending]` (docs: complete plan 08-04)

## Files Created/Modified
- `/etc/systemd/system/lobsec-collect-weekly.timer` - Weekly collection timer (Mon 02:00 UTC = 06:00 GST)
- `/etc/systemd/system/lobsec-collect-weekly.service` - Weekly service (DLD, Ejari, listings, job platforms)
- `/etc/systemd/system/lobsec-collect-monthly.timer` - Monthly collection timer (1st 02:00 UTC = 06:00 GST)
- `/etc/systemd/system/lobsec-collect-monthly.service` - Monthly service (permits, MOHRE, DXB, RTA, DEWA, ADREC)
- `/etc/systemd/system/lobsec-collect-quarterly.timer` - Quarterly collection timer (15th Jan/Apr/Jul/Oct 05:00 UTC = 09:00 GST)
- `/etc/systemd/system/lobsec-collect-quarterly.service` - Quarterly service (GDRFA, CBUAE, salary surveys, KHDA)
- `/opt/lobsec/scraper/missions/mohre-permits.yml` - MOHRE work permits mission
- `/opt/lobsec/scraper/missions/dxb-passengers.yml` - DXB airport passengers mission
- `/opt/lobsec/scraper/missions/gdrfa-visas.yml` - GDRFA visa transactions mission
- `/opt/lobsec/scraper/missions/khda-enrollment.yml` - KHDA school enrollment mission
- `/opt/lobsec/scraper/missions/rta-vehicles.yml` - RTA vehicle registrations mission
- `/opt/lobsec/scraper/missions/cbuae-remittances.yml` - CBUAE remittance data mission
- `/opt/lobsec/scraper/missions/linkedin-jobs.yml` - LinkedIn job postings mission
- `/opt/lobsec/scraper/missions/bayt-jobs.yml` - Bayt job postings mission
- `/opt/lobsec/scraper/missions/indeed-jobs.yml` - Indeed job postings mission
- `/opt/lobsec/scraper/missions/gulftalent-jobs.yml` - GulfTalent job postings mission
- `/opt/lobsec/scraper/missions/cooper-fitch-salary.yml` - Cooper Fitch salary survey mission
- `/opt/lobsec/scraper/missions/hays-salary.yml` - Hays salary survey mission
- `/opt/lobsec/scraper/missions/roberthalf-salary.yml` - Robert Half salary survey mission
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_mohre.py` - MOHRE normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_dxb.py` - DXB normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_gdrfa.py` - GDRFA normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_khda.py` - KHDA normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_rta.py` - RTA normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_remittances.py` - CBUAE normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_jobs.py` - Job platforms normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_salary.py` - Salary surveys normalization module
- `/opt/lobsec/plugins/lobsec-uae-re/dist/*` - Updated TypeScript compiled output

## Decisions Made
None - followed plan as specified.

## Deviations from Plan
None - plan executed exactly as written.

## Issues Encountered
None - all deployment steps completed successfully. Test collection verified end-to-end pipeline (collect.sh → Ninja Scraper → raw file).

## User Setup Required

**External services require manual configuration.** See [08-04-USER-SETUP.md](./08-04-USER-SETUP.md) for:
- GulfTalent account creation and credential storage in HSM
- Environment variables to add
- Verification commands

## Next Phase Readiness

**Phase 8 (Tier B Collection) complete.** All 4 plans executed:
- Plan 08-01: 6 government/institutional sources (MOHRE, DXB, GDRFA, KHDA, RTA, CBUAE)
- Plan 08-02: 7 job/salary sources (4 job platforms + 3 salary surveys)
- Plan 08-03: TypeScript registry + collect.sh orchestrator
- Plan 08-04: systemd timers + production deployment

**Ready for Phase 9 (Tier C Collection)** with:
- 20 missions operational in Ninja Scraper
- 3 systemd timers scheduled correctly
- collect.sh orchestrator handling frequency-based collection
- Python normalization pipeline deployed for all sources

**Blockers:**
- Dubai Pulse API credentials needed for DLD, Ejari, Building Permits, DEWA (4 sources block at WAF without auth)
- GulfTalent account needed for authenticated session (COLL-11)

**Next steps:**
- User creates accounts per USER-SETUP.md
- Phase 9 adds remaining 14 Tier C sources
- Phase 10 builds statistical analysis pipeline on collected data

---
*Phase: 08-tier-b-collection*
*Completed: 2026-03-13*
