---
phase: 20-dormant-mission-activation
plan: 01
subsystem: uae-re-mission-audit
tags: [mission-audit, pytrends, collector-registry, dormant-missions, retired-missions]
dependency_graph:
  requires: [06-02 collector-framework]
  provides: [mission-audit-report, enabled-flag-registry]
  affects: [collector-registry, collection-runs, normalized_monthly-scope]
tech_stack:
  added: []
  patterns: [enabled-flag-skip, pytrends-urllib3-patch]
key_files:
  created:
    - .planning/phases/20-dormant-mission-activation/20-AUDIT.md
  modified:
    - packages/uae-re/src/collectors/types.ts
    - packages/uae-re/src/collectors/registry.ts
    - /opt/lobsec/analytics-venv/lib/python3.13/site-packages/pytrends/request.py
decisions:
  - "Patch pytrends 4.9.2 in-place (method_whitelist -> allowed_methods) rather than downgrade urllib3"
  - "Use enabled:false flag (not removal) to preserve audit trail of retired missions"
  - "Keep bayut-listings enabled despite broken selectors (fixable, not permanent block)"
  - "Keep reddit-sentiment and news-sentiment enabled (work if credentials provided)"
  - "40 total missions (not 38 as initially counted): 22 enabled, 18 disabled"
metrics:
  duration: 514s
  completed: "2026-03-25T17:13:40Z"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 3
---

# Phase 20 Plan 01: Mission Audit + Registry Cleanup Summary

Full audit of 40 registered collector missions with pytrends urllib3 compatibility patch and 18 missions disabled (6 retired + 12 dormant) via `enabled: false` flag in CollectorMetadata, reducing wasted collection cycles from 40 to 22 active sources.

## What Was Built

### Task 1: Audit Report + pytrends Fix (20-AUDIT.md)

**Audit Report:** Created comprehensive classification of all 40 missions:
- 17 ACTIVE: Producing rows in normalized_monthly (1,534 total rows, 354 metrics)
- 4 ACTIVATION-TARGET: Have raw data + normalizer code but need pipeline verification
- 2 BLOCKED-CREDENTIALS: reddit-sentiment (REDDIT_CLIENT_ID/SECRET), news-sentiment (NEWSAPI_KEY)
- 8 DORMANT-NEVER-RAN: Paywalled/no-public-data sources (salary surveys, commercial reports, customs, licenses, FB closures, Airbnb)
- 3 DORMANT-BROKEN: Producing null/empty data (dtcm-tourism, rta-metro, rta-vehicles)
- 6 RETIRED: Permanently blocked (DLD/Ejari/Permits WAF, DEWA timeout, GulfTalent paid, Google Maps unscrapable)

**pytrends Fix:** Patched pytrends 4.9.2 request.py in analytics-venv:
- Root cause: `Retry(method_whitelist=...)` removed in urllib3 2.0+, installed urllib3 2.6.3
- Fix: Changed `method_whitelist` to `allowed_methods` (line 128 of request.py)
- Verification: Google Trends collector now produces 318 records across 6 keyword groups (buy_intent, rent_intent, expat_lifecycle, distress, luxury, exit_moving)
- pytrends 4.9.2 is latest on PyPI; no upgrade available, in-place patch was the only option

### Task 2: Registry Changes + Deploy

**CollectorMetadata type extension:**
- Added `enabled?: boolean` field (defaults to true, set false for retired/blocked)

**18 missions marked `enabled: false`:**
- 6 RETIRED: dld-sales, ejari-rentals, building-permits, dewa-connections, gulftalent-jobs, google-maps-traffic
- 12 DORMANT: gdrfa-visas, rta-vehicles, cooper-fitch-salary, hays-salary, roberthalf-salary, rta-metro, dtcm-tourism, ded-licenses, fb-closures, customs-imports, insideairbnb, commercial-office-reports

**Skip logic:** Added `if (def.metadata.enabled === false) { continue; }` at top of `createCollectors()` loop.

**22 missions remain enabled:**
- 17 producing normalized data
- google-trends (just fixed)
- bayut-listings (broken selectors, fixable)
- cbuae-mortgages (activation target for Plan 20-02)
- reddit-sentiment + news-sentiment (credential-blocked, user action needed)

**Build:** 0 TypeScript errors. Deployed to production. Service restarted successfully.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] pytrends 4.9.2 is latest on PyPI**
- **Found during:** Task 1 (pytrends upgrade attempt)
- **Issue:** Plan expected pytrends 4.9.3+ to fix urllib3 compatibility, but 4.9.2 is the latest available version on PyPI.
- **Fix:** Patched pytrends request.py in-place, changing `method_whitelist` to `allowed_methods` on line 128. This is the standard urllib3 2.x migration.
- **Files modified:** `/opt/lobsec/analytics-venv/lib/python3.13/site-packages/pytrends/request.py`
- **Note:** Patch will need reapplication if pytrends is reinstalled.

**2. [Rule 1 - Bug] Mission count was 40, not 38**
- **Found during:** Task 2 (registry audit)
- **Issue:** Plan referenced 38 missions but actual COLLECTOR_DEFINITIONS has 40 entries (Phase 19 added commodities, news-sentiment, cbuae-expanded after the count was set).
- **Fix:** No code change needed. Adjusted documentation. 40 total - 18 disabled = 22 enabled.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | 8b174e3 | Audit report (20-AUDIT.md) + pytrends patch documentation |
| 2 | b0360bc | CollectorMetadata enabled field + 18 missions disabled + skip logic |

## Success Criteria Verification

- [x] Audit report (20-AUDIT.md) documents all 40 missions with classification and evidence
- [x] pytrends patched and Google Trends collector verified working (318 records)
- [x] 18 missions disabled in registry (6 retired + 12 dormant)
- [x] Build passes with 0 TypeScript errors
- [x] Deployed to production, service restarted
- [x] Collection runs now skip disabled missions (22 enabled vs 40 previously)

## Self-Check: PASSED

All files verified present. Both commits (8b174e3, b0360bc) verified in git log.
