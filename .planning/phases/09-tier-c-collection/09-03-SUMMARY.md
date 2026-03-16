---
phase: 09-tier-c-collection
plan: 03
subsystem: data-collection
tags: [ninja-scraper, yaml-missions, python-normalizers, airbnb, google-maps, customs, f&b-closures, commercial-office, pandera, pdfplumber]

# Dependency graph
requires:
  - phase: 09-tier-c-collection
    provides: "Plan 09-01/02: government/social Tier C missions and normalizers (proxy fields, schemas package)"
  - phase: 08-tier-b-collection
    provides: "Mission YAML schema, Mission Pydantic model, load_all_missions() auto-discovery"

provides:
  - "insideairbnb.yml: quarterly http_download for STR CSV from insideairbnb.com"
  - "fb-closures.yml: monthly browser_scrape with proxy+UA rotation for Google Maps/Zomato"
  - "customs-imports.yml: quarterly browser_scrape for CBUAE/Dubai Customs HS-code trade stats"
  - "google-maps-traffic.yml: weekly browser_scrape for 50 locations with 10-15min drip-feed pacing"
  - "commercial-office-reports.yml: quarterly browser_scrape for JLL/CBRE/Savills office market data"
  - "normalize_airbnb.py: gzipped CSV normalization with occupancy proxy + multihost ratio"
  - "normalize_fb_closures.py: Google Maps + Zomato deduplication, per-area closure counts"
  - "normalize_customs.py: HS-code household goods import metrics with PDF pdfplumber fallback"
  - "normalize_foot_traffic.py: Popular Times histogram → per-location + 5-category aggregate metrics"
  - "normalize_office.py: JLL/CBRE/Savills cross-validation metrics with PDF pdfplumber fallback"
  - "5 pandera schema files for raw data validation"

affects:
  - 09-tier-c-collection (Plan 09-04: collector registry + deployment)
  - 10-statistical-analysis
  - 11-intelligence-products

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "proxy + user_agent_rotation optional YAML fields on Mission model for stealth scraping"
    - "drip-feed pacing: delay_between_requests_ms [600000, 900000] for 10-15min inter-location delays"
    - "graceful failure: all normalizers return [] on missing/empty data"
    - "PDF fallback: pdfplumber in normalizers for gated reports (customs, office)"
    - "cross-validation: per-source metrics (office_jll_vacancy, office_cbre_vacancy, office_savills_vacancy)"
    - "occupancy proxy: 1 - avg_availability/365 from InsideAirbnb availability_365 field"

key-files:
  created:
    - packages/scraper/missions/insideairbnb.yml
    - packages/scraper/missions/fb-closures.yml
    - packages/scraper/missions/customs-imports.yml
    - packages/scraper/missions/google-maps-traffic.yml
    - packages/scraper/missions/commercial-office-reports.yml
    - packages/uae-re/python/uae_re/normalize_airbnb.py
    - packages/uae-re/python/uae_re/normalize_fb_closures.py
    - packages/uae-re/python/uae_re/normalize_customs.py
    - packages/uae-re/python/uae_re/normalize_foot_traffic.py
    - packages/uae-re/python/uae_re/normalize_office.py
    - packages/uae-re/python/uae_re/schemas/airbnb_schema.py
    - packages/uae-re/python/uae_re/schemas/fb_closures_schema.py
    - packages/uae-re/python/uae_re/schemas/customs_schema.py
    - packages/uae-re/python/uae_re/schemas/foot_traffic_schema.py
    - packages/uae-re/python/uae_re/schemas/office_schema.py
  modified:
    - packages/scraper/src/ninja_scraper/engine/mission.py

key-decisions:
  - "Mission model extended with optional proxy and user_agent_rotation bool fields (default False)"
  - "Google Maps traffic uses max_attempts=1 (no retry on block) + skip_on_403=true — retry accelerates bans"
  - "F&B closures areas list includes 7 Google Maps area searches + Zomato as 8th entry for cross-validation"
  - "Foot traffic drip-feed: 600-900s delay between 50 locations = ~10 hours total runtime"
  - "normalize_fb_closures deduplicates by (restaurant_name, area) preferring Google Maps over Zomato"
  - "normalize_office produces both per-source and averaged aggregate metrics for cross-validation"
  - "InsideAirbnb multihost_ratio uses calculated_host_listings_count>1 as commercial STR indicator"
  - "Foot traffic category inference: URL pattern matching (metro, malls, business, residential, landmarks)"

patterns-established:
  - "Graceful empty return: all normalizers return [] if file missing or data empty"
  - "PDF pdfplumber fallback: normalize_customs and normalize_office try PDF when JSON incomplete"
  - "normalize() module-level function: all normalizers expose normalize(file_path, collected_at) entry point"

requirements-completed:
  - COLL-19
  - COLL-21
  - COLL-22
  - COLL-26
  - COLL-28

# Metrics
duration: 10min
completed: 2026-03-16
---

# Phase 9 Plan 03: Alternative/Commercial Tier C Collection Summary

**5 YAML missions (InsideAirbnb STR, F&B closures, Dubai Customs HS-code imports, Google Maps Popular Times 50-location drip-feed, JLL/CBRE/Savills office reports) + 5 Python normalizers with per-category aggregates, occupancy proxy, and PDF pdfplumber fallback**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-16T06:20:00Z
- **Completed:** 2026-03-16T06:26:53Z
- **Tasks:** 2
- **Files modified:** 16

## Accomplishments

- 5 YAML missions auto-discovered by Ninja Scraper (total: 31 missions across all phases)
- Google Maps traffic mission: 50 curated locations across 5 categories, 10-15 min drip-feed pacing (max 1 attempt per location, skip on block)
- InsideAirbnb: http_download for gzipped quarterly CSV — only alternative data source not using browser_scrape
- 5 Python normalizers all import and pass functional tests from analytics-venv
- normalize_foot_traffic produces per-location metrics + 5 category aggregates (malls, metro, landmarks, business, residential) + composite index
- normalize_office produces per-firm (JLL/CBRE/Savills) metrics and averaged aggregates for cross-validation

## Task Commits

Each task was committed atomically:

1. **Task 1: Alternative/commercial YAML missions** - `077fc17` (feat)
2. **Task 2: Python normalizers for alternative/commercial sources** - `15d55b4` (feat)

## Files Created/Modified

- `packages/scraper/missions/insideairbnb.yml` - Quarterly http_download of InsideAirbnb CSV
- `packages/scraper/missions/fb-closures.yml` - Monthly browser_scrape (Google Maps + Zomato), proxy=true, UA rotation=true
- `packages/scraper/missions/customs-imports.yml` - Quarterly browser_scrape for CBUAE/Dubai Customs HS-code stats
- `packages/scraper/missions/google-maps-traffic.yml` - Weekly browser_scrape for 50 locations, drip-feed pacing [600000, 900000]ms
- `packages/scraper/missions/commercial-office-reports.yml` - Quarterly browser_scrape for JLL/CBRE/Savills
- `packages/scraper/src/ninja_scraper/engine/mission.py` - Added proxy and user_agent_rotation optional fields
- `packages/uae-re/python/uae_re/normalize_airbnb.py` - Gzipped CSV, occupancy proxy, multihost ratio, top-10 neighbourhoods
- `packages/uae-re/python/uae_re/normalize_fb_closures.py` - Google Maps + Zomato dedup, per-area counts
- `packages/uae-re/python/uae_re/normalize_customs.py` - HS-code imports, household share %, PDF fallback
- `packages/uae-re/python/uae_re/normalize_foot_traffic.py` - Popular Times histogram, 5-category aggregates, composite
- `packages/uae-re/python/uae_re/normalize_office.py` - JLL/CBRE/Savills cross-validation, PDF fallback
- `packages/uae-re/python/uae_re/schemas/airbnb_schema.py` - DataFrame + JSON validation for InsideAirbnb
- `packages/uae-re/python/uae_re/schemas/fb_closures_schema.py` - Closure record validation
- `packages/uae-re/python/uae_re/schemas/customs_schema.py` - HS-code import value range validation
- `packages/uae-re/python/uae_re/schemas/foot_traffic_schema.py` - Popular Times histogram structure validation
- `packages/uae-re/python/uae_re/schemas/office_schema.py` - Office metric range + source validation

## Decisions Made

- Mission model needed `proxy` and `user_agent_rotation` fields added — plan required them on YAML files but Pydantic model would reject unknown fields. Added as optional with default False (auto-fixed inline before Task 1).
- Google Maps traffic uses `max_attempts: 1` (single attempt per location). Retrying on Google block accelerates detection and banning. Better to skip and get partial data than trigger IP bans.
- F&B closures `areas` list uses 7 Google Maps area-specific search URLs + Zomato as entry 8 — enables both sources within single mission.
- InsideAirbnb `occupancy_proxy = 1 - (avg_availability_365 / 365)` — lower availability = higher estimated occupancy.
- Foot traffic normalizer infers location category from URL pattern matching for aggregate grouping.
- Commercial office normalizer outputs per-source (JLL/CBRE/Savills) metrics separately from averaged aggregate — enables cross-validation when firms disagree.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added proxy and user_agent_rotation fields to Mission Pydantic model**
- **Found during:** Task 1 (YAML mission creation)
- **Issue:** Plan required `proxy: true` in YAML missions, but the Mission Pydantic model in `mission.py` had no such fields. Pydantic would silently ignore unknown fields OR reject them, making `missions['google-maps-traffic'].proxy` inaccessible (verification would fail).
- **Fix:** Added `proxy: bool = False` and `user_agent_rotation: bool = False` as optional fields to the `Mission` BaseModel.
- **Files modified:** `packages/scraper/src/ninja_scraper/engine/mission.py`
- **Verification:** Verification script asserts `missions['google-maps-traffic'].proxy == True` passes.
- **Committed in:** `077fc17` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical)
**Impact on plan:** Required for plan verification to succeed and for proxy-aware scraper handlers to check mission.proxy flag. No scope creep.

## Issues Encountered

None — all missions loaded on first pass. Normalizer functional tests all passed.

## User Setup Required

None - no external service configuration required. When proxy service is purchased, store proxy URL in HSM as described in CONTEXT.md.

## Next Phase Readiness

- 31 YAML missions ready for auto-discovery (7 Tier A + 13 Tier B + 6 Phase 09-01 + 5 Phase 09-02 + 5 this plan)
- 5 new normalizers ready to register in COLLECTOR_DEFINITIONS array (Plan 09-04)
- Google Maps mission requires residential proxy service for production operation (deferred per CONTEXT.md)
- All normalizers return gracefully on empty data — safe to run before source data is available

## Self-Check: PASSED

- All 16 created/modified files confirmed present on disk
- Commits 077fc17 (Task 1) and 15d55b4 (Task 2) confirmed in git log

---
*Phase: 09-tier-c-collection*
*Completed: 2026-03-16*
