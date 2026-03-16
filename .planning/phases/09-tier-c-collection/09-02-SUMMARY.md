---
phase: 09-tier-c-collection
plan: 02
subsystem: data-collection
tags: [yaml, ninja-scraper, python, pdfplumber, pandera, rta, cbuae, dtcm, ded, fcsa, jebel-ali, browser-scrape]

# Dependency graph
requires:
  - phase: 08-tier-b-collection
    provides: Ninja Scraper engine with 20 missions, Python normalization pattern, pandera schema conventions
  - phase: 09-tier-c-collection/09-01
    provides: Phase 9 infrastructure setup (daily timer, collect.sh daily dispatch)

provides:
  - 6 government/institutional YAML missions (rta-metro, cbuae-mortgages, dtcm-tourism, ded-licenses, fcsa-demographics, jebel-ali-port)
  - 6 Python normalizer modules with established stdin/stdout JSON bridge pattern
  - 6 pandera validation schema files with value-range sanity checks
  - CBUAE mortgages PDF normalizer using pdfplumber with header-based table detection

affects:
  - 09-tier-c-collection/09-03 (next plan — remaining Tier C sources)
  - 10-statistical-analysis (will consume these metrics for Granger/correlation analysis)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "browser_scrape for all government sources (consistent with Phase 8 approach)"
    - "proxy: false for government sources (no WAF evasion needed)"
    - "skip_on_403: true for graceful failure on government blocks"
    - "PDF extraction in Python normalizer, not YAML mission (clean separation)"
    - "pdfplumber header keyword detection for table identification"
    - "Empty list return for annual data sources on non-annual quarters"
    - "uae| prefix for national-level metrics, dubai| for Dubai-specific"
    - "Optional sector/category breakdown via dict field (metrics generated per key)"

key-files:
  created:
    - packages/scraper/missions/rta-metro.yml
    - packages/scraper/missions/cbuae-mortgages.yml
    - packages/scraper/missions/dtcm-tourism.yml
    - packages/scraper/missions/ded-licenses.yml
    - packages/scraper/missions/fcsa-demographics.yml
    - packages/scraper/missions/jebel-ali-port.yml
    - packages/uae-re/python/uae_re/normalize_metro.py
    - packages/uae-re/python/uae_re/normalize_mortgages.py
    - packages/uae-re/python/uae_re/normalize_tourism.py
    - packages/uae-re/python/uae_re/normalize_licenses.py
    - packages/uae-re/python/uae_re/normalize_demographics.py
    - packages/uae-re/python/uae_re/normalize_port.py
    - packages/uae-re/python/uae_re/schemas/metro_schema.py
    - packages/uae-re/python/uae_re/schemas/mortgages_schema.py
    - packages/uae-re/python/uae_re/schemas/tourism_schema.py
    - packages/uae-re/python/uae_re/schemas/licenses_schema.py
    - packages/uae-re/python/uae_re/schemas/demographics_schema.py
    - packages/uae-re/python/uae_re/schemas/port_schema.py
  modified: []

key-decisions:
  - "FCSA demographics uses DSC (Dubai Statistics Centre) URL, not national FCSA — more granular Dubai-specific data"
  - "Demographics normalizer returns empty list for most quarterly runs (annual data) — this is valid, not an error"
  - "CBUAE mortgages uses uae| prefix (national data), consistent with cbuae-remittances pattern"
  - "DED licenses uses Dubai Pulse URL (same WAF approach as rta-vehicles browser scrape)"
  - "Jebel Ali port construction material breakdown is optional — logged as warning if absent, not error"
  - "Sector breakdown in DED licenses generates dynamic per-sector metrics (dubai|ded_new_by_sector_{sector})"

patterns-established:
  - "Annual data sources: return empty list [] when no new bulletin detected (demographics pattern)"
  - "PDF normalizers: header keyword detection across all pages, _parse_numeric helper for value extraction"
  - "Optional subset metrics: log warning to stderr and skip metric (don't raise error) for missing breakdowns"
  - "Dynamic per-category metrics: iterate dict breakdown fields to generate N metrics from 1 source field"

requirements-completed: [COLL-16, COLL-17, COLL-18, COLL-20, COLL-23, COLL-25]

# Metrics
duration: 6min
completed: 2026-03-16
---

# Phase 9 Plan 02: Government Tier C Sources Summary

**6 government YAML missions (RTA metro, CBUAE mortgages, DTCM tourism, DED licenses, FCSA demographics, Jebel Ali port) with Python normalizers and pandera schemas producing 2-6 metrics each**

## Performance

- **Duration:** ~6 min
- **Started:** 2026-03-16T06:18:41Z
- **Completed:** 2026-03-16T06:24:41Z
- **Tasks:** 2 completed
- **Files modified:** 18 (6 YAML + 6 normalizers + 6 schemas)

## Accomplishments

- Created 6 YAML missions for government/institutional Tier C sources, all loading correctly alongside 25 existing missions (total 31 in Ninja Scraper)
- Created 6 Python normalizers following the established stdin/stdout JSON bridge pattern, producing 2-6 typed metrics each
- CBUAE mortgages normalizer uses pdfplumber with header-keyword table detection (same approach as cbuae-remittances), including EIBOR sanity validation (0-15% range)
- Demographics normalizer gracefully returns empty list for non-annual quarters (expected behavior for annual DSC data)
- DED licenses normalizer generates dynamic per-sector metrics from optional breakdown dict

## Task Commits

Each task was committed atomically:

1. **Task 1: Government YAML missions** - `df2d6fc` (feat)
2. **Task 2: Python normalizers + pandera schemas** - `8ea6432` (feat)

**Plan metadata:** (final docs commit — see below)

## Files Created/Modified

**YAML Missions:**
- `packages/scraper/missions/rta-metro.yml` — monthly browser_scrape, ridership fields, RTA statistics page
- `packages/scraper/missions/cbuae-mortgages.yml` — quarterly PDF download, EIBOR + mortgage outstanding
- `packages/scraper/missions/dtcm-tourism.yml` — monthly browser_scrape, hotel occupancy + visitor stats
- `packages/scraper/missions/ded-licenses.yml` — monthly browser_scrape via Dubai Pulse WAF bypass
- `packages/scraper/missions/fcsa-demographics.yml` — quarterly check for annual DSC population data
- `packages/scraper/missions/jebel-ali-port.yml` — monthly browser_scrape of DP World press releases

**Normalizers:**
- `packages/uae-re/python/uae_re/normalize_metro.py` — 4 monthly metrics (total/rail/tram/bus)
- `packages/uae-re/python/uae_re/normalize_mortgages.py` — 3 quarterly UAE-level metrics via pdfplumber
- `packages/uae-re/python/uae_re/normalize_tourism.py` — 4 monthly metrics (occupancy/visitors/revenue/stay)
- `packages/uae-re/python/uae_re/normalize_licenses.py` — 3+ monthly metrics with optional sector breakdown
- `packages/uae-re/python/uae_re/normalize_demographics.py` — 5 annual metrics, empty list is valid
- `packages/uae-re/python/uae_re/normalize_port.py` — 2-3 monthly metrics, construction materials optional

**Schemas:**
- `packages/uae-re/python/uae_re/schemas/metro_schema.py` — validates JSON structure, non-negative ridership
- `packages/uae-re/python/uae_re/schemas/mortgages_schema.py` — validates PDF file + EIBOR 0-15% range
- `packages/uae-re/python/uae_re/schemas/tourism_schema.py` — occupancy 0-100, visitor_count positive
- `packages/uae-re/python/uae_re/schemas/licenses_schema.py` — counts non-negative, sector dict optional
- `packages/uae-re/python/uae_re/schemas/demographics_schema.py` — population positive, growth -10 to 20%
- `packages/uae-re/python/uae_re/schemas/port_schema.py` — TEU+cargo positive, construction materials optional

## Decisions Made

- **DSC over FCSA**: Used Dubai Statistics Centre URL for demographics — more granular Dubai-specific population data vs. national FCSA
- **uae| prefix for CBUAE mortgages**: National mortgage market data, consistent with existing cbuae-remittances prefix convention
- **Empty list = valid output**: Demographics normalizer returns [] when no annual bulletin detected — logged as expected behavior, not error
- **Construction materials optional**: Jebel Ali port construction material breakdown uses warning+skip pattern rather than error, since DP World press releases don't consistently include this breakdown
- **Dynamic sector metrics**: DED licenses generates `dubai|ded_new_by_sector_{sector}` metrics from a sector breakdown dict, normalized through a SECTOR_MAP for consistent naming

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pandas `UserWarning: Converting to Period representation will drop timezone information` appears when calling `to_period("M")` on timezone-aware timestamps. This is a pre-existing cosmetic warning present in all existing normalizers (normalize_rta.py, etc.) — not a bug, not fixed.

## User Setup Required

None — all 6 new missions use public government URLs without authentication. DED licenses and RTA metro will depend on Dubai Pulse WAF behavior, which may require the same Dubai Pulse API credentials being tracked for Phase 8 sources.

## Next Phase Readiness

- All 6 government Tier C sources now have complete collection infrastructure (YAML + normalizer + schema)
- Requirements COLL-16, COLL-17, COLL-18, COLL-20, COLL-23, COLL-25 implemented
- Ready for Plan 09-03 (remaining Tier C sources: Google Trends, Reddit sentiment, InsideAirbnb, F&B closures, foot traffic, commercial office reports, customs imports)

---
*Phase: 09-tier-c-collection*
*Completed: 2026-03-16*
