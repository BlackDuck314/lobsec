---
phase: 08-tier-b-collection
plan: 01
subsystem: collection
tags: [ninja-scraper, pdfplumber, patchright, yaml-missions, python-normalization, government-data]

# Dependency graph
requires:
  - phase: 07.1-ninja-scraper
    provides: Browser scrape engine with Patchright stealth, YAML mission auto-discovery, FastAPI at 127.0.0.1:18791
  - phase: 06-foundation-infrastructure
    provides: Python analytics environment with pdfplumber, pandas, SQLite database, stdin/stdout bridge pattern
provides:
  - 6 YAML browser_scrape missions for government/institutional sources (MOHRE, DXB, GDRFA, KHDA, RTA, CBUAE)
  - 6 Python normalization modules with pdfplumber table extraction
  - 6 pandera validation schemas
  - Established PDF extraction pattern (page targeting, header detection, fallback to manual entry)
affects: [08-02-tier-b-scheduling, 10-statistical-analysis, 12-plugin-tools]

# Tech tracking
tech-stack:
  added: []  # pdfplumber already in analytics-venv from Phase 6
  patterns:
    - "PDF table extraction with page targeting (pages 2-10) to reduce false positives"
    - "Measurement date computation: monthly → start of month, quarterly → start of quarter, annual → September"
    - "Error messages for Telegram manual-entry fallback when PDF extraction fails"
    - "Regex-based text extraction for press releases (MOHRE)"
    - "Sanity validation (DXB >100K passengers, KHDA >100K students)"

key-files:
  created:
    - packages/scraper/missions/mohre-permits.yml
    - packages/scraper/missions/dxb-passengers.yml
    - packages/scraper/missions/gdrfa-visas.yml
    - packages/scraper/missions/khda-enrollment.yml
    - packages/scraper/missions/rta-vehicles.yml
    - packages/scraper/missions/cbuae-remittances.yml
    - packages/uae-re/python/uae_re/normalize_mohre.py
    - packages/uae-re/python/uae_re/normalize_dxb.py
    - packages/uae-re/python/uae_re/normalize_gdrfa.py
    - packages/uae-re/python/uae_re/normalize_khda.py
    - packages/uae-re/python/uae_re/normalize_rta.py
    - packages/uae-re/python/uae_re/normalize_remittances.py
    - packages/uae-re/python/uae_re/schemas/mohre_schema.py
    - packages/uae-re/python/uae_re/schemas/dxb_schema.py
    - packages/uae-re/python/uae_re/schemas/gdrfa_schema.py
    - packages/uae-re/python/uae_re/schemas/khda_schema.py
    - packages/uae-re/python/uae_re/schemas/rta_schema.py
    - packages/uae-re/python/uae_re/schemas/remittances_schema.py
  modified: []

key-decisions:
  - "All 6 missions use browser_scrape type (not http_download) for consistent Patchright stealth approach"
  - "PDF extraction happens in Python normalization modules, not YAML missions (clean separation: scraper collects files, Python understands content)"
  - "MOHRE targets statistical reports page (not press releases) for structured data"
  - "DXB targets PDF factsheets over HTML press releases for reliable pdfplumber extraction"
  - "KHDA uses quarterly frequency (not annual) so timer checks for new annual report"
  - "CBUAE extracts ALL tables from full PDF, filters for remittance data during normalization"
  - "RTA uses browser_scrape to bypass Dubai Pulse WAF"
  - "GDRFA and CBUAE are independent quarterly missions (different URLs, extraction, failure modes)"

patterns-established:
  - "PDF normalizer pattern: validate PDF exists → pdfplumber.open() → target specific pages → detect tables by header keywords → extract numeric values → compute measurement_date → return metrics"
  - "Press release normalizer pattern: validate JSON structure → regex extraction from text → sector keyword matching → accumulate across articles → compute measurement_date → return metrics"
  - "Error handling for PDF extraction: descriptive ValueError with required field names for Telegram manual-entry fallback"
  - "Page targeting: first 3-5 pages for summaries (DXB), pages 2-5 for visa stats (GDRFA), first 10 pages for enrollment (KHDA)"
  - "Header detection: join table[0] cells, lowercase, check for keywords (visa+issued, enrollment+student, remittance+personal)"
  - "Sanity validation: DXB >100K passengers/month, KHDA >100K students (Dubai has 300K+)"

requirements-completed: [COLL-06, COLL-07, COLL-08, COLL-09, COLL-10, COLL-13]

# Metrics
duration: 18min
completed: 2026-03-13
---

# Phase 08 Plan 01: Tier B Government Sources Summary

**6 YAML browser_scrape missions and 6 Python normalization modules with pdfplumber table extraction for MOHRE work permits, DXB airport passengers, GDRFA visa transactions, KHDA school enrollment, RTA vehicle registrations, and CBUAE remittance outflows**

## Performance

- **Duration:** 18 min
- **Started:** 2026-03-13T07:04:00Z
- **Completed:** 2026-03-13T07:22:00Z
- **Tasks:** 2
- **Files modified:** 18 (6 YAML + 6 normalizers + 6 schemas)

## Accomplishments
- 6 new YAML missions auto-discoverable by Ninja Scraper (total 13 missions with Phase 7)
- 6 Python normalization modules following stdin/stdout JSON bridge pattern
- 6 pandera validation schemas for raw data validation
- PDF extraction pattern established with page targeting and header detection
- All normalizers handle extraction failures with descriptive errors for Telegram manual-entry fallback

## Task Commits

Each task was committed atomically:

1. **Task 1: Create 6 YAML mission specs** - `3fc3833` (feat)
2. **Task 2: Create 6 Python normalization modules with pandera schemas** - `55b1913` (feat)

## Files Created/Modified

**YAML missions (6):**
- `packages/scraper/missions/mohre-permits.yml` - Monthly MOHRE work permits from statistical reports page
- `packages/scraper/missions/dxb-passengers.yml` - Monthly DXB airport passengers from PDF factsheets
- `packages/scraper/missions/gdrfa-visas.yml` - Quarterly GDRFA visa transactions from PDF reports
- `packages/scraper/missions/khda-enrollment.yml` - Annual KHDA school enrollment from PDF census
- `packages/scraper/missions/rta-vehicles.yml` - Monthly RTA vehicle registrations from Dubai Pulse (browser scrape to bypass WAF)
- `packages/scraper/missions/cbuae-remittances.yml` - Quarterly CBUAE remittance outflows from balance of payments PDF

**Python normalizers (6):**
- `packages/uae-re/python/uae_re/normalize_mohre.py` - Press release text extraction with regex, sector keyword matching
- `packages/uae-re/python/uae_re/normalize_dxb.py` - pdfplumber table extraction (pages 0-4) for passenger counts with sanity check (>100K)
- `packages/uae-re/python/uae_re/normalize_gdrfa.py` - pdfplumber table extraction (pages 1-4) for visa issuance/cancellation with net flow computation
- `packages/uae-re/python/uae_re/normalize_khda.py` - pdfplumber table extraction (pages 0-9) for enrollment by curriculum with sanity check (>100K)
- `packages/uae-re/python/uae_re/normalize_rta.py` - JSON table data from browser scrape with net change computation
- `packages/uae-re/python/uae_re/normalize_remittances.py` - pdfplumber extraction from full PDF (all pages) filtered by remittance keywords

**Pandera schemas (6):**
- `packages/uae-re/python/uae_re/schemas/mohre_schema.py` - JSON structure validation for press releases
- `packages/uae-re/python/uae_re/schemas/dxb_schema.py` - PDF file validation (exists, readable, valid header)
- `packages/uae-re/python/uae_re/schemas/gdrfa_schema.py` - PDF file validation
- `packages/uae-re/python/uae_re/schemas/khda_schema.py` - PDF file validation
- `packages/uae-re/python/uae_re/schemas/rta_schema.py` - JSON structure validation for vehicle registration data
- `packages/uae-re/python/uae_re/schemas/remittances_schema.py` - PDF file validation

## Decisions Made

**YAML mission configuration:**
- All 6 missions use `type: browser_scrape` (consistent approach, Patchright overhead is small)
- MOHRE targets statistical reports page (`mohre.gov.ae/en/data-library/statistical-report.aspx`) instead of press releases for structured data
- DXB uses `find_and_download` strategy targeting PDF factsheets over HTML press releases for reliable table extraction
- KHDA uses `frequency: quarterly` (not annual) so timer checks for new annual report without creating separate frequency
- RTA uses browser_scrape to bypass Dubai Pulse WAF that blocks HTTP downloads
- GDRFA and CBUAE are independent quarterly missions (different URLs, different extraction logic)

**Python normalization patterns:**
- PDF extraction happens in Python (not YAML missions) — clean separation: scraper collects files, Python understands content
- Page targeting reduces false positives: DXB 0-4, GDRFA 1-4, KHDA 0-9, CBUAE all pages
- Header detection via lowercase keyword matching: `if "visa" in header and "issued" in header`
- Sanity validation for critical metrics: DXB >100K passengers, KHDA >100K students
- Measurement date computation: monthly → start of month, quarterly → start of quarter, annual → September (academic year)
- Error messages include required field names for Telegram manual-entry fallback

**Metric naming:**
- Dubai-level metrics use `dubai|` prefix (MOHRE, DXB, GDRFA, KHDA, RTA)
- UAE-level metrics use `uae|` prefix (CBUAE remittances — national data, not Dubai-specific)
- Sector/curriculum breakdowns use underscore suffix: `mohre_permits_tech`, `khda_enrollment_british`

## Deviations from Plan

None - plan executed exactly as written. All decisions were within Claude's discretion per 08-01-PLAN.md context.

## Issues Encountered

None - all 6 missions and 6 normalizers created successfully, Python files parse without syntax errors, patterns established cleanly.

## User Setup Required

None - no external service configuration required. All sources use public URLs.

Note: GulfTalent credentials for authenticated job scraping are deferred to Plan 08-02 (job postings). Dubai Pulse API credentials needed for DLD/Ejari/Building Permits are user action items from Phase 7 (not Phase 8).

## Next Phase Readiness

**Ready for Plan 08-02 (job postings and salary surveys):**
- YAML mission pattern established (browser_scrape with keywords/selectors)
- Python normalization pattern established (stdin/stdout bridge, pdfplumber extraction)
- Pandera validation pattern established (JSON structure or PDF file validation)

**Ready for scheduling integration (Plan 08-03):**
- All 6 missions have correct `frequency` field (monthly, quarterly)
- Mission names are collector-friendly (mohre-permits, dxb-passengers, etc.)
- Normalizers follow naming convention (normalize_{source}.py)

**Blockers:**
- None for next plan

**Note for Plan 08-02:**
- Job platform missions (LinkedIn, Bayt, Indeed, GulfTalent) and salary survey missions (Cooper Fitch, Hays, Robert Half) already exist in packages/scraper/missions/ (7 files total, committed in first Task 1 commit 3fc3833)
- Plan 08-02 needs to create corresponding normalize_jobs.py and normalize_salary.py modules plus schemas

---
*Phase: 08-tier-b-collection*
*Completed: 2026-03-13*
