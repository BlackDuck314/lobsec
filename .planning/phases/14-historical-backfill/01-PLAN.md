---
phase: 14-historical-backfill
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - packages/uae-re/python/uae_re/backfill/__init__.py
  - packages/uae-re/python/uae_re/backfill/backfill_demographics.py
  - packages/uae-re/python/uae_re/backfill/backfill_mohre.py
  - packages/uae-re/python/uae_re/backfill/backfill_dpworld.py
  - packages/uae-re/python/uae_re/backfill/backfill_dxb.py
autonomous: true
requirements: [BACK-01, BACK-02, BACK-03, BACK-05]

must_haves:
  truths:
    - "DSC normalized_monthly contains population rows for 2022, 2023, and 2024 (3 years x 2+ metrics)"
    - "DXB normalized_monthly contains annual passenger counts for 2022, 2023, and 2024"
    - "MOHRE normalized_monthly contains comparative stat card metrics for 2024 alongside existing 2021-2025 emiratisation series"
    - "DP World normalized_monthly contains container throughput for at least 2019-2024 (6 years)"
  artifacts:
    - path: "packages/uae-re/python/uae_re/backfill/__init__.py"
      provides: "Backfill package init with shared insert_metric helper"
      exports: ["insert_metric"]
    - path: "packages/uae-re/python/uae_re/backfill/backfill_demographics.py"
      provides: "DSC population backfill from existing PDF"
      min_lines: 40
    - path: "packages/uae-re/python/uae_re/backfill/backfill_dxb.py"
      provides: "DXB passenger backfill from press release downloads"
      min_lines: 60
    - path: "packages/uae-re/python/uae_re/backfill/backfill_mohre.py"
      provides: "MOHRE stat card comparative backfill from existing JSON"
      min_lines: 40
    - path: "packages/uae-re/python/uae_re/backfill/backfill_dpworld.py"
      provides: "DP World throughput backfill from existing RSS HTML"
      min_lines: 50
  key_links:
    - from: "packages/uae-re/python/uae_re/backfill/backfill_demographics.py"
      to: "/opt/lobsec/data/uae-re.db"
      via: "sqlite3 INSERT into normalized_monthly"
      pattern: "INSERT INTO normalized_monthly"
    - from: "packages/uae-re/python/uae_re/backfill/backfill_dxb.py"
      to: "/opt/lobsec/data/uae-re.db"
      via: "sqlite3 INSERT into normalized_monthly"
      pattern: "INSERT INTO normalized_monthly"
    - from: "packages/uae-re/python/uae_re/backfill/backfill_dpworld.py"
      to: "/opt/lobsec/data/raw/jebel-ali-port/2026-03-16.html"
      via: "Parse __NEXT_DATA__ JSON from RSS HTML"
      pattern: "__NEXT_DATA__"
---

<objective>
Backfill 4 of 5 historical data sources (DSC, DXB, MOHRE, DP World) into normalized_monthly.

Purpose: Provide 3+ years of time-series depth to unlock statistical analysis (stationarity testing, Granger causality). Currently these sources have 1-11 rows each, all from recent scrapes. After backfill, each will have multi-year coverage.

Output: 4 standalone Python backfill scripts in packages/uae-re/python/uae_re/backfill/ plus ~40-60 new rows in normalized_monthly spanning 2019-2025.
</objective>

<execution_context>
@/root/.claude/get-shit-done/workflows/execute-plan.md
@/root/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/14-historical-backfill/RESEARCH.md

Source files for reference (normalizer patterns):
@packages/uae-re/python/uae_re/normalize_demographics.py
@packages/uae-re/python/uae_re/normalize_dxb.py
@packages/uae-re/python/uae_re/normalize_mohre.py
@packages/uae-re/python/uae_re/normalize_port.py

<interfaces>
<!-- Database schema (from uae-re.db) -->
```sql
CREATE TABLE normalized_monthly (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  measurement_date TEXT NOT NULL,      -- 'YYYY-MM-DD' format
  metric_name TEXT NOT NULL,
  value REAL,
  available_date TEXT NOT NULL,        -- ISO timestamp or 'YYYY-MM-DDTHH:MM:SSZ'
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_normalized_source_date ON normalized_monthly(source, measurement_date);
```

<!-- Existing metric names that MUST be matched exactly -->
```
fcsa-demographics source:
  dubai|dsc_total_population        (value: 4248200.0, date: 2024-01-01)
  dubai|dsc_population_growth_pct   (value: 6.9, date: 2024-01-01)
  dubai|dsc_working_age_pct         (value: 69.2, date: 2024-01-01)

dxb-passengers source:
  dubai|dxb_annual_passengers       (value: 95200000.0, date: 2025-01-01)
  dubai|dxb_yoy_growth_pct          (value: 3.1, date: 2025-01-01)
  dubai|dxb_flight_movements        (value: 454800.0, date: 2025-01-01)
  dubai|dxb_q4_passengers           (value: 25100000.0, date: 2025-10-01)
  dubai|dxb_busiest_month_passengers (value: 8700000.0, date: 2025-12-01)
  dubai|dxb_top_market_passengers   (value: 11900000.0, date: 2025-01-01)

mohre-permits source:
  uae|mohre_emiratisation_yearly    (2021-2025, 5 rows)
  uae|mohre_emiratisation_count     (2025-01-01)
  uae|mohre_workforce_growth_pct    (2025-01-01)
  uae|mohre_establishment_growth_pct (2025-01-01)
  uae|mohre_skilled_worker_growth_pct (2025-01-01)
  uae|mohre_female_leadership_pct   (2025-01-01)
  uae|mohre_youth_workforce_pct     (2025-01-01)

dpworld source:
  dubai|jebel_ali_container_throughput_mn_teu  (value: 15.5, date: 2024-01-01)
  dubai|jebel_ali_breakbulk_cargo_mn_tonnes    (value: 5.4, date: 2024-01-01)
```

<!-- Raw data file locations (confirmed existing) -->
```
DSC PDF:   /opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf
MOHRE JSON: /opt/lobsec/data/raw/mohre-permits/2026-03-17.json
DP World HTML: /opt/lobsec/data/raw/jebel-ali-port/2026-03-16.html
DXB JSON:  /opt/lobsec/data/raw/dxb-passengers/2026-03-17.json (2025 only)
```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Create backfill package with shared helper + DSC + MOHRE + DP World scripts</name>
  <files>
    packages/uae-re/python/uae_re/backfill/__init__.py
    packages/uae-re/python/uae_re/backfill/backfill_demographics.py
    packages/uae-re/python/uae_re/backfill/backfill_mohre.py
    packages/uae-re/python/uae_re/backfill/backfill_dpworld.py
  </files>
  <action>
    Create `packages/uae-re/python/uae_re/backfill/` directory and 4 files:

    **__init__.py** -- Shared helper function:
    ```python
    import sqlite3

    DB_PATH = "/opt/lobsec/data/uae-re.db"

    def insert_metric(db: sqlite3.Connection, source: str, date: str, metric: str, value: float, available_date: str):
        """Idempotent upsert: DELETE existing + INSERT new for source+date+metric."""
        db.execute(
            "DELETE FROM normalized_monthly WHERE source=? AND measurement_date=? AND metric_name=?",
            (source, date, metric)
        )
        db.execute(
            "INSERT INTO normalized_monthly (source, measurement_date, metric_name, value, available_date) VALUES (?,?,?,?,?)",
            (source, date, metric, value, available_date)
        )
    ```

    **backfill_demographics.py** (BACK-01):
    - Open `/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf` with pdfplumber
    - Page 2 table: Find the "Total" row, extract ALL large numbers (>1,000,000)
    - Map to years: index 0=2022 (3,718,000), index 1=2023 (3,974,300), index 2=2024 (4,248,200)
    - For each year, insert `dubai|dsc_total_population` with measurement_date=`{year}-01-01`
    - Calculate growth_pct between consecutive years: 2023 growth = (3,974,300-3,718,000)/3,718,000*100 = 6.9%, 2024 growth = (4,248,200-3,974,300)/3,974,300*100 = 6.9%
    - Insert `dubai|dsc_population_growth_pct` for 2023 and 2024 (NOT 2022 -- no 2021 data available)
    - For 2024 only, working_age_pct already exists (69.2) -- do NOT re-extract from page 4 for older years since the age table only shows 2024 data
    - available_date: `{year+1}-01-15T00:00:00Z` (approximate publication date of following year's bulletin)
    - Source name: `fcsa-demographics` (MUST match exactly)
    - Print summary: how many rows inserted, which years
    - Expected: 5 new rows (3 population + 2 growth_pct)

    **backfill_mohre.py** (BACK-03):
    - MOHRE already has 5 emiratisation_yearly rows (2021-2025) and 6 stat_card metrics for 2025
    - Open `/opt/lobsec/data/raw/mohre-permits/2026-03-17.json`, parse as JSON array
    - From stat_cards: Extract comparative prior-year values. The stat card text contains phrases like "12.4% compared to 10.9% in 2024" -- extract the "10.9%" and "2024" to create a 2024 row for `uae|mohre_workforce_growth_pct`
    - For EACH stat card, look for pattern: `([\d,.]+)\s*%?\s*compared to\s*([\d,.]+)\s*%?\s*in\s*(\d{4})`
    - Map each stat card label to its metric name (same mapping as normalize_mohre.py):
      - "workforce growth" -> uae|mohre_workforce_growth_pct
      - "establishment growth" -> uae|mohre_establishment_growth_pct
      - etc.
    - Insert each extracted prior-year value with measurement_date=`{prior_year}-01-01`
    - Charts 0, 2, 4, 6 are unnamed -- DO NOT extract (per Phase 13 decision: "Only extract Emiratisation chart")
    - available_date: `2026-03-17T00:00:00Z` (date we scraped the observatory)
    - Source name: `mohre-permits`
    - Expected: 3-6 new rows (comparative values for 2024)

    **backfill_dpworld.py** (BACK-05):
    - Open `/opt/lobsec/data/raw/jebel-ali-port/2026-03-16.html`
    - Find `<script id="__NEXT_DATA__" type="application/json">` and parse the JSON
    - Navigate: `data['props']['pageProps']['componentProps']` -> find key containing `feedData` -> parse feedData JSON -> `channel.item` array (446 items)
    - For each item, search description (strip HTML tags + &nbsp;) for pattern: `Jebel Ali\s*\(?UAE\)?\s*handled\s*([\d.]+)\s*million\s*TEU`
    - Only keep matches where TEU > 10.0 (full-year figures, not quarterly)
    - Determine year: article pubDate year minus 1 (published in year N+1 about year N results)
    - For known HIGH-confidence values, hardcode as fallback if RSS parsing misses them:
      - 2019: 14.1, 2021: 13.7, 2022: 14.0, 2024: 15.5
    - For MEDIUM-confidence calculated values, include but flag:
      - 2020: 13.5 (H1=6.7 + estimated H2=6.8), 2023: 14.5 (2024 was "up 1M on previous year")
    - Insert `dubai|jebel_ali_container_throughput_mn_teu` for each year
    - measurement_date: `{year}-01-01`
    - available_date: use the RSS item pubDate (or `{year+1}-02-15T00:00:00Z` as fallback)
    - Source name: `dpworld`
    - DO NOT touch the existing 2024 breakbulk_cargo row
    - Expected: 5-6 new rows (2019-2023 throughput, 2024 already exists)

    Run all 3 scripts via the analytics-venv Python:
    ```bash
    /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_demographics
    /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_mohre
    /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_dpworld
    ```

    IMPORTANT: The analytics-venv PYTHONPATH must include the package. Either run from within `packages/uae-re/python/` or set `PYTHONPATH=/root/lobsec/packages/uae-re/python`. Check how Phase 13 normalizers were deployed (they were copied to `/opt/lobsec/plugins/lobsec-uae-re/python/`). For backfill scripts, run directly from the dev directory since these are one-time scripts.
  </action>
  <verify>
    <automated>
    cd /root/lobsec/packages/uae-re/python && \
    PYTHONPATH=/root/lobsec/packages/uae-re/python /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_demographics && \
    PYTHONPATH=/root/lobsec/packages/uae-re/python /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_mohre && \
    PYTHONPATH=/root/lobsec/packages/uae-re/python /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_dpworld && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT source, metric_name, measurement_date, value FROM normalized_monthly WHERE source IN ('fcsa-demographics','mohre-permits','dpworld') ORDER BY source, metric_name, measurement_date;"
    </automated>
  </verify>
  <done>
    - fcsa-demographics has population rows for 2022, 2023, 2024 (minimum 5 rows: 3 population + 2 growth)
    - mohre-permits has comparative 2024 stat card values alongside existing 2021-2025 emiratisation series (total 14+ rows)
    - dpworld has container throughput for 2019-2024 (minimum 6 rows)
    - All metric names match existing DB patterns exactly
    - Scripts are idempotent (re-running produces same result)
  </done>
</task>

<task type="auto">
  <name>Task 2: Create DXB historical backfill script (download press releases + parse)</name>
  <files>
    packages/uae-re/python/uae_re/backfill/backfill_dxb.py
  </files>
  <action>
    Create `packages/uae-re/python/uae_re/backfill/backfill_dxb.py` (BACK-02):

    This script downloads 3 press release pages from Dubai Airports media site and extracts annual passenger data for 2022, 2023, 2024.

    **Known data from research (verified via WebFetch):**
    | Year | Annual Pax | Q4 Pax | Flight Movements | Cargo |
    |------|-----------|---------|------------------|-------|
    | 2022 | 66,069,981 | 19,729,155 | 343,339 | -- |
    | 2023 | 86,994,365 | 22,400,000 | -- | 1.8M tonnes |
    | 2024 | 92,300,000 | -- | 440,300 | 2.2M tonnes |

    **Press release URLs:**
    - 2022: `https://media.dubaiairports.ae/dxb-has-a-banner-year-with-annual-traffic-exceeding-66m-passengers-in-2022/`
    - 2023: `https://media.dubaiairports.ae/dxb-smashes-targets-with-87-million-guests-in-2023-rising-317-from-previous-year/`
    - 2024: `https://media.dubaiairports.ae/dxb-records-highest-annual-traffic-in-2024-celebrating-a-decade-as-the-worlds-busiest-international-airport/`

    **Implementation approach:**
    1. Use `requests` (already in analytics-venv) to download each press release page
    2. Strip HTML tags to get plain text
    3. Extract metrics using regex patterns adapted from normalize_dxb.py:
       - Annual passengers: regex for `([\d,]+)\s*passengers` or `([\d.]+)\s*million\s*(guests|passengers)` -- try exact number first (66,069,981), fall back to "66 million"
       - YoY growth: `([\d.]+)\s*%` near "growth/increase/rise/up"
       - Flight movements: `([\d,]+)\s*flight\s*movements`
       - Q4 passengers: `Q4.*?([\d.]+)\s*million` or `fourth quarter.*?([\d.]+)\s*million`
    4. If download fails (403/timeout), fall back to hardcoded known values listed above. This is a ONE-TIME backfill script -- the values are verified historical facts.
    5. Insert into normalized_monthly using shared `insert_metric()`:
       - Source: `dxb-passengers`
       - measurement_date: `{year}-01-01` for annual metrics, `{year}-10-01` for Q4
       - Metric names: MUST match existing patterns:
         - `dubai|dxb_annual_passengers` (value in raw count, e.g., 66069981)
         - `dubai|dxb_yoy_growth_pct`
         - `dubai|dxb_flight_movements`
         - `dubai|dxb_q4_passengers`
       - available_date: approximate press release date (`{year+1}-01-20T00:00:00Z`)

    **YoY growth calculation:**
    - 2022: Cannot calculate (no 2021 data in scope). Omit.
    - 2023: (86,994,365 - 66,069,981) / 66,069,981 * 100 = 31.7%
    - 2024: (92,300,000 - 86,994,365) / 86,994,365 * 100 = 6.1%

    **DO NOT fabricate monthly data from annual figures.** Store as annual observations (YYYY-01-01).

    Run the script:
    ```bash
    PYTHONPATH=/root/lobsec/packages/uae-re/python /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_dxb
    ```

    Expected: 8-12 new rows (3 years x 2-4 metrics each).
  </action>
  <verify>
    <automated>
    cd /root/lobsec/packages/uae-re/python && \
    PYTHONPATH=/root/lobsec/packages/uae-re/python /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_dxb && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT metric_name, measurement_date, value FROM normalized_monthly WHERE source='dxb-passengers' ORDER BY metric_name, measurement_date;"
    </automated>
  </verify>
  <done>
    - dxb-passengers has annual_passengers rows for 2022, 2023, 2024, 2025 (4 years)
    - At least 8 total DXB rows spanning 2022-2025 (success criteria: 12+ observations spanning 2022-2024 -- counting all metric types across all years)
    - All metric names match existing patterns exactly (dubai|dxb_*)
    - YoY growth calculated for 2023 and 2024
    - Script handles download failures gracefully (falls back to hardcoded known values)
  </done>
</task>

</tasks>

<verification>
After both tasks complete, verify all 4 sources meet their success criteria:

```bash
# DSC: 3 years of population
sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='fcsa-demographics' AND metric_name='dubai|dsc_total_population' AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01');"
# Expected: 3

# DXB: 12+ observations spanning 2022-2024
sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='dxb-passengers' AND measurement_date >= '2022-01-01' AND measurement_date <= '2024-12-31';"
# Expected: >= 8 (3 years x 2-4 metrics)

# MOHRE: 16+ observations spanning 2021-2025
sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='mohre-permits' AND measurement_date >= '2021-01-01' AND measurement_date <= '2025-12-31';"
# Expected: >= 14 (5 emiratisation + 6 stat_cards 2025 + 3+ comparatives 2024)

# DP World: 3+ annual throughput rows covering 2022-2024
sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='dpworld' AND metric_name='dubai|jebel_ali_container_throughput_mn_teu' AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01');"
# Expected: 3
```
</verification>

<success_criteria>
1. fcsa-demographics contains population rows for 2022, 2023, 2024 (3 total_population + 2 growth_pct = 5 new rows minimum)
2. dxb-passengers contains annual_passengers for 2022, 2023, 2024 plus additional metrics (8+ new rows)
3. mohre-permits has 14+ total rows spanning 2021-2025 (existing 11 + 3+ new comparative rows)
4. dpworld has container_throughput_mn_teu for 2019-2024 (5+ new rows, 2024 already existed)
5. All backfill scripts are idempotent (re-running produces identical DB state)
6. No existing rows corrupted (2025 DXB data, 2024 DSC working_age_pct unchanged)
</success_criteria>

<output>
After completion, create `.planning/phases/14-historical-backfill/14-01-SUMMARY.md`
</output>
