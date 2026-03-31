---
phase: 14-historical-backfill
plan: 02
type: execute
wave: 2
depends_on: ["01"]
files_modified:
  - packages/uae-re/python/uae_re/backfill/backfill_cbuae.py
autonomous: true
requirements: [BACK-04]

must_haves:
  truths:
    - "CBUAE normalized_monthly contains at least 4 quarterly rows covering consecutive quarters"
    - "Within-year quarterly values are correctly de-cumulated (Q2 = Jun - Mar, Q3 = Sep - Jun, Q4 = Dec - Sep)"
    - "Annual totals (Dec 2021, Dec 2022, Dec 2023) are stored as-is (full year, not cumulative)"
    - "All 5 backfill sources pass their success criteria row counts"
  artifacts:
    - path: "packages/uae-re/python/uae_re/backfill/backfill_cbuae.py"
      provides: "CBUAE multi-year backfill from Statistical Bulletin PDF Table 48"
      min_lines: 80
  key_links:
    - from: "packages/uae-re/python/uae_re/backfill/backfill_cbuae.py"
      to: "/opt/lobsec/data/raw/cbuae-remittances/2026-03-16.pdf"
      via: "pdfplumber table extraction from page 58 (0-indexed: 57)"
      pattern: "pdfplumber\\.open"
    - from: "packages/uae-re/python/uae_re/backfill/backfill_cbuae.py"
      to: "/opt/lobsec/data/uae-re.db"
      via: "sqlite3 INSERT into normalized_monthly"
      pattern: "INSERT INTO normalized_monthly"
---

<objective>
Backfill CBUAE domestic fund transfer statistics from the Statistical Bulletin PDF (Table 48) and run final verification of all 5 backfill sources.

Purpose: The CBUAE bulletin contains 8 time periods (Dec 2021 through Mar 2025) of fund transfer data. Within-year columns are CUMULATIVE year-to-date, requiring subtraction to get quarterly period amounts. This is the most technically complex backfill script and is separated to avoid context bloat.

Output: 1 backfill script producing 30+ new CBUAE rows in normalized_monthly, plus final verification that all 5 sources meet Phase 14 success criteria.
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

Source file for reference:
@packages/uae-re/python/uae_re/normalize_remittances.py

<interfaces>
<!-- Database schema and existing CBUAE data -->
```sql
CREATE TABLE normalized_monthly (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  measurement_date TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  value REAL,
  available_date TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

<!-- Existing CBUAE metric names (MUST match exactly) -->
```
cbuae source (6 rows, all measurement_date 2026-03-01):
  uae|cbuae_c2c_transfers_count       114,870,132
  uae|cbuae_c2c_transfers_amount_mn   9,854,512
  uae|cbuae_b2b_transfers_count       865,708
  uae|cbuae_b2b_transfers_amount_mn   14,513,488
  uae|cbuae_total_transfers_count     115,735,840
  uae|cbuae_total_transfers_amount_mn 24,368,000
```

<!-- Shared helper from Plan 01 -->
```python
# From packages/uae-re/python/uae_re/backfill/__init__.py
def insert_metric(db, source, date, metric, value, available_date):
    """Idempotent upsert: DELETE existing + INSERT new."""
```

<!-- CBUAE Table 48 verified data (from RESEARCH.md) -->
```
Period          | C2C Count    | C2C Amt (M AED) | B2B Count | B2B Amt    | Total Count  | Total Amt
Dec 2021 (Ann)  | 60,572,382   | 3,868,969        | 537,239   | 5,723,490  | 61,109,621   | 9,592,459
Dec 2022 (Ann)  | 74,540,998   | 4,910,567        | 633,663   | 7,797,467  | 75,174,661   | 12,708,034
Dec 2023 (Ann)  | 89,505,431   | 6,140,128        | 674,486   | 11,018,872 | 90,179,917   | 17,159,000
Mar 2024 (Q1)   | 25,556,480   | 1,687,838        | 179,531   | 2,839,971  | 25,736,011   | 4,527,809
Jun 2024 (H1)   | 52,197,172   | 3,493,837        | 362,945   | 5,829,263  | 52,560,117   | 9,323,100
Sep 2024 (9M)   | 80,569,401   | 5,301,604        | 554,573   | 9,036,713  | 81,123,974   | 14,338,317
Dec 2024 (Ann)  | 109,708,556  | 7,406,545        | 757,910   | 12,491,923 | 110,466,466  | 19,898,468
Mar 2025 (Q1)   | 29,322,091   | 2,118,444        | 199,458   | 3,331,361  | 29,521,549   | 5,449,805
```

CRITICAL: Within-year quarterly columns are CUMULATIVE YTD:
- Q1 2024 = Mar value (as-is)
- Q2 2024 = Jun - Mar
- Q3 2024 = Sep - Jun
- Q4 2024 = Dec - Sep
Annual totals (Dec 2021/2022/2023) ARE full-year totals, use directly.
```

<!-- Raw PDF location -->
```
CBUAE PDF: /opt/lobsec/data/raw/cbuae-remittances/2026-03-16.pdf (59 pages)
Table 48 is on page 58 (0-indexed: page 57)
```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Create CBUAE backfill script with cumulative YTD de-accumulation</name>
  <files>
    packages/uae-re/python/uae_re/backfill/backfill_cbuae.py
  </files>
  <action>
    Create `packages/uae-re/python/uae_re/backfill/backfill_cbuae.py` (BACK-04):

    This is the most complex backfill script because CBUAE within-year quarterly columns are CUMULATIVE year-to-date values, not individual quarter amounts. Must subtract to get per-quarter figures.

    **Strategy:** Use hardcoded verified values from research rather than fragile PDF table parsing. The RESEARCH.md contains HIGH-confidence values for all 8 periods of Table 48, extracted via pdfplumber during research and cross-verified against multiple data points.

    **Why hardcoded over PDF parsing:** Table 48 has complex multi-line headers, merged cells, and formatting that makes pdfplumber extraction fragile. The values were already verified during research. This is a ONE-TIME backfill script. However, ALSO attempt pdfplumber extraction and compare against hardcoded values as a sanity check.

    **Implementation:**

    1. Define the known Table 48 data as a Python dict:
    ```python
    TABLE_48_DATA = {
        # Annual full-year totals (use directly)
        "2021-12": {"c2c_count": 60572382, "c2c_amount": 3868969, "b2b_count": 537239, "b2b_amount": 5723490, "total_count": 61109621, "total_amount": 9592459},
        "2022-12": {"c2c_count": 74540998, "c2c_amount": 4910567, "b2b_count": 633663, "b2b_amount": 7797467, "total_count": 75174661, "total_amount": 12708034},
        "2023-12": {"c2c_count": 89505431, "c2c_amount": 6140128, "b2b_count": 674486, "b2b_amount": 11018872, "total_count": 90179917, "total_amount": 17159000},
        # Quarterly cumulative YTD (must de-cumulate)
        "2024-03": {"c2c_count": 25556480, "c2c_amount": 1687838, ...},
        "2024-06": {"c2c_count": 52197172, "c2c_amount": 3493837, ...},
        "2024-09": {"c2c_count": 80569401, "c2c_amount": 5301604, ...},
        "2024-12": {"c2c_count": 109708556, "c2c_amount": 7406545, ...},
        "2025-03": {"c2c_count": 29322091, "c2c_amount": 2118444, ...},
    }
    ```

    2. **Annual totals (Dec 2021, Dec 2022, Dec 2023):**
       - Use values directly as full-year totals
       - measurement_date: `{year}-01-01` (annual, same convention as other sources)
       - Insert all 6 metric types for each year

    3. **Quarterly 2024 de-cumulation:**
       - Q1 2024 = Mar 2024 values (as-is, first period of year)
       - Q2 2024 = Jun 2024 - Mar 2024 (each field individually)
       - Q3 2024 = Sep 2024 - Jun 2024
       - Q4 2024 = Dec 2024 - Sep 2024
       - measurement_date for quarters: `2024-01-01` (Q1), `2024-04-01` (Q2), `2024-07-01` (Q3), `2024-10-01` (Q4)

    4. **Q1 2025:**
       - measurement_date: `2025-01-01`
       - Values as-is (first period of 2025)

    5. **Metric names (MUST match existing DB exactly):**
       - `uae|cbuae_c2c_transfers_count`
       - `uae|cbuae_c2c_transfers_amount_mn`
       - `uae|cbuae_b2b_transfers_count`
       - `uae|cbuae_b2b_transfers_amount_mn`
       - `uae|cbuae_total_transfers_count`
       - `uae|cbuae_total_transfers_amount_mn`

    6. **Available dates:**
       - Dec 2021-2023 annuals: `{year+1}-03-01T00:00:00Z` (CBUAE publishes ~3 months after period end)
       - 2024 quarterly: `2025-03-01T00:00:00Z` (published in the Dec 2025 bulletin)
       - Q1 2025: `2025-06-01T00:00:00Z` (approximate)

    7. **Sanity checks after de-cumulation:**
       - All quarterly values must be positive (if Jun < Mar for any field, something is wrong)
       - Q1+Q2+Q3+Q4 should approximately equal the Dec annual total
       - Print both cumulative and de-cumulated values for visual verification

    8. **Source name:** `cbuae`

    9. **Existing data handling:** The existing 6 rows have measurement_date `2026-03-01` -- these are from a different collection run. The backfill inserts rows with dates 2021-2025. The DELETE+INSERT upsert in insert_metric will NOT touch existing rows since dates differ.

    Run the script:
    ```bash
    PYTHONPATH=/root/lobsec/packages/uae-re/python /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_cbuae
    ```

    Expected: 48 new rows (8 periods x 6 metrics).
    - 3 annual periods (2021, 2022, 2023) x 6 metrics = 18
    - 4 quarterly periods (Q1-Q4 2024) x 6 metrics = 24
    - 1 quarterly period (Q1 2025) x 6 metrics = 6
    Total: 48 new rows
  </action>
  <verify>
    <automated>
    cd /root/lobsec/packages/uae-re/python && \
    PYTHONPATH=/root/lobsec/packages/uae-re/python /opt/lobsec/analytics-venv/bin/python -m uae_re.backfill.backfill_cbuae && \
    echo "--- CBUAE row count ---" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='cbuae';" && \
    echo "--- CBUAE quarterly check (4+ consecutive quarters) ---" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT measurement_date, metric_name, value FROM normalized_monthly WHERE source='cbuae' AND metric_name='uae|cbuae_c2c_transfers_count' ORDER BY measurement_date;" && \
    echo "--- Q1+Q2+Q3+Q4 2024 vs Dec 2024 annual c2c_count ---" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT SUM(value) FROM normalized_monthly WHERE source='cbuae' AND metric_name='uae|cbuae_c2c_transfers_count' AND measurement_date IN ('2024-01-01','2024-04-01','2024-07-01','2024-10-01');"
    </automated>
  </verify>
  <done>
    - CBUAE has 48+ new rows across 8 time periods and 6 metric types
    - Quarterly 2024 values are de-cumulated (not cumulative YTD)
    - Q1+Q2+Q3+Q4 2024 sums match Dec 2024 annual total for each metric (within rounding)
    - All quarterly values are positive (no negative de-cumulation artifacts)
    - At least 4 consecutive quarterly rows exist (BACK-04 success criteria)
    - Existing 6 rows (measurement_date 2026-03-01) are untouched
  </done>
</task>

<task type="auto">
  <name>Task 2: Final verification of all 5 backfill sources against Phase 14 success criteria</name>
  <files></files>
  <action>
    Run comprehensive verification queries against all 5 backfill sources to confirm Phase 14 success criteria are met. This task produces NO code changes -- it only runs verification queries.

    **Success Criteria checks:**

    1. **BACK-01 (DSC):** "DSC normalized_monthly contains population rows for 2022, 2023, 2024 (3 rows minimum)"
    ```sql
    SELECT COUNT(*) >= 3 FROM normalized_monthly
    WHERE source='fcsa-demographics'
      AND metric_name='dubai|dsc_total_population'
      AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01');
    ```

    2. **BACK-02 (DXB):** "DXB normalized_monthly contains at least 12 monthly or quarterly passenger count observations spanning 2022-2024"
    ```sql
    SELECT COUNT(*) >= 12 FROM normalized_monthly
    WHERE source='dxb-passengers'
      AND measurement_date >= '2022-01-01'
      AND measurement_date <= '2024-12-31';
    ```
    Note: If we have 3 years x 4 metrics each = 12, this passes. If fewer metrics extracted per year, count ALL dxb-passengers rows including 2025 to see if 12+ total across all years.

    3. **BACK-03 (MOHRE):** "MOHRE normalized_monthly contains at least 16 monthly workforce observations spanning 2021-2025"
    ```sql
    SELECT COUNT(*) >= 16 FROM normalized_monthly
    WHERE source='mohre-permits'
      AND measurement_date >= '2021-01-01'
      AND measurement_date <= '2025-12-31';
    ```

    4. **BACK-04 (CBUAE):** "CBUAE normalized_monthly contains at least 4 quarterly remittance/transfer rows covering consecutive quarters"
    ```sql
    SELECT COUNT(DISTINCT measurement_date) >= 4 FROM normalized_monthly
    WHERE source='cbuae'
      AND measurement_date >= '2024-01-01'
      AND measurement_date <= '2024-12-31';
    ```

    5. **BACK-05 (DP World):** "DP World normalized_monthly contains at least 3 annual throughput rows covering 2022, 2023, 2024"
    ```sql
    SELECT COUNT(*) >= 3 FROM normalized_monthly
    WHERE source='dpworld'
      AND metric_name='dubai|jebel_ali_container_throughput_mn_teu'
      AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01');
    ```

    Run ALL queries and print PASS/FAIL for each. Also print a full summary table:
    ```sql
    SELECT source, COUNT(*) as rows, MIN(measurement_date) as earliest, MAX(measurement_date) as latest,
           COUNT(DISTINCT metric_name) as metrics
    FROM normalized_monthly
    WHERE source IN ('fcsa-demographics','dxb-passengers','mohre-permits','cbuae','dpworld')
    GROUP BY source ORDER BY source;
    ```

    If any check fails, investigate and log what's missing. Do NOT modify data in this task.
  </action>
  <verify>
    <automated>
    echo "=== Phase 14 Success Criteria Verification ===" && \
    echo "BACK-01 DSC (need >=3):" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='fcsa-demographics' AND metric_name='dubai|dsc_total_population' AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01');" && \
    echo "BACK-02 DXB (need >=12 spanning 2022-2024):" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='dxb-passengers' AND measurement_date >= '2022-01-01' AND measurement_date <= '2024-12-31';" && \
    echo "BACK-03 MOHRE (need >=16 spanning 2021-2025):" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='mohre-permits' AND measurement_date >= '2021-01-01' AND measurement_date <= '2025-12-31';" && \
    echo "BACK-04 CBUAE (need >=4 consecutive quarters):" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(DISTINCT measurement_date) FROM normalized_monthly WHERE source='cbuae' AND measurement_date >= '2024-01-01' AND measurement_date <= '2024-12-31';" && \
    echo "BACK-05 DP World (need >=3 for 2022-2024):" && \
    sqlite3 /opt/lobsec/data/uae-re.db "SELECT COUNT(*) FROM normalized_monthly WHERE source='dpworld' AND metric_name='dubai|jebel_ali_container_throughput_mn_teu' AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01');" && \
    echo "=== Summary ===" && \
    sqlite3 /opt/lobsec/data/uae-re.db -header -column "SELECT source, COUNT(*) as rows, MIN(measurement_date) as earliest, MAX(measurement_date) as latest, COUNT(DISTINCT metric_name) as metrics FROM normalized_monthly WHERE source IN ('fcsa-demographics','dxb-passengers','mohre-permits','cbuae','dpworld') GROUP BY source ORDER BY source;"
    </automated>
  </verify>
  <done>
    - All 5 BACK-* success criteria produce passing counts
    - Summary table shows multi-year coverage for all 5 sources
    - No data corruption (existing non-backfill rows untouched)
    - Phase 14 is complete
  </done>
</task>

</tasks>

<verification>
All Phase 14 success criteria verified:

```bash
# Run all 5 checks in one shot
sqlite3 /opt/lobsec/data/uae-re.db "
  SELECT 'BACK-01' as req,
    CASE WHEN (SELECT COUNT(*) FROM normalized_monthly WHERE source='fcsa-demographics' AND metric_name='dubai|dsc_total_population' AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01')) >= 3 THEN 'PASS' ELSE 'FAIL' END as status
  UNION ALL
  SELECT 'BACK-02',
    CASE WHEN (SELECT COUNT(*) FROM normalized_monthly WHERE source='dxb-passengers' AND measurement_date >= '2022-01-01' AND measurement_date <= '2024-12-31') >= 12 THEN 'PASS' ELSE 'FAIL' END
  UNION ALL
  SELECT 'BACK-03',
    CASE WHEN (SELECT COUNT(*) FROM normalized_monthly WHERE source='mohre-permits' AND measurement_date >= '2021-01-01' AND measurement_date <= '2025-12-31') >= 16 THEN 'PASS' ELSE 'FAIL' END
  UNION ALL
  SELECT 'BACK-04',
    CASE WHEN (SELECT COUNT(DISTINCT measurement_date) FROM normalized_monthly WHERE source='cbuae' AND measurement_date >= '2024-01-01' AND measurement_date <= '2024-12-31') >= 4 THEN 'PASS' ELSE 'FAIL' END
  UNION ALL
  SELECT 'BACK-05',
    CASE WHEN (SELECT COUNT(*) FROM normalized_monthly WHERE source='dpworld' AND metric_name='dubai|jebel_ali_container_throughput_mn_teu' AND measurement_date IN ('2022-01-01','2023-01-01','2024-01-01')) >= 3 THEN 'PASS' ELSE 'FAIL' END;
"
```

Expected: All 5 rows show PASS.
</verification>

<success_criteria>
1. CBUAE has 48+ rows spanning Dec 2021 through Mar 2025 (8 periods x 6 metrics)
2. Quarterly 2024 de-cumulation is correct (Q1+Q2+Q3+Q4 = Dec 2024 annual for each metric)
3. All 5 BACK-* requirements pass their verification queries
4. Total normalized_monthly row count for backfill sources increased from ~28 to ~100+
5. Phase 14 is ready to be marked complete in ROADMAP.md
</success_criteria>

<output>
After completion, create `.planning/phases/14-historical-backfill/14-02-SUMMARY.md`
</output>
