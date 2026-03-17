# Plan 04: Verify All 8 Sources + Deploy Normalizer Fixes to Production

**Requirement(s):** NORM-09
**Estimated complexity:** Low
**Depends on:** Plan 01 (DXB), Plan 02 (MOHRE), Plan 03 (DSC)

## Goal

Verify all 8 existing sources have at least 1 row each in normalized_monthly, deploy the three rewritten normalizers to production, run them against real data, and confirm the new rows land in the database.

## Context

**Existing normalized_monthly rows (already confirmed in research):**

| Source (DB name) | Row Count | Status |
|------------------|-----------|--------|
| propertyfinder | 206 | Working |
| khda | 37 | Working |
| adrec | 18 | Working |
| bayt-jobs | 6 | Working |
| cbuae | 6 | Working |
| linkedin-jobs | 6 | Working |
| indeed-jobs | 5 | Working |
| dpworld | 2 | Working |

These 8 sources are already producing normalized_monthly rows. NORM-09 is primarily a verification task.

After Plans 01-03 complete, we also need to verify the 3 rewritten normalizers (DXB, MOHRE, DSC) produce new rows.

**Deployment pattern (from STATE.md):**
- Python normalizers deploy via `cp` to `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/`
- The analytics-venv already has pdfplumber installed
- Restart `lobsec.service` to pick up changes (or the Python bridge spawns fresh processes per call)
- The Python bridge uses subprocess, so code changes take effect on next invocation without service restart

**Database path:** `/opt/lobsec/data/uae-re.db`

## Tasks

### Task 1: Verify existing 8 sources in normalized_monthly

Query the database directly to confirm all 8 sources have rows:

```bash
sudo -u lobsec /opt/lobsec/analytics-venv/bin/python3 -c "
import sqlite3
conn = sqlite3.connect('/opt/lobsec/data/uae-re.db')
cursor = conn.execute('''
    SELECT source, COUNT(*) as row_count,
           MIN(measurement_date) as earliest,
           MAX(measurement_date) as latest
    FROM normalized_monthly
    GROUP BY source
    ORDER BY row_count DESC
''')
print('Source | Rows | Earliest | Latest')
print('-' * 60)
for row in cursor:
    print(f'{row[0]:25s} | {row[1]:4d} | {row[2]} | {row[3]}')
conn.close()
"
```

**Expected:** At least 8 distinct sources, each with >= 1 row. If any source is missing, investigate (but research says all 8 are present).

### Task 2: Deploy rewritten normalizers to production

Copy the 3 rewritten normalizers + 3 rewritten schemas to production:

```bash
# Copy normalizer modules
sudo cp /root/lobsec/packages/uae-re/python/uae_re/normalize_dxb.py \
  /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_dxb.py

sudo cp /root/lobsec/packages/uae-re/python/uae_re/normalize_mohre.py \
  /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_mohre.py

sudo cp /root/lobsec/packages/uae-re/python/uae_re/normalize_demographics.py \
  /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/normalize_demographics.py

# Copy updated schemas
sudo cp /root/lobsec/packages/uae-re/python/uae_re/schemas/dxb_schema.py \
  /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/schemas/dxb_schema.py

sudo cp /root/lobsec/packages/uae-re/python/uae_re/schemas/mohre_schema.py \
  /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/schemas/mohre_schema.py

sudo cp /root/lobsec/packages/uae-re/python/uae_re/schemas/demographics_schema.py \
  /opt/lobsec/plugins/lobsec-uae-re/python/uae_re/schemas/demographics_schema.py

# Fix ownership
sudo chown -R lobsec:lobsec /opt/lobsec/plugins/lobsec-uae-re/python/

# Clear Python bytecode cache (important! old .pyc will mask new code)
sudo find /opt/lobsec/plugins/lobsec-uae-re/python/ -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
```

### Task 3: Run rewritten normalizers against real data on production

Run each normalizer as the lobsec user against real raw data files:

**DXB:**
```bash
echo '{"filePath":"/opt/lobsec/data/raw/dxb-passengers/2026-03-17.json","source":"dxb-passengers","collectedAt":"2026-03-17T10:00:00.000Z"}' | \
sudo -u lobsec PYTHONPATH=/opt/lobsec/plugins/lobsec-uae-re/python \
  /opt/lobsec/analytics-venv/bin/python -m uae_re.normalize_dxb
```

Expected: JSON array with 3+ records including `dubai|dxb_annual_passengers`.

**MOHRE:**
```bash
echo '{"filePath":"/opt/lobsec/data/raw/mohre-permits/2026-03-17.json","source":"mohre-permits","collectedAt":"2026-03-17T10:00:00.000Z"}' | \
sudo -u lobsec PYTHONPATH=/opt/lobsec/plugins/lobsec-uae-re/python \
  /opt/lobsec/analytics-venv/bin/python -m uae_re.normalize_mohre
```

Expected: JSON array with 4+ records including `uae|mohre_workforce_growth_pct`.

**DSC:**
```bash
echo '{"filePath":"/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf","source":"fcsa-demographics","collectedAt":"2026-03-17T10:00:00.000Z"}' | \
sudo -u lobsec PYTHONPATH=/opt/lobsec/plugins/lobsec-uae-re/python \
  /opt/lobsec/analytics-venv/bin/python -m uae_re.normalize_demographics
```

Expected: JSON array with 2-3 records including `dubai|dsc_total_population`.

### Task 4: Insert normalizer output into database and final verification

For each of the 3 new normalizers, take the stdout JSON output and upsert into the database.

The simplest approach: write a small Python script that takes normalizer output and inserts it:

```bash
sudo -u lobsec /opt/lobsec/analytics-venv/bin/python3 -c "
import sqlite3, json, sys

# Run each normalizer and insert results
import subprocess

sources = [
    ('dxb-passengers', '/opt/lobsec/data/raw/dxb-passengers/2026-03-17.json', 'uae_re.normalize_dxb'),
    ('mohre-permits', '/opt/lobsec/data/raw/mohre-permits/2026-03-17.json', 'uae_re.normalize_mohre'),
    ('fcsa-demographics', '/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf', 'uae_re.normalize_demographics'),
]

conn = sqlite3.connect('/opt/lobsec/data/uae-re.db')

for source, file_path, module in sources:
    input_json = json.dumps({
        'filePath': file_path,
        'source': source,
        'collectedAt': '2026-03-17T10:00:00.000Z',
    })

    result = subprocess.run(
        ['/opt/lobsec/analytics-venv/bin/python', '-m', module],
        input=input_json, capture_output=True, text=True,
        env={'PYTHONPATH': '/opt/lobsec/plugins/lobsec-uae-re/python'},
        timeout=60,
    )

    if result.returncode != 0:
        print(f'FAIL {source}: {result.stderr}')
        continue

    records = json.loads(result.stdout)
    print(f'{source}: {len(records)} records')

    for r in records:
        # Delete existing then insert (upsert pattern)
        conn.execute(
            'DELETE FROM normalized_monthly WHERE source=? AND measurement_date=? AND metric_name=?',
            (r['source'], r['measurement_date'], r['metric_name'])
        )
        conn.execute(
            'INSERT INTO normalized_monthly (source, measurement_date, metric_name, value, available_date) VALUES (?, ?, ?, ?, ?)',
            (r['source'], r['measurement_date'], r['metric_name'], r['value'], r['available_date'])
        )

conn.commit()

# Final verification: count all sources
cursor = conn.execute('''
    SELECT source, COUNT(*) as cnt
    FROM normalized_monthly
    GROUP BY source
    ORDER BY cnt DESC
''')
print()
print('=== FINAL VERIFICATION ===')
print('Source | Rows')
print('-' * 40)
source_count = 0
for row in cursor:
    print(f'{row[0]:25s} | {row[1]:4d}')
    source_count += 1

print(f'Total distinct sources: {source_count}')
if source_count >= 11:  # 8 existing + 3 new
    print('NORM-09: PASS (all sources present)')
else:
    print(f'NORM-09: CHECK — expected >= 11 sources, got {source_count}')

conn.close()
"
```

**Note about source name overlap:** The 3 new sources (dxb-passengers, mohre-permits, fcsa-demographics) may or may not already exist in the DB with 0 rows. The final count should be at least 11 distinct sources (8 existing + 3 new). If some of the new sources were already counted in the original 8 (unlikely based on research data), the count may stay at 8 but each must have >= 1 row.

## Verification

1. Database query shows >= 8 distinct sources in normalized_monthly, each with >= 1 row
2. `dxb-passengers` source has rows with `dubai|dxb_annual_passengers` metric
3. `mohre-permits` source has rows with `uae|mohre_workforce_growth_pct` metric
4. `fcsa-demographics` source has rows with `dubai|dsc_total_population` metric
5. All normalizer runs completed without errors on production
6. File ownership on production is `lobsec:lobsec`
7. No `__pycache__` stale bytecode interfering

## Files Modified

- No source files modified (this plan deploys + verifies)
- Production files updated at `/opt/lobsec/plugins/lobsec-uae-re/python/uae_re/` (6 files copied)
