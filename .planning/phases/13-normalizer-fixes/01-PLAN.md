# Plan 01: Rewrite DXB Airport Normalizer for HTML Fact File JSON

**Requirement(s):** NORM-06
**Estimated complexity:** Medium
**Depends on:** none

## Goal

Rewrite `normalize_dxb.py` and `dxb_schema.py` to extract passenger metrics from the HTML fact file JSON (paragraphs array with text like "95.2 million guests") instead of the old PDF-based extraction that no longer works.

## Context

The scraper now captures the DXB fact file as an HTML page, saved as JSON at `/opt/lobsec/data/raw/dxb-passengers/2026-03-17.json`. The raw data is a JSON array with one object containing:

```json
[{
  "url": "https://media.dubaiairports.ae/dubai-airports-main-fact-file/",
  "paragraphs": [
    "DXB 2025 Annual Traffic",
    "DXB recorded its highest-ever annual traffic with 95.2 million guests, up 3.1% YoY",
    "Total flight movements reached 454,800",
    "December became the busiest month...with 8.7 million guests",
    "Q4...reaching 25.1 million guests, up 5.9%",
    "Top destination countries: India (11.9m), Saudi Arabia (7.5m), the United Kingdom (6.3m)...",
    ...
  ]
}]
```

The current `normalize_dxb.py` uses pdfplumber on a PDF file and will crash because the raw data is now JSON. The schema `dxb_schema.py` validates a PDF file (checks `.pdf` extension and `%PDF` header) which will also reject the JSON file.

**Bridge protocol (DO NOT CHANGE):**
- stdin: `{"filePath": "/opt/lobsec/data/raw/dxb-passengers/2026-03-17.json", "source": "dxb-passengers", "collectedAt": "2026-03-17T10:00:00.000Z"}`
- stdout: `[{"source": "dxb-passengers", "measurement_date": "2025-01-01", "metric_name": "dubai|dxb_annual_passengers", "value": 95200000, "available_date": "2026-03-17T10:00:00.000Z"}, ...]`

**Metric naming:** Use `dubai|dxb_` prefix (matches existing convention). DXB data is ANNUAL, not monthly -- use `measurement_date = "2025-01-01"` (Jan 1 of the reference year extracted from text).

**CRITICAL PITFALL: DXB data is annual/quarterly, NOT monthly.** Do NOT divide by 12 to fabricate monthly data. Report annual total as one row with measurement_date = Jan 1 of the year. Quarterly data gets measurement_date = start of quarter (Q4 = Oct 1).

## Tasks

### Task 1: Rewrite `dxb_schema.py` to validate JSON input

Replace the PDF validation with JSON validation. The new schema must validate:
- File exists and is readable
- File contains valid JSON
- JSON is a list with at least one object
- Each object has a `paragraphs` key that is a list of strings

**File:** `packages/uae-re/python/uae_re/schemas/dxb_schema.py`

```python
"""
Schema validation for DXB airport data (NORM-06).

DXB data comes from HTML fact file scrape, saved as JSON with paragraphs array.
"""

import json
import os


def validate_dxb_json(file_path: str) -> list[dict]:
    """
    Validate DXB JSON file exists, is readable, and has expected structure.

    Args:
        file_path: Path to JSON file

    Returns:
        Parsed JSON data (list of page objects)

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(file_path, str):
        raise ValueError("file_path must be a string")

    if not os.path.exists(file_path):
        raise ValueError(f"JSON file does not exist: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"File is not valid JSON: {e}")
    except IOError as e:
        raise ValueError(f"Cannot read file: {e}")

    if not isinstance(data, list) or len(data) == 0:
        raise ValueError("DXB JSON must be a non-empty list")

    for i, page in enumerate(data):
        if not isinstance(page, dict):
            raise ValueError(f"Item {i} must be a dict")
        if "paragraphs" not in page:
            raise ValueError(f"Item {i} missing 'paragraphs' key")
        if not isinstance(page["paragraphs"], list):
            raise ValueError(f"Item {i} 'paragraphs' must be a list")

    return data
```

### Task 2: Rewrite `normalize_dxb.py` to parse JSON paragraphs

Complete rewrite. Remove pdfplumber import. Parse paragraphs with regex to extract:

1. **Annual passengers**: "95.2 million guests" -> `dubai|dxb_annual_passengers` = 95200000
2. **YoY growth**: "up 3.1% YoY" -> `dubai|dxb_yoy_growth_pct` = 3.1
3. **Flight movements**: "454,800" -> `dubai|dxb_flight_movements` = 454800
4. **Q4 passengers**: "25.1 million guests" -> `dubai|dxb_q4_passengers` = 25100000
5. **Busiest month passengers**: "8.7 million guests" -> `dubai|dxb_busiest_month_passengers` = 8700000
6. **Top market**: "India (11.9m)" -> `dubai|dxb_top_market_passengers` = 11900000

**File:** `packages/uae-re/python/uae_re/normalize_dxb.py`

Key implementation details:

1. **Import `validate_dxb_json` instead of `validate_dxb_pdf`** -- the schema function now returns parsed data.
2. **Extract reference year from paragraphs** -- look for "2025 Annual Traffic" or "annual traffic" near a 4-digit year. Default to prior year if not found.
3. **Use `measurement_date = "{year}-01-01"` for annual metrics** (Jan 1 of reference year).
4. **Use `measurement_date = "{year}-10-01"` for Q4 data** (start of Q4).
5. **Join all paragraphs into one blob** before regex matching (some metrics may span paragraphs).
6. **Regex patterns** (case-insensitive):
   - Annual passengers: `r'annual\s+traffic\s+(?:with|of)\s+([\d.]+)\s*million\s*(?:guests|passengers)'`
   - YoY growth: `r'up\s+([\d.]+)\s*%\s*(?:y[/-]?o[/-]?y|year.on.year)'`
   - Flight movements: `r'flight\s+movements?\s+(?:reached|totaled|totalled)\s+([\d,]+)'`
   - Q4 passengers: `r'q4.*?([\d.]+)\s*million\s*(?:guests|passengers)'`
   - Busiest month: `r'(?:busiest\s+month|december).*?([\d.]+)\s*million\s*(?:guests|passengers)'`
   - Top market: `r'(?:top\s+destination\s+countries?|top\s+markets?)[:\s]+(\w[\w\s]+?)\s*\(([\d.]+)m\)'`
7. **Sanity check**: annual_passengers must be > 10,000,000 (DXB handles tens of millions per year).
8. **`main()` function**: Read stdin JSON `{filePath, source, collectedAt}`. Call `validate_dxb_json(file_path)` to get parsed data. Concatenate all paragraphs from all pages. Call `normalize_dxb(paragraphs, collected_at)`. Add `source` to each record. Output JSON to stdout.

```python
#!/usr/bin/env python3
"""
DXB airport passengers normalization module.

Reads DXB HTML fact file JSON (paragraphs array) and produces normalized metrics:

Dubai-level metrics:
- dubai|dxb_annual_passengers
- dubai|dxb_yoy_growth_pct
- dubai|dxb_flight_movements
- dubai|dxb_q4_passengers
- dubai|dxb_busiest_month_passengers
- dubai|dxb_top_market_passengers

All metrics include available_date (NORM-02 compliance).
Data is ANNUAL — measurement_date is Jan 1 of the reference year.
"""

import json
import re
import sys
from typing import Any

from .schemas.dxb_schema import validate_dxb_json


def extract_reference_year(text: str) -> int | None:
    """Extract the reference year from DXB fact file text (e.g., '2025 Annual Traffic')."""
    match = re.search(r'(\d{4})\s+annual\s+traffic', text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    # Fallback: look for any 4-digit year near "annual"
    match = re.search(r'annual.*?(\d{4})|(\d{4}).*?annual', text, re.IGNORECASE)
    if match:
        return int(match.group(1) or match.group(2))
    return None


def normalize_dxb(paragraphs: list[str], collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DXB airport fact file paragraphs to annual metrics.

    Args:
        paragraphs: List of text paragraphs from the fact file HTML scrape.
        collected_at: ISO timestamp of collection.

    Returns:
        List of normalized metric records.
    """
    import pandas as pd

    # Join all paragraphs for regex matching
    text = "\n".join(p for p in paragraphs if isinstance(p, str))
    text_lower = text.lower()

    # Determine reference year
    ref_year = extract_reference_year(text)
    if ref_year is None:
        # Fall back to prior year (fact file published in current year for prior year)
        collected = pd.to_datetime(collected_at)
        ref_year = collected.year - 1

    measurement_date = f"{ref_year}-01-01"
    metrics = []

    # 1. Annual passengers: "95.2 million guests"
    annual_match = re.search(
        r'annual\s+traffic\s+(?:with|of)\s+([\d.]+)\s*million\s*(?:guests|passengers)',
        text_lower,
    )
    if annual_match:
        annual_pax = float(annual_match.group(1)) * 1_000_000
        if annual_pax > 10_000_000:  # Sanity check
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dxb_annual_passengers",
                "value": annual_pax,
                "available_date": collected_at,
            })

    # 2. YoY growth: "up 3.1% YoY"
    yoy_match = re.search(
        r'up\s+([\d.]+)\s*%\s*(?:y[/\-]?o[/\-]?y|year.on.year)',
        text_lower,
    )
    if yoy_match:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dxb_yoy_growth_pct",
            "value": float(yoy_match.group(1)),
            "available_date": collected_at,
        })

    # 3. Flight movements: "454,800"
    flight_match = re.search(
        r'flight\s+movements?\s+(?:reached|totale?d)\s+([\d,]+)',
        text_lower,
    )
    if flight_match:
        movements = int(flight_match.group(1).replace(",", ""))
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dxb_flight_movements",
            "value": movements,
            "available_date": collected_at,
        })

    # 4. Q4 passengers: "Q4...25.1 million guests"
    q4_match = re.search(
        r'q4.*?([\d.]+)\s*million\s*(?:guests|passengers)',
        text_lower,
    )
    if q4_match:
        q4_pax = float(q4_match.group(1)) * 1_000_000
        metrics.append({
            "measurement_date": f"{ref_year}-10-01",  # Q4 starts Oct 1
            "metric_name": "dubai|dxb_q4_passengers",
            "value": q4_pax,
            "available_date": collected_at,
        })

    # 5. Busiest month passengers: "8.7 million guests"
    busiest_match = re.search(
        r'(?:busiest\s+month|december).*?([\d.]+)\s*million\s*(?:guests|passengers)',
        text_lower,
    )
    if busiest_match:
        busiest_pax = float(busiest_match.group(1)) * 1_000_000
        metrics.append({
            "measurement_date": f"{ref_year}-12-01",  # December
            "metric_name": "dubai|dxb_busiest_month_passengers",
            "value": busiest_pax,
            "available_date": collected_at,
        })

    # 6. Top market: "India (11.9m)"
    market_match = re.search(
        r'(?:top\s+destination\s+countries?|top\s+markets?)[:\s]+(\w[\w\s]+?)\s*\(([\d.]+)m\)',
        text_lower,
    )
    if market_match:
        top_market_pax = float(market_match.group(2)) * 1_000_000
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dxb_top_market_passengers",
            "value": top_market_pax,
            "available_date": collected_at,
        })

    return metrics


def main() -> None:
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads and validates JSON file, normalizes, and outputs to stdout.
    """
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        # Validate and load JSON file
        data = validate_dxb_json(file_path)

        # Concatenate all paragraphs from all pages
        all_paragraphs = []
        for page in data:
            all_paragraphs.extend(page.get("paragraphs", []))

        # Normalize
        normalized = normalize_dxb(all_paragraphs, collected_at)

        # Add source field to each record
        for record in normalized:
            record["source"] = input_data["source"]

        json.dump(normalized, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Task 3: Verify against actual raw data

Run the rewritten normalizer against the real raw data file on the production server:

```bash
cd /root/lobsec
echo '{"filePath":"/opt/lobsec/data/raw/dxb-passengers/2026-03-17.json","source":"dxb-passengers","collectedAt":"2026-03-17T10:00:00.000Z"}' | \
  /opt/lobsec/analytics-venv/bin/python -m uae_re.normalize_dxb
```

**Expected output:** JSON array with at least 3 records:
- `dubai|dxb_annual_passengers` = 95200000 (measurement_date: 2025-01-01)
- `dubai|dxb_yoy_growth_pct` = 3.1
- `dubai|dxb_flight_movements` = 454800

If any metric is missing, inspect the raw JSON paragraphs and adjust regex patterns.

**Note:** The Python module needs to be importable. Either:
- Set `PYTHONPATH=/root/lobsec/packages/uae-re/python` before running, or
- Run from the correct directory with proper path

```bash
PYTHONPATH=/root/lobsec/packages/uae-re/python \
echo '{"filePath":"/opt/lobsec/data/raw/dxb-passengers/2026-03-17.json","source":"dxb-passengers","collectedAt":"2026-03-17T10:00:00.000Z"}' | \
  /opt/lobsec/analytics-venv/bin/python -m uae_re.normalize_dxb
```

## Verification

1. The normalizer runs without errors against the real raw data file
2. Output contains at least 3 metric records with `source = "dxb-passengers"`
3. `dubai|dxb_annual_passengers` value is approximately 95,200,000
4. All `measurement_date` values use annual format (YYYY-01-01), not monthly
5. No pdfplumber import remains in the file

## Files Modified

- `packages/uae-re/python/uae_re/schemas/dxb_schema.py` (rewrite)
- `packages/uae-re/python/uae_re/normalize_dxb.py` (rewrite)
