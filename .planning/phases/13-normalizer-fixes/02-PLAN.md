# Plan 02: Rewrite MOHRE Observatory Normalizer for Dashboard JSON

**Requirement(s):** NORM-07
**Estimated complexity:** Medium
**Depends on:** none

## Goal

Rewrite `normalize_mohre.py` and `mohre_schema.py` to extract workforce metrics from the MOHRE Observatory dashboard JSON (stat_cards + chart_labels) instead of the old press-release article format that no longer matches the scraped data.

## Context

The scraper now captures the MOHRE Observatory dashboard as JSON at `/opt/lobsec/data/raw/mohre-permits/2026-03-17.json`. The raw data is a JSON array with one object containing:

```json
[{
  "url": "https://observatory.mohre.gov.ae/en/uae-labour-market-priorities/...",
  "stat_cards": [
    "Statistics Overview...\n12.4 %\n Workforce Growth in 2025\n...",
    "All",
    "Workforce",
    ...
    "7.8 %\n Establishment Growth in 2025\n...",
    "17.4 %\n Percentage of Female Workers in Leadership Positions\n...",
    "176,125\n Total UAE National Employees Working in the Private Sector\n...",
    ...
  ],
  "chart_labels": [
    "(Chart.js config with labels:[\"2021\",...,\"2025\"] data:[45.4,...,92.6])",
    ...
    "Yearly Total of UAE Nationals Working in the Private Sector(Chart.js with data:[37569,...,176255])",
    ...
  ],
  "paragraphs": [...],
  "tables": null
}]
```

The current `normalize_mohre.py` expects `data["articles"]` with `full_text` fields and extracts "work permits" via regex. This completely fails on the new dashboard format which has no articles. The schema `mohre_schema.py` requires `scrapedAt`, `source_url`, `articles` list -- all wrong.

**Bridge protocol (DO NOT CHANGE):**
- stdin: `{"filePath": "/opt/lobsec/data/raw/mohre-permits/2026-03-17.json", "source": "mohre-permits", "collectedAt": "2026-03-17T10:00:00.000Z"}`
- stdout: `[{"source": "mohre-permits", "measurement_date": "2025-01-01", "metric_name": "uae|mohre_workforce_growth_pct", "value": 12.4, "available_date": "..."}, ...]`

**Metric prefix:** Use `uae|mohre_` (UAE-level, not Dubai-specific -- MOHRE is a federal ministry).

**CRITICAL PITFALLS:**
1. **Stat cards have duplicates** -- cards 0 and 6 may both contain "12.4% Workforce Growth". De-duplicate by metric label.
2. **Chart data is YEARLY** (labels: 2021-2025), not monthly. Use annual measurement_dates.
3. **Only extract chart 8** (Emiratisation yearly totals) which is clearly labeled. Other charts are ambiguous.

## Tasks

### Task 1: Rewrite `mohre_schema.py` to validate dashboard JSON

Replace the article-based validation with dashboard validation. The new schema must validate:
- File exists and is readable
- File contains valid JSON
- JSON is a list with at least one object
- Each object has `stat_cards` (list of strings) and `chart_labels` (list of strings)

**File:** `packages/uae-re/python/uae_re/schemas/mohre_schema.py`

```python
"""
Schema validation for MOHRE Observatory dashboard data (NORM-07).

MOHRE data comes from observatory.mohre.gov.ae dashboard scrape,
saved as JSON with stat_cards and chart_labels arrays.
"""

import json
import os


def validate_mohre_json(file_path: str) -> list[dict]:
    """
    Validate MOHRE JSON file exists, is readable, and has expected structure.

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
        raise ValueError("MOHRE JSON must be a non-empty list")

    for i, page in enumerate(data):
        if not isinstance(page, dict):
            raise ValueError(f"Item {i} must be a dict")
        if "stat_cards" not in page:
            raise ValueError(f"Item {i} missing 'stat_cards' key")
        if not isinstance(page["stat_cards"], list):
            raise ValueError(f"Item {i} 'stat_cards' must be a list")
        if "chart_labels" not in page:
            raise ValueError(f"Item {i} missing 'chart_labels' key")
        if not isinstance(page["chart_labels"], list):
            raise ValueError(f"Item {i} 'chart_labels' must be a list")

    return data
```

**IMPORTANT:** The function signature changes from `validate_mohre_json(data: dict)` (taking in-memory dict) to `validate_mohre_json(file_path: str)` (taking file path, loading internally). This matches the DXB and KHDA schema pattern where validation + loading happen together.

### Task 2: Rewrite `normalize_mohre.py` to parse stat_cards + chart_labels

Complete rewrite. The new normalizer extracts metrics from two data sources within the JSON:

**A. Stat Cards Extraction:**
Pattern in stat_cards: `"12.4 %\n Workforce Growth in 2025\n..."`

For each card, use regex: `r'([\d,]+\.?\d*)\s*%?\s*\n\s+(.*?)(?:\n|$)'`

De-duplicate by tracking seen labels. Extract:
- `workforce growth` -> `uae|mohre_workforce_growth_pct` (percentage)
- `establishment growth` -> `uae|mohre_establishment_growth_pct` (percentage)
- `total uae national` -> `uae|mohre_emiratisation_count` (integer)
- `skilled worker` + `growth` -> `uae|mohre_skilled_worker_growth_pct` (percentage)
- `female workers` + `leadership` -> `uae|mohre_female_leadership_pct` (percentage)
- `youth workforce` -> `uae|mohre_youth_workforce_pct` (percentage)

Extract the reference year from stat_card text (e.g., "in 2025"). measurement_date = `{year}-01-01`.

**B. Chart Labels Extraction (Emiratisation time series only):**
Find chart_labels entries containing "Yearly Total of UAE Nationals" (chart index 8 in current data).
Parse: `labels:["2021","2022","2023","2024","2025"]` and `data:[37569,60136,91773,131883,176255]`

For each year-value pair, emit `uae|mohre_emiratisation_yearly` with measurement_date = `{year}-01-01`.

Only extract chart 8. Other charts are ambiguous (unnamed indices).

**File:** `packages/uae-re/python/uae_re/normalize_mohre.py`

Key implementation:

```python
#!/usr/bin/env python3
"""
MOHRE Observatory normalization module.

Reads MOHRE Observatory dashboard JSON (stat_cards + chart_labels) and produces
normalized annual metrics:

UAE-level metrics (from stat_cards):
- uae|mohre_workforce_growth_pct
- uae|mohre_establishment_growth_pct
- uae|mohre_emiratisation_count
- uae|mohre_skilled_worker_growth_pct
- uae|mohre_female_leadership_pct
- uae|mohre_youth_workforce_pct

UAE-level metrics (from chart_labels):
- uae|mohre_emiratisation_yearly (time series 2021-2025)

All metrics include available_date (NORM-02 compliance).
Data is ANNUAL — measurement_date is Jan 1 of the reference year.
"""

import json
import re
import sys
from typing import Any

from .schemas.mohre_schema import validate_mohre_json


def extract_stat_card_metrics(
    stat_cards: list[str], collected_at: str
) -> list[dict[str, Any]]:
    """Extract metrics from MOHRE stat_cards text blocks."""
    metrics = []
    seen_labels: set[str] = set()

    # Determine reference year from cards
    ref_year = None
    for card in stat_cards:
        year_match = re.search(r'in\s+(\d{4})', card)
        if year_match:
            ref_year = int(year_match.group(1))
            break

    if ref_year is None:
        import pandas as pd
        ref_year = pd.to_datetime(collected_at).year

    measurement_date = f"{ref_year}-01-01"

    # Metric mapping: (label keyword(s), metric_name, is_count)
    METRIC_MAP = [
        (["workforce growth"], "uae|mohre_workforce_growth_pct", False),
        (["establishment growth"], "uae|mohre_establishment_growth_pct", False),
        (["total uae national"], "uae|mohre_emiratisation_count", True),
        (["skilled worker", "growth"], "uae|mohre_skilled_worker_growth_pct", False),
        (["female workers", "leadership"], "uae|mohre_female_leadership_pct", False),
        (["youth workforce"], "uae|mohre_youth_workforce_pct", False),
    ]

    for card in stat_cards:
        if not isinstance(card, str) or len(card.strip()) < 3:
            continue

        # Pattern: "176,125\n Total UAE National Employees..." or "12.4 %\n Workforce Growth..."
        matches = re.findall(
            r'([\d,]+\.?\d*)\s*%?\s*\n\s+(.*?)(?:\n|$)', card
        )

        for value_str, label in matches:
            label_lower = label.strip().lower()

            for keywords, metric_name, is_count in METRIC_MAP:
                if all(kw in label_lower for kw in keywords):
                    if metric_name in seen_labels:
                        continue  # De-duplicate
                    seen_labels.add(metric_name)

                    value = float(value_str.replace(",", ""))
                    if is_count:
                        value = int(value)

                    metrics.append({
                        "measurement_date": measurement_date,
                        "metric_name": metric_name,
                        "value": value,
                        "available_date": collected_at,
                    })
                    break

    return metrics


def extract_emiratisation_chart(
    chart_labels: list[str], collected_at: str
) -> list[dict[str, Any]]:
    """Extract Emiratisation yearly time series from Chart.js configs."""
    metrics = []

    for label_str in chart_labels:
        if not isinstance(label_str, str):
            continue

        # Only process the Emiratisation chart
        if "uae nationals" not in label_str.lower() and "emirat" not in label_str.lower():
            continue

        # Extract labels (years) and data (counts)
        year_match = re.search(r'labels:\[([^\]]+)\]', label_str)
        data_match = re.search(r'data:\[([^\]]+)\]', label_str)

        if year_match and data_match:
            years = [y.strip().strip('"').strip("'") for y in year_match.group(1).split(",")]
            values = [float(v.strip()) for v in data_match.group(1).split(",")]

            for year_str, value in zip(years, values):
                try:
                    year = int(year_str)
                except ValueError:
                    continue

                metrics.append({
                    "measurement_date": f"{year}-01-01",
                    "metric_name": "uae|mohre_emiratisation_yearly",
                    "value": int(value),
                    "available_date": collected_at,
                })

            break  # Only process first matching chart

    return metrics


def normalize_mohre(
    stat_cards: list[str], chart_labels: list[str], collected_at: str
) -> list[dict[str, Any]]:
    """
    Normalize MOHRE Observatory data to annual metrics.

    Args:
        stat_cards: List of stat card text blocks.
        chart_labels: List of Chart.js config strings.
        collected_at: ISO timestamp of collection.

    Returns:
        List of normalized metric records.
    """
    metrics = []
    metrics.extend(extract_stat_card_metrics(stat_cards, collected_at))
    metrics.extend(extract_emiratisation_chart(chart_labels, collected_at))
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
        data = validate_mohre_json(file_path)

        # Aggregate stat_cards and chart_labels from all pages
        all_stat_cards = []
        all_chart_labels = []
        for page in data:
            all_stat_cards.extend(page.get("stat_cards", []))
            all_chart_labels.extend(page.get("chart_labels", []))

        # Normalize
        normalized = normalize_mohre(all_stat_cards, all_chart_labels, collected_at)

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

Run the rewritten normalizer against the real raw data file:

```bash
PYTHONPATH=/root/lobsec/packages/uae-re/python \
echo '{"filePath":"/opt/lobsec/data/raw/mohre-permits/2026-03-17.json","source":"mohre-permits","collectedAt":"2026-03-17T10:00:00.000Z"}' | \
  /opt/lobsec/analytics-venv/bin/python -m uae_re.normalize_mohre
```

**Expected output:** JSON array with at least 4 records:
- `uae|mohre_workforce_growth_pct` = 12.4 (measurement_date: 2025-01-01)
- `uae|mohre_establishment_growth_pct` = 7.8
- `uae|mohre_emiratisation_count` = 176125
- `uae|mohre_emiratisation_yearly` = 176255 for 2025, 131883 for 2024, etc.

If any metric is missing, inspect the raw JSON stat_cards/chart_labels and adjust regex patterns.

## Verification

1. The normalizer runs without errors against the real raw data file
2. Output contains at least 4 metric records with `source = "mohre-permits"`
3. `uae|mohre_workforce_growth_pct` value is 12.4
4. `uae|mohre_emiratisation_count` value is 176125 (or 176,125 parsed correctly)
5. Emiratisation chart produces 5 yearly records (2021-2025)
6. All `measurement_date` values use annual format (YYYY-01-01)
7. No reference to `articles` or `scrapedAt` in the normalizer code
8. No duplicate metric records in output

## Files Modified

- `packages/uae-re/python/uae_re/schemas/mohre_schema.py` (rewrite)
- `packages/uae-re/python/uae_re/normalize_mohre.py` (rewrite)
