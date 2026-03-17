# Plan 03: Rewrite DSC Demographics Normalizer for PDF Extraction

**Requirement(s):** NORM-08
**Estimated complexity:** Medium-High
**Depends on:** none

## Goal

Rewrite `normalize_demographics.py` and `demographics_schema.py` to extract population data from the DSC Population Bulletin PDF via pdfplumber, instead of the old browser-extracted JSON format that no longer matches the scraped data.

## Context

The scraper now downloads the DSC Population Bulletin as a PDF at `/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf`. It is a 12-page document with structured tables.

**Key pages and data:**
- Page 1 (index 0): Title "Population Bulletin Emirate of Dubai 2024" -- reference year
- Page 2 (index 1): Table 1 "Population by Gender" with columns for 2022, 2023, 2024. The "Total" row has `4,248,200` for 2024 and `3,974,300` for 2023.
- Page 4 (index 3): Table 3 "Population by Age Group and Gender" with 16 age groups.
- Pages 5-12: Population by planning sector/community (not needed for NORM-08)

**CRITICAL: No national/expat breakdown.** The 2024 Population Bulletin does NOT contain nationality data. The `dubai|dsc_expat_population` and `dubai|dsc_national_population` metrics CANNOT be extracted from this PDF. The normalizer must extract what IS available and simply omit what isn't. Do NOT fabricate data or return 0.

**pdfplumber table extraction quirks (from research):**
- Table cells can have `None` values
- Numbers may have embedded spaces: `'4,248 ,200'` instead of `'4,248,200'`
- Multi-year columns with merged headers
- Page 2 Table 0 row 4: `['', 'Total', '', '3,718,000', None, None, '100.00', None, None, '3,974,300', None, None, '100.00', None, None, '4,248,200', None, None, '100.00', None, None]`
- The 2024 total population value is at the END of the Total row (need to find last valid large number)

**Bridge protocol (DO NOT CHANGE):**
- stdin: `{"filePath": "/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf", "source": "fcsa-demographics", "collectedAt": "2026-03-17T10:00:00.000Z"}`
- stdout: `[{"source": "fcsa-demographics", "measurement_date": "2024-01-01", "metric_name": "dubai|dsc_total_population", "value": 4248200, "available_date": "..."}, ...]`

**Existing pattern to follow:** The KHDA normalizer (`normalize_khda.py`) already uses pdfplumber for PDF table extraction with the same bridge protocol. Follow that pattern.

## Tasks

### Task 1: Rewrite `demographics_schema.py` to validate PDF input

Replace the JSON-dict validation with PDF file validation. Follow the exact same pattern as `khda_schema.py`:
- File exists and is a file
- File ends with `.pdf`
- File starts with `%PDF` header bytes

**File:** `packages/uae-re/python/uae_re/schemas/demographics_schema.py`

```python
"""
Schema validation for DSC demographics data (NORM-08).

DSC data comes from PDF Population Bulletin files.
"""

import os


def validate_demographics_pdf(file_path: str) -> None:
    """
    Validate DSC demographics PDF file exists and is readable.

    Args:
        file_path: Path to PDF file

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(file_path, str):
        raise ValueError("file_path must be a string")

    if not os.path.exists(file_path):
        raise ValueError(f"PDF file does not exist: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    if not file_path.lower().endswith('.pdf'):
        raise ValueError(f"File is not a PDF: {file_path}")

    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            if header != b'%PDF':
                raise ValueError(f"File is not a valid PDF: {file_path}")
    except IOError as e:
        raise ValueError(f"Cannot read PDF file: {e}")
```

**Note:** The function name changes from `validate_demographics_json` to `validate_demographics_pdf`. The normalizer import must be updated to match.

### Task 2: Rewrite `normalize_demographics.py` to extract from PDF

Complete rewrite. Add pdfplumber import. Extract:

1. **Reference year** from Page 1 title text (e.g., "2024")
2. **Total population** from Page 2 Table 0 "Total" row, last valid large number (4,248,200 for 2024)
3. **Prior year population** from same row (3,974,300 for 2023) to compute growth rate
4. **Population growth rate** calculated: `(current - prior) / prior * 100` = 6.9%
5. **Working age percentage** from Page 4 age group table: sum population for age groups 25-54, divide by total

**File:** `packages/uae-re/python/uae_re/normalize_demographics.py`

Key implementation:

```python
#!/usr/bin/env python3
"""
FCSA / Dubai Statistics Centre demographics normalization module.

Reads DSC Population Bulletin PDF and produces normalized annual metrics:

Dubai-level metrics:
- dubai|dsc_total_population
- dubai|dsc_population_growth_pct
- dubai|dsc_working_age_pct

All metrics include available_date (NORM-02 compliance).
Annual data — measurement_date is January 1 of the reference year.

Note: The 2024 Population Bulletin does NOT contain national/expat breakdown.
Those metrics are omitted (not zeroed) when unavailable.
"""

import json
import re
import sys
from typing import Any

import pdfplumber

from .schemas.demographics_schema import validate_demographics_pdf


def clean_number(cell: Any) -> int | None:
    """
    Clean a table cell value to an integer.
    Handles None, embedded spaces, commas, and percentage symbols.
    Returns None if not a valid integer.
    """
    if cell is None:
        return None
    s = str(cell).replace(" ", "").replace(",", "").replace("%", "").strip()
    if not s:
        return None
    try:
        # Try int first (exact population counts)
        return int(float(s))
    except (ValueError, OverflowError):
        return None


def extract_reference_year(pdf) -> int | None:
    """Extract reference year from PDF title page (page 1)."""
    if not pdf.pages:
        return None
    text = pdf.pages[0].extract_text() or ""
    # Pattern: "Population Bulletin\nEmirate of Dubai\n2024"
    match = re.search(r'(\d{4})\s*$', text.strip())
    if match:
        return int(match.group(1))
    # Fallback: any 4-digit year on page 1
    match = re.search(r'(20\d{2})', text)
    if match:
        return int(match.group(1))
    return None


def extract_population_from_page2(pdf) -> dict[str, Any]:
    """
    Extract total population and prior-year population from Page 2.

    Page 2 has a gender breakdown table with multi-year columns (2022, 2023, 2024).
    The "Total" row contains population counts. We want the last (most recent)
    and second-to-last (prior year) large numbers from the Total row.
    """
    result = {"total_population": None, "prior_year_population": None}

    if len(pdf.pages) < 2:
        return result

    page2 = pdf.pages[1]
    tables = page2.extract_tables()

    if not tables:
        return result

    # Look for the Total row in the first table
    for table in tables:
        for row in table:
            if not row:
                continue

            # Check if this is a "Total" row
            row_text = " ".join(str(c) for c in row if c).lower()
            if "total" not in row_text:
                continue

            # Extract all large numbers from this row (population-scale: > 1,000,000)
            large_nums = []
            for cell in row:
                n = clean_number(cell)
                if n is not None and n > 1_000_000:
                    large_nums.append(n)

            if large_nums:
                # Last = most recent year, second-to-last = prior year
                result["total_population"] = large_nums[-1]
                if len(large_nums) >= 2:
                    result["prior_year_population"] = large_nums[-2]

            if result["total_population"]:
                break  # Found what we need

        if result["total_population"]:
            break

    return result


def extract_working_age_from_page4(pdf) -> float | None:
    """
    Extract working age percentage from Page 4 age group table.

    Working age defined as 25-54 (standard economic definition for Dubai).
    Returns percentage or None if extraction fails.
    """
    if len(pdf.pages) < 4:
        return None

    page4 = pdf.pages[3]
    tables = page4.extract_tables()

    if not tables:
        return None

    total_pop = 0
    working_age_pop = 0

    for table in tables:
        for row in table:
            if not row:
                continue

            # Get the age group label (first non-None cell that contains digits)
            age_label = ""
            for cell in row:
                if cell and str(cell).strip():
                    age_label = str(cell).strip()
                    break

            if not age_label:
                continue

            # Skip header/total rows
            age_label_lower = age_label.lower()
            if any(skip in age_label_lower for skip in ["age", "total", "group", "gender", "male", "female"]):
                # But allow rows like "25 - 29" that happen to contain other words
                if not re.search(r'\d+\s*[-–]\s*\d+', age_label):
                    continue

            # Extract age range from label (e.g., "25 - 29", "30-34", "25 – 29")
            age_nums = re.findall(r'\d+', age_label)
            if len(age_nums) < 2:
                continue

            low_age = int(age_nums[0])
            high_age = int(age_nums[1])

            # Find the total column value (largest number in the row that's population-scale)
            # The "Total" column is typically the largest number per row for an age group
            row_nums = []
            for cell in row:
                n = clean_number(cell)
                if n is not None and 1000 < n < 2_000_000:
                    row_nums.append(n)

            if not row_nums:
                continue

            # Use the largest number as the total (Male + Female = Total)
            age_total = max(row_nums)
            total_pop += age_total

            # Check if working age (25-54)
            if low_age >= 25 and high_age <= 54:
                working_age_pop += age_total

    if total_pop > 0 and working_age_pop > 0:
        return round(working_age_pop / total_pop * 100, 1)

    return None


def normalize_demographics(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DSC Population Bulletin PDF to annual metrics.

    Args:
        file_path: Path to the DSC PDF file.
        collected_at: ISO timestamp of collection.

    Returns:
        List of normalized metric records.
    """
    import pandas as pd

    metrics = []

    with pdfplumber.open(file_path) as pdf:
        # Extract reference year from title page
        ref_year = extract_reference_year(pdf)
        if ref_year is None:
            collected = pd.to_datetime(collected_at)
            ref_year = collected.year - 1  # Bulletin published for prior year

        measurement_date = f"{ref_year}-01-01"

        # Extract population from Page 2
        pop_data = extract_population_from_page2(pdf)

        if pop_data["total_population"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dsc_total_population",
                "value": int(pop_data["total_population"]),
                "available_date": collected_at,
            })

            # Calculate growth rate if prior year available
            if pop_data["prior_year_population"]:
                prior = pop_data["prior_year_population"]
                current = pop_data["total_population"]
                growth_pct = round((current - prior) / prior * 100, 1)
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": "dubai|dsc_population_growth_pct",
                    "value": growth_pct,
                    "available_date": collected_at,
                })

        # Extract working age percentage from Page 4
        working_age_pct = extract_working_age_from_page4(pdf)
        if working_age_pct is not None and 0 < working_age_pct < 100:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dsc_working_age_pct",
                "value": working_age_pct,
                "available_date": collected_at,
            })

    return metrics


def main() -> None:
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    validates PDF, extracts data via pdfplumber, normalizes, outputs to stdout.
    """
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        # Validate PDF file
        validate_demographics_pdf(file_path)

        # Normalize
        normalized = normalize_demographics(file_path, collected_at)

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

**Key differences from old code:**
1. Uses pdfplumber to open PDF directly (not JSON parsing)
2. Schema validates PDF (not JSON dict)
3. `clean_number()` helper strips spaces AND commas (critical for DSC's formatting quirks)
4. Looks for "Total" row in tables, then finds last large number (most recent year)
5. Working age = sum of 25-29, 30-34, 35-39, 40-44, 45-49, 50-54 age groups
6. NO expat/national metrics -- they don't exist in this bulletin
7. Returns empty list if PDF has no extractable tables (instead of crashing)

### Task 3: Verify against actual raw PDF

Run the rewritten normalizer against the real PDF:

```bash
PYTHONPATH=/root/lobsec/packages/uae-re/python \
echo '{"filePath":"/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf","source":"fcsa-demographics","collectedAt":"2026-03-17T10:00:00.000Z"}' | \
  /opt/lobsec/analytics-venv/bin/python -m uae_re.normalize_demographics
```

**Expected output:** JSON array with 2-3 records:
- `dubai|dsc_total_population` = 4248200 (measurement_date: 2024-01-01)
- `dubai|dsc_population_growth_pct` = approximately 6.9 (could vary by rounding)
- `dubai|dsc_working_age_pct` = approximately 56-60% (25-54 age bracket)

**Debugging if extraction fails:**

If total_population is not found, run pdfplumber interactively to inspect table structure:

```bash
/opt/lobsec/analytics-venv/bin/python3 -c "
import pdfplumber
with pdfplumber.open('/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf') as pdf:
    page = pdf.pages[1]
    for i, table in enumerate(page.extract_tables()):
        print(f'Table {i}:')
        for j, row in enumerate(table):
            print(f'  Row {j}: {row}')
"
```

Adjust `clean_number()` or row detection logic based on actual table structure.

If working_age_pct is not found, inspect page 4:

```bash
/opt/lobsec/analytics-venv/bin/python3 -c "
import pdfplumber
with pdfplumber.open('/opt/lobsec/data/raw/fcsa-demographics/2026-03-17.pdf') as pdf:
    page = pdf.pages[3]
    for i, table in enumerate(page.extract_tables()):
        print(f'Table {i}:')
        for j, row in enumerate(table):
            print(f'  Row {j}: {row}')
"
```

## Verification

1. The normalizer runs without errors against the real PDF file
2. Output contains at least 2 records with `source = "fcsa-demographics"`
3. `dubai|dsc_total_population` value is 4,248,200 (or close, depends on exact cell parsing)
4. `dubai|dsc_population_growth_pct` is approximately 6.9%
5. measurement_date is `2024-01-01` (reference year from PDF title)
6. NO `dubai|dsc_expat_population` or `dubai|dsc_national_population` records in output (these don't exist in the bulletin)
7. pdfplumber import is present; no reference to old JSON fields (`scrapedAt`, `source_url`, etc.)

## Files Modified

- `packages/uae-re/python/uae_re/schemas/demographics_schema.py` (rewrite)
- `packages/uae-re/python/uae_re/normalize_demographics.py` (rewrite)
