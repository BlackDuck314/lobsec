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
                if not re.search(r'\d+\s*[-\u2013]\s*\d+', age_label):
                    continue

            # Extract age range from label (e.g., "25 - 29", "30-34", "25 - 29")
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
