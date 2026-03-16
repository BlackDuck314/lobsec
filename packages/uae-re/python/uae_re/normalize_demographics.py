#!/usr/bin/env python3
"""
FCSA / Dubai Statistics Centre demographics normalization module.

Reads scraped DSC population statistics data (JSON from DSC website browser
scrape) and produces normalized annual metrics:

Dubai-level metrics:
- dubai|dsc_total_population
- dubai|dsc_population_growth_pct
- dubai|dsc_expat_population
- dubai|dsc_national_population
- dubai|dsc_working_age_pct

All metrics include available_date (NORM-02 compliance).

Annual data is published once per year (~Q1 for prior year).
Most quarterly runs will return an empty list — this is expected and valid.
measurement_date is January 1 of the reference year.
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.demographics_schema import validate_demographics_json


def normalize_demographics(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DSC demographics data to annual metrics.

    Extracts population totals by nationality and age group.
    Returns empty list when no new annual bulletin data is present.
    measurement_date is set to January 1 of the reference year.

    Args:
        data: Raw JSON dict from Ninja Scraper browser extraction
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records (empty if no new annual data)
    """
    # Validate JSON structure
    validate_demographics_json(data)

    metrics = []

    # Check if any population data was actually scraped
    # Annual data — most quarterly runs will return empty
    population_fields = [
        "total_population", "population_growth_rate",
        "expat_population", "national_population", "working_age_pct"
    ]

    has_data = any(data.get(f) is not None for f in population_fields)

    if not has_data:
        # No new annual bulletin available — return empty list (expected for most quarters)
        return []

    # Determine measurement year from data or fall back to collection year
    # DSC publishes prior year data in current year (e.g., 2024 data in Q1 2025)
    reference_year = data.get("reference_year")
    if reference_year is None:
        # Fall back to prior year if not explicitly provided
        collected = pd.to_datetime(collected_at)
        reference_year = collected.year - 1

    measurement_date = f"{reference_year}-01-01"

    # Total population
    total_population = data.get("total_population")
    if total_population is not None and total_population > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dsc_total_population",
            "value": int(total_population),
            "available_date": collected_at,
        })

    # Population growth rate (YoY %)
    growth_rate = data.get("population_growth_rate")
    if growth_rate is not None:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dsc_population_growth_pct",
            "value": float(growth_rate),
            "available_date": collected_at,
        })

    # Expatriate / non-national population
    expat_population = data.get("expat_population")
    if expat_population is not None and expat_population >= 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dsc_expat_population",
            "value": int(expat_population),
            "available_date": collected_at,
        })

    # UAE national population
    national_population = data.get("national_population")
    if national_population is not None and national_population >= 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dsc_national_population",
            "value": int(national_population),
            "available_date": collected_at,
        })

    # Working age population percentage (25-54 age bracket)
    working_age_pct = data.get("working_age_pct")
    if working_age_pct is not None and 0 <= working_age_pct <= 100:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dsc_working_age_pct",
            "value": float(working_age_pct),
            "available_date": collected_at,
        })

    return metrics


def main():
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads raw data, normalizes, and outputs to stdout.

    Note: Empty list output is normal for most quarterly runs (annual data).
    """
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        # Load raw DSC demographics data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data for context
        raw_data["source"] = input_data["source"]

        # Normalize (empty list is valid for non-annual quarters)
        normalized = normalize_demographics(raw_data, collected_at)

        # Add source field to each record
        for record in normalized:
            record["source"] = input_data["source"]

        # Output to stdout (empty list [] is a valid and expected output)
        json.dump(normalized, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
