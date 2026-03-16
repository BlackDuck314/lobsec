#!/usr/bin/env python3
"""
DTCM Dubai tourism statistics normalization module.

Reads scraped DTCM tourism performance data (JSON from browser scrape of
dubaitourism.gov.ae) and produces normalized monthly metrics:

Dubai-level metrics:
- dubai|dtcm_hotel_occupancy_pct
- dubai|dtcm_visitor_count
- dubai|dtcm_hotel_revenue_aed
- dubai|dtcm_avg_length_of_stay

All metrics include available_date (NORM-02 compliance).

Sanity checks: occupancy must be 0-100, visitor count must be positive.
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.tourism_schema import validate_tourism_json


def normalize_tourism(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DTCM tourism statistics to monthly metrics.

    Extracts hotel occupancy, visitor count, hotel revenue, and average
    length of stay. measurement_date set to start of collection month.

    Args:
        data: Raw JSON dict from Ninja Scraper browser extraction
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records
    """
    # Validate JSON structure
    validate_tourism_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    # Hotel occupancy rate (%)
    hotel_occupancy_pct = data.get("hotel_occupancy_pct")
    if hotel_occupancy_pct is not None:
        if 0 <= hotel_occupancy_pct <= 100:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dtcm_hotel_occupancy_pct",
                "value": float(hotel_occupancy_pct),
                "available_date": collected_at,
            })
        else:
            print(
                f"Warning: hotel_occupancy_pct={hotel_occupancy_pct} outside 0-100 range, skipping",
                file=sys.stderr
            )

    # International visitor count
    visitor_count = data.get("visitor_count")
    if visitor_count is not None and visitor_count > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dtcm_visitor_count",
            "value": int(visitor_count),
            "available_date": collected_at,
        })

    # Hotel establishment revenue (AED)
    hotel_revenue_aed = data.get("hotel_revenue_aed")
    if hotel_revenue_aed is not None and hotel_revenue_aed > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dtcm_hotel_revenue_aed",
            "value": float(hotel_revenue_aed),
            "available_date": collected_at,
        })

    # Average length of stay (nights)
    avg_length_of_stay = data.get("average_length_of_stay")
    if avg_length_of_stay is not None and avg_length_of_stay > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dtcm_avg_length_of_stay",
            "value": float(avg_length_of_stay),
            "available_date": collected_at,
        })

    return metrics


def main():
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads raw data, normalizes, and outputs to stdout.
    """
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        # Load raw DTCM tourism data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data for context
        raw_data["source"] = input_data["source"]

        # Normalize
        normalized = normalize_tourism(raw_data, collected_at)

        # Add source field to each record
        for record in normalized:
            record["source"] = input_data["source"]

        # Output to stdout
        json.dump(normalized, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
