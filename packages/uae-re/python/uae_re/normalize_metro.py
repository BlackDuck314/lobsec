#!/usr/bin/env python3
"""
RTA metro ridership normalization module.

Reads scraped RTA public transport ridership data (JSON from RTA statistics
browser scrape) and produces normalized monthly metrics:

Dubai-level metrics:
- dubai|metro_total_ridership
- dubai|metro_rail_ridership
- dubai|metro_tram_ridership
- dubai|metro_bus_ridership

All metrics include available_date (NORM-02 compliance).

Handles browser-extracted table data from RTA statistics page.
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.metro_schema import validate_metro_json


def normalize_metro(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize RTA metro ridership data to monthly metrics.

    Extracts total ridership, metro rail, tram, and bus breakdown.
    measurement_date is set to the start of the month of collection.

    Args:
        data: Raw JSON dict from Ninja Scraper browser extraction
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records
    """
    # Validate JSON structure
    validate_metro_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    # Total ridership (all public transport modes combined)
    total_ridership = data.get("total_ridership")
    if total_ridership is not None and total_ridership > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|metro_total_ridership",
            "value": int(total_ridership),
            "available_date": collected_at,
        })

    # Metro rail ridership
    metro_ridership = data.get("metro_ridership")
    if metro_ridership is not None and metro_ridership > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|metro_rail_ridership",
            "value": int(metro_ridership),
            "available_date": collected_at,
        })

    # Dubai Tram ridership
    tram_ridership = data.get("tram_ridership")
    if tram_ridership is not None and tram_ridership > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|metro_tram_ridership",
            "value": int(tram_ridership),
            "available_date": collected_at,
        })

    # Bus ridership
    bus_ridership = data.get("bus_ridership")
    if bus_ridership is not None and bus_ridership > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|metro_bus_ridership",
            "value": int(bus_ridership),
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

        # Load raw metro data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data for schema validation context
        raw_data["source"] = input_data["source"]

        # Normalize
        normalized = normalize_metro(raw_data, collected_at)

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
