#!/usr/bin/env python3
"""
DEWA connections normalization module.

Reads scraped DEWA press release data (JSON) and produces normalized monthly metrics:

Emirate-level metrics (default if area data unavailable):
- dubai|dewa_new_connections
- dubai|dewa_disconnections
- dubai|dewa_net_change

Per-area metrics (if areas mentioned in press releases):
- {area}|dewa_new_connections
- {area}|dewa_disconnections
- {area}|dewa_net_change

All metrics include available_date (NORM-02 compliance).

Note: DEWA may only publish emirate-level data. If so, we aggregate to
emirate level without area prefix.
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.dewa_schema import validate_dewa_json


def normalize_dewa(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DEWA connections data to monthly metrics.

    Aggregates connections/disconnections counts by area (if available)
    or emirate-level otherwise.
    """
    # Validate JSON structure
    validate_dewa_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    # Check if we have any articles with data
    if not data["articles"]:
        # No data - return empty (will trigger empty collection warning)
        return metrics

    # Aggregate connections/disconnections across all articles
    total_connections = 0
    total_disconnections = 0
    areas_data: dict[str, dict[str, int]] = {}

    for article in data["articles"]:
        connections = article.get("connections_new", 0) or 0
        disconnections = article.get("disconnections", 0) or 0

        # Check if areas are mentioned
        areas_mentioned = article.get("areas_mentioned", [])

        if areas_mentioned:
            # Area-level data available
            # Distribute counts equally across mentioned areas (naive approach)
            count_per_area_conn = connections / len(areas_mentioned) if areas_mentioned else 0
            count_per_area_disc = disconnections / len(areas_mentioned) if areas_mentioned else 0

            for area in areas_mentioned:
                area_lower = area.lower().replace(" ", "_")
                if area_lower not in areas_data:
                    areas_data[area_lower] = {"connections": 0, "disconnections": 0}

                areas_data[area_lower]["connections"] += count_per_area_conn
                areas_data[area_lower]["disconnections"] += count_per_area_disc
        else:
            # No area-level breakdown - accumulate emirate-level
            total_connections += connections
            total_disconnections += disconnections

    # Generate metrics
    if areas_data:
        # Area-level metrics
        for area, counts in areas_data.items():
            new_connections = int(counts["connections"])
            disconnections_count = int(counts["disconnections"])
            net_change = new_connections - disconnections_count

            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{area}|dewa_new_connections",
                "value": new_connections,
                "available_date": collected_at,
            })

            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{area}|dewa_disconnections",
                "value": disconnections_count,
                "available_date": collected_at,
            })

            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{area}|dewa_net_change",
                "value": net_change,
                "available_date": collected_at,
            })
    else:
        # Emirate-level only
        net_change = total_connections - total_disconnections

        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dewa_new_connections",
            "value": int(total_connections),
            "available_date": collected_at,
        })

        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dewa_disconnections",
            "value": int(total_disconnections),
            "available_date": collected_at,
        })

        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dewa_net_change",
            "value": int(net_change),
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

        # Load raw DEWA data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data
        raw_data["source"] = input_data["source"]

        # Normalize
        normalized = normalize_dewa(raw_data, collected_at)

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
