#!/usr/bin/env python3
"""
RTA vehicle registrations normalization module.

Reads scraped RTA vehicle registration data (JSON from Dubai Pulse browser scrape)
and produces normalized monthly metrics:

Dubai-level metrics:
- dubai|rta_new_registrations
- dubai|rta_deregistrations
- dubai|rta_total_registered
- dubai|rta_net_change

All metrics include available_date (NORM-02 compliance).

Handles browser-extracted table data from Dubai Pulse.
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.rta_schema import validate_rta_json


def normalize_rta(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize RTA vehicle registration data to monthly metrics.

    Extracts new registrations, deregistrations, and total registered vehicles.
    """
    # Validate JSON structure
    validate_rta_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    # Extract vehicle registration data
    new_registrations = data.get("new_registrations", 0)
    deregistrations = data.get("deregistrations", 0)
    total_registered = data.get("total_registered", 0)

    # Compute net change
    net_change = new_registrations - deregistrations

    # Validate: counts should be non-negative
    if new_registrations < 0 or deregistrations < 0:
        raise ValueError(
            f"Invalid vehicle counts: new_registrations={new_registrations}, "
            f"deregistrations={deregistrations} (cannot be negative)"
        )

    # Generate metrics
    if new_registrations > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|rta_new_registrations",
            "value": int(new_registrations),
            "available_date": collected_at,
        })

    if deregistrations > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|rta_deregistrations",
            "value": int(deregistrations),
            "available_date": collected_at,
        })

    if total_registered > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|rta_total_registered",
            "value": int(total_registered),
            "available_date": collected_at,
        })

    metrics.append({
        "measurement_date": measurement_date,
        "metric_name": "dubai|rta_net_change",
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

        # Load raw RTA data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data
        raw_data["source"] = input_data["source"]

        # Normalize
        normalized = normalize_rta(raw_data, collected_at)

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
