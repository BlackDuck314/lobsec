#!/usr/bin/env python3
"""
Jebel Ali port / DP World cargo normalization module.

Reads scraped DP World press release data (JSON from dpworld.com browser
scrape) and produces normalized monthly metrics:

Dubai-level metrics:
- dubai|port_container_throughput_teu
- dubai|port_total_cargo_tonnes
- dubai|port_construction_material_tonnes  (optional — subset may not be reported)

All metrics include available_date (NORM-02 compliance).

Construction material imports (steel, cement, timber, aggregates) are a
leading indicator for residential construction starts. If the DP World press
release does not break out construction materials, this metric is skipped
with a warning logged (not an error).
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.port_schema import validate_port_json

# Construction material keywords to look for in category breakdown
CONSTRUCTION_MATERIAL_KEYWORDS = [
    "construction", "steel", "cement", "concrete", "timber", "lumber",
    "aggregate", "sand", "gravel", "building material", "rebar", "iron"
]


def is_construction_material(category: str) -> bool:
    """
    Check if a cargo category label represents construction materials.

    Args:
        category: Raw cargo category label from press release

    Returns:
        True if category matches construction material keywords
    """
    category_lower = category.lower()
    return any(keyword in category_lower for keyword in CONSTRUCTION_MATERIAL_KEYWORDS)


def normalize_port(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize Jebel Ali port cargo data to monthly metrics.

    Extracts container throughput (TEU), total cargo volume, and optionally
    construction material imports subset.
    measurement_date set to start of collection month.

    Args:
        data: Raw JSON dict from Ninja Scraper browser extraction
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records
    """
    # Validate JSON structure
    validate_port_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    # Container throughput (TEU)
    teu = data.get("container_throughput_teu")
    if teu is not None and teu > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|port_container_throughput_teu",
            "value": float(teu),
            "available_date": collected_at,
        })

    # Total cargo volume (metric tonnes)
    cargo_tonnes = data.get("cargo_volume_tonnes")
    if cargo_tonnes is not None and cargo_tonnes > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|port_total_cargo_tonnes",
            "value": float(cargo_tonnes),
            "available_date": collected_at,
        })

    # Construction material imports (optional subset)
    # Approach 1: Directly provided by scraper
    construction_tonnes = data.get("construction_material_tonnes")

    # Approach 2: Compute from category breakdown if available
    if construction_tonnes is None and data.get("by_cargo_category"):
        category_data = data["by_cargo_category"]
        if isinstance(category_data, dict):
            construction_total = 0.0
            found_construction = False
            for category, volume in category_data.items():
                if is_construction_material(str(category)) and volume is not None:
                    construction_total += float(volume)
                    found_construction = True
            if found_construction:
                construction_tonnes = construction_total

    if construction_tonnes is not None and construction_tonnes > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|port_construction_material_tonnes",
            "value": float(construction_tonnes),
            "available_date": collected_at,
        })
    else:
        # Construction material breakdown not available in this press release
        # Log warning but do not raise error — subset data is optional
        print(
            f"Warning: construction_material_tonnes not available in press release "
            f"for {measurement_date}. Metric skipped.",
            file=sys.stderr
        )

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

        # Load raw DP World port data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data for context
        raw_data["source"] = input_data["source"]

        # Normalize
        normalized = normalize_port(raw_data, collected_at)

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
