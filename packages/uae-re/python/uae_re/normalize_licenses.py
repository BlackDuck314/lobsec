#!/usr/bin/env python3
"""
DED business licenses normalization module.

Reads scraped DED business license data (JSON from Dubai Pulse browser scrape)
and produces normalized monthly metrics:

Dubai-level metrics:
- dubai|ded_new_licenses
- dubai|ded_cancelled_licenses
- dubai|ded_net_licenses
- dubai|ded_new_by_sector_{sector} (per sector breakdown when available)

All metrics include available_date (NORM-02 compliance).

Sector breakdown is optional — Dubai Pulse may not always provide sector
filtering. Core metrics (new/cancelled/net) are always produced when available.
"""

import json
import sys
from typing import Any

import pandas as pd

from .schemas.licenses_schema import validate_licenses_json

# Canonical sector names for normalization
# Maps raw sector labels to standardized metric suffixes
SECTOR_MAP = {
    "real estate": "real_estate",
    "real_estate": "real_estate",
    "property": "real_estate",
    "hospitality": "hospitality",
    "hotel": "hospitality",
    "tourism": "hospitality",
    "food and beverage": "food_and_beverage",
    "f&b": "food_and_beverage",
    "restaurant": "food_and_beverage",
    "professional services": "professional_services",
    "professional": "professional_services",
    "consulting": "professional_services",
    "trading": "trading",
    "retail": "retail",
    "wholesale": "wholesale",
    "manufacturing": "manufacturing",
    "transport": "transport",
    "logistics": "transport",
    "technology": "technology",
    "it": "technology",
    "healthcare": "healthcare",
    "medical": "healthcare",
    "education": "education",
    "financial services": "financial_services",
    "finance": "financial_services",
    "construction": "construction",
}


def normalize_sector_name(raw_sector: str) -> str:
    """
    Normalize a raw sector label to a canonical metric suffix.

    Args:
        raw_sector: Raw sector name from Dubai Pulse

    Returns:
        Canonical sector suffix for metric name
    """
    normalized = raw_sector.lower().strip()
    return SECTOR_MAP.get(normalized, normalized.replace(" ", "_").replace("-", "_"))


def normalize_licenses(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DED business license data to monthly metrics.

    Extracts new licenses, cancelled licenses, net change, and optional
    sector breakdown. measurement_date set to start of collection month.

    Args:
        data: Raw JSON dict from Ninja Scraper browser extraction
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records
    """
    # Validate JSON structure
    validate_licenses_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    new_licenses = data.get("new_licenses", 0)
    cancelled_licenses = data.get("cancelled_licenses", 0)

    # New licenses issued
    if new_licenses is not None and new_licenses >= 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|ded_new_licenses",
            "value": int(new_licenses),
            "available_date": collected_at,
        })

    # Cancelled / suspended licenses
    if cancelled_licenses is not None and cancelled_licenses >= 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|ded_cancelled_licenses",
            "value": int(cancelled_licenses),
            "available_date": collected_at,
        })

    # Net licenses (new minus cancelled)
    if new_licenses is not None and cancelled_licenses is not None:
        net_licenses = new_licenses - cancelled_licenses
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|ded_net_licenses",
            "value": int(net_licenses),
            "available_date": collected_at,
        })

    # Sector breakdown (optional — when Dubai Pulse provides it)
    by_sector = data.get("by_sector")
    if by_sector and isinstance(by_sector, dict):
        for raw_sector, count in by_sector.items():
            if count is not None and count >= 0:
                sector_suffix = normalize_sector_name(str(raw_sector))
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"dubai|ded_new_by_sector_{sector_suffix}",
                    "value": int(count),
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

        # Load raw DED licenses data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data for context
        raw_data["source"] = input_data["source"]

        # Normalize
        normalized = normalize_licenses(raw_data, collected_at)

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
