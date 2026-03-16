#!/usr/bin/env python3
"""
F&B closures normalization module (COLL-21).

Reads scraped Google Maps + Zomato permanently closed restaurant data (JSON)
and produces normalized monthly metrics:

Dubai-level metrics:
- dubai|fb_permanently_closed_count       — total permanently closed restaurants found
- dubai|fb_closed_by_area_{area}         — closures per area (normalized area names)
- dubai|fb_closure_rate_mom              — month-over-month change (null if no history)

All metrics include available_date (NORM-02 compliance).
Deduplicates across Google Maps + Zomato by restaurant_name + area.
Returns empty list if no closure data available.
"""

import json
import re
import sys
from typing import Any

import pandas as pd

from .schemas.fb_closures_schema import validate_fb_closures_json


# Canonical Dubai area name mapping for normalization
_AREA_ALIASES: dict[str, str] = {
    "dubai marina": "dubai-marina",
    "marina": "dubai-marina",
    "downtown": "downtown-dubai",
    "downtown dubai": "downtown-dubai",
    "deira": "deira",
    "jumeirah lake towers": "jlt",
    "jlt": "jlt",
    "business bay": "business-bay",
    "jumeirah beach residence": "jbr",
    "jbr": "jbr",
    "al barsha": "al-barsha",
    "jumeirah village circle": "jvc",
    "jvc": "jvc",
    "palm jumeirah": "palm-jumeirah",
    "difc": "difc",
    "discovery gardens": "discovery-gardens",
    "silicon oasis": "dubai-silicon-oasis",
    "dubai silicon oasis": "dubai-silicon-oasis",
    "mirdif": "mirdif",
    "karama": "al-karama",
    "al karama": "al-karama",
    "satwa": "al-satwa",
    "al satwa": "al-satwa",
    "bur dubai": "bur-dubai",
    "international city": "international-city",
}


def _normalize_area(area: str | None) -> str:
    """Normalize area name to a consistent slug."""
    if not area:
        return "unknown"
    lower = area.lower().strip()
    if lower in _AREA_ALIASES:
        return _AREA_ALIASES[lower]
    # Fall back to slugify
    slug = re.sub(r"[^a-z0-9]+", "-", lower)
    return slug.strip("-")


def _deduplicate_closures(closures: list[dict]) -> list[dict]:
    """
    Deduplicate closure records by (restaurant_name, area) across sources.

    When the same restaurant appears in both Google Maps and Zomato,
    prefer the Google Maps entry (more authoritative for 'permanently closed').
    """
    seen: dict[tuple[str, str], dict] = {}
    for record in closures:
        name = str(record.get("restaurant_name", "")).lower().strip()
        area = _normalize_area(record.get("area"))
        key = (name, area)

        if key not in seen:
            seen[key] = record
        else:
            # Prefer Google Maps source
            source_url = str(record.get("source_url", "")).lower()
            if "google.com/maps" in source_url:
                seen[key] = record

    return list(seen.values())


def normalize_fb_closures(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize F&B closures data to monthly metrics.

    Args:
        data: Dictionary with scrapedAt, closures list
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records. Empty if no closures found.
    """
    validate_fb_closures_json(data)

    if not data.get("closures"):
        return []

    # Measurement date: start of month
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics: list[dict[str, Any]] = []

    # Deduplicate across sources
    closures = _deduplicate_closures(data["closures"])

    # Filter to permanently_closed only
    permanently_closed = [
        r for r in closures
        if r.get("permanently_closed", False) or r.get("permanently_closed") == "true"
    ]

    # If no explicit permanently_closed flag, count all records
    # (Google Maps search for 'permanently closed' implies all results are closed)
    if not permanently_closed and closures:
        permanently_closed = closures

    total_closed = len(permanently_closed)

    # Total closed count
    metrics.append({
        "measurement_date": measurement_date,
        "metric_name": "dubai|fb_permanently_closed_count",
        "value": total_closed,
        "available_date": collected_at,
    })

    # Per-area counts
    if permanently_closed:
        df = pd.DataFrame(permanently_closed)
        df["area_normalized"] = df.get("area", pd.Series(dtype=str)).apply(
            lambda x: _normalize_area(x)
        )

        area_counts = df["area_normalized"].value_counts()
        for area_slug, count in area_counts.items():
            if area_slug and area_slug != "unknown":
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"dubai|fb_closed_by_area_{area_slug}",
                    "value": int(count),
                    "available_date": collected_at,
                })

    # Month-over-month change: null — requires historical comparison from DB
    # The TS collector computes this when inserting into the metrics table
    metrics.append({
        "measurement_date": measurement_date,
        "metric_name": "dubai|fb_closure_rate_mom",
        "value": None,
        "available_date": collected_at,
    })

    return metrics


def normalize(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """Module-level normalize entry point (matches framework convention)."""
    import os
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return normalize_fb_closures(data, collected_at)


def main() -> None:
    """
    Main entry point for Python normalization bridge.

    Reads {filePath, source, collectedAt} from stdin.
    Outputs normalized metrics as JSON to stdout.
    """
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]
        source = input_data.get("source", "fb-closures")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        metrics = normalize_fb_closures(data, collected_at)

        for record in metrics:
            record["source"] = source

        json.dump(metrics, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
