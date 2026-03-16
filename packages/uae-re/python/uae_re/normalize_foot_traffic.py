#!/usr/bin/env python3
"""
Google Maps Popular Times foot traffic normalization module (COLL-26).

Reads scraped Google Maps Popular Times data (JSON) for 50 curated Dubai
locations and produces normalized weekly metrics:

Per-location metrics:
- dubai|traffic_{location_slug}_weekly_avg — average weekly popularity index (0-100)
- dubai|traffic_{location_slug}_peak_hour  — hour with highest average popularity

Category aggregate metrics:
- dubai|traffic_malls_avg       — mean across 10 malls
- dubai|traffic_metro_avg       — mean across 10 metro stations
- dubai|traffic_landmarks_avg   — mean across 15 key areas/landmarks
- dubai|traffic_business_avg    — mean across 10 business districts
- dubai|traffic_residential_avg — mean across 5 residential hubs
- dubai|traffic_composite       — overall mean across all successful locations

Handles partial data: locations that failed (Google blocking) are logged and excluded.
All metrics include available_date (NORM-02 compliance).
"""

import json
import re
import sys
from typing import Any

import pandas as pd

from .schemas.foot_traffic_schema import validate_foot_traffic_json


# Location categorization for aggregate metrics
# Maps source_url pattern fragments to category slugs
_MALL_PATTERNS = [
    "dubai+mall", "dubai_mall", "the+dubai+mall",
    "mall+of+the+emirates", "mall_of_the_emirates",
    "ibn+battuta", "dubai+marina+mall",
    "city+centre+deira", "city+centre+mirdif",
    "nakheel+mall", "dragon+mart",
    "festival+city+mall", "burjuman",
]

_METRO_PATTERNS = [
    "metro+station", "metro_station",
    "burj+khalifa+dubai+mall+metro",
    "mall+of+the+emirates+metro",
    "dubai+marina+metro",
    "dmcc+metro", "business+bay+metro",
    "union+metro", "deira+city+centre+metro",
    "creek+metro", "jlt+metro",
    "expo+2020+metro", "jumeirah+lake+towers+metro",
]

_BUSINESS_PATTERNS = [
    "financial+centre", "internet+city",
    "media+city", "jebel+ali+free+zone",
    "design+district", "healthcare+city",
    "al+quoz+industrial", "tecom",
    "dubai+south", "studio+city",
]

_RESIDENTIAL_PATTERNS = [
    "discovery+gardens", "international+city",
    "sports+city", "mirdif", "al+nahda",
]


def _slugify(name: str) -> str:
    """Convert location name to metric slug."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _infer_category(source_url: str, location_name: str) -> str:
    """Infer location category from URL or name."""
    url_lower = source_url.lower().replace(" ", "+")
    name_lower = location_name.lower()

    # Check business first (some are ambiguous with landmarks)
    for pat in _BUSINESS_PATTERNS:
        if pat in url_lower or pat.replace("+", " ") in name_lower:
            return "business"

    for pat in _METRO_PATTERNS:
        if pat in url_lower or pat.replace("+", " ") in name_lower:
            return "metro"

    for pat in _MALL_PATTERNS:
        if pat in url_lower or pat.replace("+", " ") in name_lower:
            return "malls"

    for pat in _RESIDENTIAL_PATTERNS:
        if pat in url_lower or pat.replace("+", " ") in name_lower:
            return "residential"

    return "landmarks"


def _compute_weekly_avg(popular_times: dict | None) -> float | None:
    """
    Compute average popularity across all days and hours from Popular Times histogram.

    Args:
        popular_times: Dict mapping day names to lists of 24 hourly values (0-100).
                      Format varies: {"Monday": [0, 0, ..., 45, 80, ...], ...}
                      or {"0": [...], "1": [...], ...} (0=Sunday)

    Returns:
        Mean popularity (0-100), or None if data unavailable.
    """
    if not popular_times:
        return None

    all_values: list[float] = []
    for day_key, hours in popular_times.items():
        if isinstance(hours, list):
            values = [v for v in hours if v is not None and isinstance(v, (int, float))]
            all_values.extend(values)

    if not all_values:
        return None

    return sum(all_values) / len(all_values)


def _compute_peak_hour(popular_times: dict | None) -> int | None:
    """
    Find the hour (0-23) with the highest average popularity across all days.

    Returns:
        Hour integer (0-23) of peak popularity, or None if data unavailable.
    """
    if not popular_times:
        return None

    hourly_totals: dict[int, list[float]] = {h: [] for h in range(24)}

    for day_key, hours in popular_times.items():
        if isinstance(hours, list):
            for hour_idx, val in enumerate(hours[:24]):
                if val is not None and isinstance(val, (int, float)):
                    hourly_totals[hour_idx].append(float(val))

    hourly_avgs = {
        h: sum(vals) / len(vals)
        for h, vals in hourly_totals.items()
        if vals
    }

    if not hourly_avgs:
        return None

    return max(hourly_avgs, key=lambda h: hourly_avgs[h])


def normalize_foot_traffic(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize Google Maps Popular Times data to weekly metrics.

    Args:
        data: Dictionary with scrapedAt and locations list
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records. Empty if no data available.
    """
    validate_foot_traffic_json(data)

    if not data.get("locations"):
        return []

    # Measurement date: Monday of the collection week
    scraped_at = pd.to_datetime(data["scrapedAt"])
    week_monday = scraped_at - pd.Timedelta(days=scraped_at.weekday())
    measurement_date = week_monday.strftime("%Y-%m-%d")

    metrics: list[dict[str, Any]] = []
    locations = data["locations"]

    # Track per-category weekly averages for aggregate metrics
    category_avgs: dict[str, list[float]] = {
        "malls": [],
        "metro": [],
        "landmarks": [],
        "business": [],
        "residential": [],
    }

    successful = 0
    failed = 0
    all_avgs: list[float] = []

    for loc in locations:
        location_name = loc.get("location_name", "")
        source_url = loc.get("source_url", "")
        popular_times = loc.get("popular_times")

        # Skip failed locations (Google blocked, no data)
        if loc.get("error") or not popular_times:
            failed += 1
            continue

        successful += 1
        loc_slug = _slugify(location_name) if location_name else _slugify(source_url)

        # Per-location weekly average
        weekly_avg = _compute_weekly_avg(popular_times)
        if weekly_avg is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"dubai|traffic_{loc_slug}_weekly_avg",
                "value": round(weekly_avg, 2),
                "available_date": collected_at,
            })
            all_avgs.append(weekly_avg)

            # Categorize for aggregates
            category = _infer_category(source_url, location_name)
            if category in category_avgs:
                category_avgs[category].append(weekly_avg)

        # Per-location peak hour
        peak_hour = _compute_peak_hour(popular_times)
        if peak_hour is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"dubai|traffic_{loc_slug}_peak_hour",
                "value": peak_hour,
                "available_date": collected_at,
            })

    # Category aggregate metrics
    category_metric_names = {
        "malls": "dubai|traffic_malls_avg",
        "metro": "dubai|traffic_metro_avg",
        "landmarks": "dubai|traffic_landmarks_avg",
        "business": "dubai|traffic_business_avg",
        "residential": "dubai|traffic_residential_avg",
    }

    for category, avg_list in category_avgs.items():
        if avg_list:
            cat_avg = sum(avg_list) / len(avg_list)
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": category_metric_names[category],
                "value": round(cat_avg, 2),
                "available_date": collected_at,
            })

    # Composite: overall mean across all successful locations
    if all_avgs:
        composite = sum(all_avgs) / len(all_avgs)
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|traffic_composite",
            "value": round(composite, 2),
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
    return normalize_foot_traffic(data, collected_at)


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
        source = input_data.get("source", "google-maps-traffic")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        metrics = normalize_foot_traffic(data, collected_at)

        for record in metrics:
            record["source"] = source

        json.dump(metrics, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
