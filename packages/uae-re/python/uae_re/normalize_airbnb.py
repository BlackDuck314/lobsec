#!/usr/bin/env python3
"""
InsideAirbnb STR listing normalization module (COLL-19).

Reads InsideAirbnb gzipped CSV for Dubai and produces normalized quarterly metrics:

Dubai-level metrics:
- dubai|airbnb_total_listings              — total active listings
- dubai|airbnb_avg_price_aed              — mean nightly price (AED)
- dubai|airbnb_avg_availability_days      — mean availability_365 (lower = higher demand)
- dubai|airbnb_occupancy_proxy            — estimated occupancy: 1 - (avg_availability / 365)
- dubai|airbnb_avg_reviews_per_month      — mean reviews/month (proxy for booking frequency)
- dubai|airbnb_multihost_ratio            — pct listings from hosts with >1 listing (commercial STR)

Per-neighbourhood metrics (top 10 areas by listing count):
- dubai|airbnb_{area}_listings            — listing count
- dubai|airbnb_{area}_avg_price          — mean nightly price

All metrics include available_date (NORM-02 compliance).
Returns empty list if CSV is empty or missing (graceful for unavailable quarters).
"""

import gzip
import io
import json
import re
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from .schemas.airbnb_schema import validate_airbnb_dataframe


def _slugify(name: str) -> str:
    """Convert area name to metric slug: lowercase, spaces/punctuation to underscores."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    slug = slug.strip("_")
    return slug


def _parse_price(price_str: Any) -> float | None:
    """
    Parse InsideAirbnb price string to float.

    InsideAirbnb prices may be formatted as '$1,234.56' or '1234.56' or '1,234'.
    Returns None if unparseable.
    """
    if pd.isna(price_str):
        return None
    s = str(price_str).replace("$", "").replace(",", "").strip()
    try:
        return float(s)
    except (ValueError, TypeError):
        return None


def normalize_airbnb(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize InsideAirbnb CSV to quarterly metrics.

    Args:
        file_path: Path to gzipped (or plain) CSV file from InsideAirbnb
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records. Empty if no data available.
    """
    path = Path(file_path)
    if not path.exists():
        return []

    # Load CSV — handle gzip transparently
    try:
        if file_path.endswith(".gz"):
            with gzip.open(file_path, "rt", encoding="utf-8") as f:
                df = pd.read_csv(f, low_memory=False)
        else:
            df = pd.read_csv(file_path, low_memory=False, encoding="utf-8")
    except Exception:
        return []

    if df.empty:
        return []

    # Validate structure
    validate_airbnb_dataframe(df)

    # Measurement date: start of quarter (based on collected_at)
    collected_ts = pd.to_datetime(collected_at)
    quarter_start = collected_ts.to_period("Q").to_timestamp()
    measurement_date = quarter_start.strftime("%Y-%m-%d")

    metrics: list[dict[str, Any]] = []

    # --- Parse price ---
    df["price_numeric"] = df["price"].apply(_parse_price)

    # --- reviews_per_month ---
    df["reviews_per_month_numeric"] = pd.to_numeric(
        df.get("reviews_per_month", pd.Series(dtype=float)), errors="coerce"
    )

    # --- availability_365 ---
    df["availability_numeric"] = pd.to_numeric(
        df.get("availability_365", pd.Series(dtype=float)), errors="coerce"
    )

    # --- calculated_host_listings_count ---
    df["host_listings"] = pd.to_numeric(
        df.get("calculated_host_listings_count", pd.Series(dtype=float)), errors="coerce"
    )

    total_listings = len(df)

    # Dubai-level: total listings
    metrics.append({
        "measurement_date": measurement_date,
        "metric_name": "dubai|airbnb_total_listings",
        "value": total_listings,
        "available_date": collected_at,
    })

    # Dubai-level: avg price
    prices = df["price_numeric"].dropna()
    if not prices.empty:
        avg_price = prices.mean()
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|airbnb_avg_price_aed",
            "value": round(float(avg_price), 2),
            "available_date": collected_at,
        })

    # Dubai-level: avg availability
    avail = df["availability_numeric"].dropna()
    if not avail.empty:
        avg_availability = avail.mean()
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|airbnb_avg_availability_days",
            "value": round(float(avg_availability), 2),
            "available_date": collected_at,
        })

        # Occupancy proxy: 1 - avg_availability / 365
        occupancy_proxy = max(0.0, 1.0 - (avg_availability / 365.0))
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|airbnb_occupancy_proxy",
            "value": round(float(occupancy_proxy), 4),
            "available_date": collected_at,
        })

    # Dubai-level: avg reviews per month
    reviews = df["reviews_per_month_numeric"].dropna()
    if not reviews.empty:
        avg_reviews = reviews.mean()
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|airbnb_avg_reviews_per_month",
            "value": round(float(avg_reviews), 4),
            "available_date": collected_at,
        })

    # Dubai-level: multihost ratio (hosts with >1 listing)
    host_counts = df["host_listings"].dropna()
    if not host_counts.empty and total_listings > 0:
        multihost_count = (host_counts > 1).sum()
        multihost_ratio = float(multihost_count) / total_listings
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|airbnb_multihost_ratio",
            "value": round(multihost_ratio, 4),
            "available_date": collected_at,
        })

    # Per-neighbourhood: top 10 areas by listing count
    if "neighbourhood_cleansed" in df.columns:
        area_counts = (
            df["neighbourhood_cleansed"]
            .dropna()
            .value_counts()
            .head(10)
        )

        for area_name, count in area_counts.items():
            area_slug = _slugify(str(area_name))

            # Listing count
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"dubai|airbnb_{area_slug}_listings",
                "value": int(count),
                "available_date": collected_at,
            })

            # Avg price for area
            area_mask = df["neighbourhood_cleansed"] == area_name
            area_prices = df.loc[area_mask, "price_numeric"].dropna()
            if not area_prices.empty:
                area_avg_price = area_prices.mean()
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"dubai|airbnb_{area_slug}_avg_price",
                    "value": round(float(area_avg_price), 2),
                    "available_date": collected_at,
                })

    return metrics


def normalize(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """Module-level normalize entry point (matches framework convention)."""
    return normalize_airbnb(file_path, collected_at)


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
        source = input_data.get("source", "insideairbnb")

        metrics = normalize_airbnb(file_path, collected_at)

        for record in metrics:
            record["source"] = source

        json.dump(metrics, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
