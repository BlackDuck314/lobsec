#!/usr/bin/env python3
"""
PropertyFinder listing normalization module.

Identical logic to Bayut normalization but reads from PropertyFinder raw JSON.
Produces same metric outputs for cross-validation capability.

Per-area metrics:
- {area}|all|active_listing_count
- {area}|all|median_asking_price
- {area}|all|median_dom (if available)
- {area}|all|price_reduction_count

Per property type metrics:
- {area}|{property_type}|active_listing_count
- {area}|{property_type}|median_asking_price
- {area}|{property_type}|median_dom
- {area}|{property_type}|price_reduction_count

All metrics include available_date (NORM-02 compliance).
"""

import json
import re
import sys
from typing import Any

import pandas as pd

from .schemas.listings_schema import validate_listings_json


def adapt_scraper_format(raw_data, collected_at: str) -> dict:
    """Convert Ninja Scraper area-list format to normalizer dict format.

    Scraper produces: [{area, url, cards: [{property_type, price, bedrooms, ...}], card_count, listing_count}, ...]
    Normalizer expects: {scrapedAt, areas: [{area, listingCount, listings: [{price, bedrooms, sqft, type, reducedPrice}]}]}
    """
    if isinstance(raw_data, dict) and "scrapedAt" in raw_data:
        return raw_data  # Already in expected format

    if not isinstance(raw_data, list):
        raise ValueError(f"Unexpected data type: {type(raw_data).__name__}")

    areas = []
    for item in raw_data:
        cards = item.get("cards") or []

        # Convert card fields to normalizer format
        listings = []
        for card in cards:
            # Parse price string "33,500,000 AED" or "7,500,000 AEDHigh demand~ 16K Mortgage Cashback" -> float
            price = None
            price_str = card.get("price", "")
            if price_str and isinstance(price_str, str):
                # Remove "AED" and everything after it that's not numeric
                cleaned = re.sub(r'AED.*$', '', price_str).strip()
                m = re.match(r'[\d,]+\.?\d*', cleaned)
                if m:
                    try:
                        price = float(m.group(0).replace(",", ""))
                    except ValueError:
                        price = None
            elif isinstance(price_str, (int, float)):
                price = float(price_str)

            # Parse bedrooms string "4" -> int
            bedrooms = None
            bed_val = card.get("bedrooms")
            if bed_val is not None:
                try:
                    bedrooms = int(str(bed_val).strip())
                except ValueError:
                    bedrooms = None

            # Parse sqft string "4,567 sqft" -> float
            sqft = None
            sqft_str = card.get("area_sqft", "")
            if sqft_str and isinstance(sqft_str, str):
                try:
                    sqft = float(sqft_str.replace(",", "").replace("sqft", "").strip())
                except ValueError:
                    sqft = None
            elif isinstance(sqft_str, (int, float)):
                sqft = float(sqft_str)

            listings.append({
                "price": price,
                "bedrooms": bedrooms,
                "sqft": sqft,
                "type": card.get("property_type"),
                "reducedPrice": False,  # PropertyFinder cards don't have reduced badge in current scraper
            })

        areas.append({
            "area": item.get("area", "unknown"),
            "listingCount": item.get("card_count") or len(cards),
            "listings": listings,
        })

    return {
        "scrapedAt": collected_at,
        "areas": areas,
    }


def normalize_propertyfinder(
    data: dict, collected_at: str
) -> list[dict[str, Any]]:
    """
    Normalize PropertyFinder listing data to monthly metrics.

    Uses same logic as Bayut normalization for consistent cross-validation.
    """
    # Validate JSON structure
    validate_listings_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    for area_data in data["areas"]:
        area = area_data["area"]
        listings = area_data["listings"]

        if not listings:
            # No listings for this area - still record zero count
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{area}|all|active_listing_count",
                "value": 0,
                "available_date": collected_at,
            })
            continue

        # Convert listings to DataFrame
        df = pd.DataFrame(listings)

        # Area-level metrics (all property types)
        total_count = len(df)
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{area}|all|active_listing_count",
            "value": total_count,
            "available_date": collected_at,
        })

        # Median asking price (area-level)
        prices = df["price"].dropna()
        if not prices.empty:
            median_price = prices.median()
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{area}|all|median_asking_price",
                "value": float(median_price),
                "available_date": collected_at,
            })

        # Price reduction count (area-level)
        reduction_count = df["reducedPrice"].sum()  # Boolean sum = count of True
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{area}|all|price_reduction_count",
            "value": int(reduction_count),
            "available_date": collected_at,
        })

        # Per property type metrics (if type field exists)
        if "type" in df.columns:
            type_grouped = df.groupby("type", dropna=False)

            for prop_type, group in type_grouped:
                if pd.isna(prop_type):
                    continue

                # Normalize type name (lowercase, spaces to underscores)
                normalized_type = str(prop_type).lower().replace(" ", "_")

                # Active listing count
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"{area}|{normalized_type}|active_listing_count",
                    "value": len(group),
                    "available_date": collected_at,
                })

                # Median asking price
                type_prices = group["price"].dropna()
                if not type_prices.empty:
                    type_median_price = type_prices.median()
                    metrics.append({
                        "measurement_date": measurement_date,
                        "metric_name": f"{area}|{normalized_type}|median_asking_price",
                        "value": float(type_median_price),
                        "available_date": collected_at,
                    })

                # Price reduction count
                type_reduction_count = group["reducedPrice"].sum()
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"{area}|{normalized_type}|price_reduction_count",
                    "value": int(type_reduction_count),
                    "available_date": collected_at,
                })

    return metrics


def main() -> None:
    """
    Main entry point.

    Reads {filePath, source, collectedAt} from stdin.
    Outputs normalized metrics as JSON to stdout.
    """
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        # Load JSON file
        with open(file_path, "r") as f:
            raw_data = json.load(f)

        # Adapt scraper list-of-areas format to normalizer dict format
        data = adapt_scraper_format(raw_data, collected_at)

        # Normalize
        metrics = normalize_propertyfinder(data, collected_at)

        # Output metrics
        print(json.dumps(metrics, indent=2))

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
