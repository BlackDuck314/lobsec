#!/usr/bin/env python3
"""
Bayut listing normalization module.

Reads scraped Bayut listing data (JSON) and produces normalized monthly metrics:

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

Price reduction count is detected from portal badges during scraping
(reducedPrice field in JSON). This is a single-scrape metric, not a
historical comparison.
"""

import json
import re
import sys
from typing import Any

import pandas as pd

from .schemas.listings_schema import validate_listings_json


def adapt_scraper_format(raw_data, collected_at: str) -> dict:
    """Convert Ninja Scraper area-list format to normalizer dict format.

    Bayut scraper produces: [{area, url, listing_count, property_cards, price, bedrooms, sqft, reduced_badge}, ...]
    When CAPTCHA-blocked, ALL fields except area/url are null.
    Normalizer expects: {scrapedAt, areas: [{area, listingCount, listings: [{price, bedrooms, sqft, type, reducedPrice}]}]}
    """
    if isinstance(raw_data, dict) and "scrapedAt" in raw_data:
        return raw_data  # Already in expected format

    if not isinstance(raw_data, list):
        raise ValueError(f"Unexpected data type: {type(raw_data).__name__}")

    areas = []
    for item in raw_data:
        # Bayut uses "property_cards" or "cards" key
        cards = item.get("property_cards") or item.get("cards") or []
        # If cards is None (CAPTCHA blocked), treat as empty list
        if cards is None:
            cards = []

        listings = []
        for card in cards:
            # Parse price (may be string "1,500,000 AED" or None)
            price = None
            price_str = card.get("price", "")
            if price_str and isinstance(price_str, str):
                cleaned = re.sub(r'AED.*$', '', price_str).strip()
                m = re.match(r'[\d,]+\.?\d*', cleaned)
                if m:
                    try:
                        price = float(m.group(0).replace(",", ""))
                    except ValueError:
                        price = None
            elif isinstance(price_str, (int, float)):
                price = float(price_str)

            # Parse bedrooms
            bedrooms = None
            bed_val = card.get("bedrooms")
            if bed_val is not None:
                try:
                    bedrooms = int(str(bed_val).strip())
                except ValueError:
                    bedrooms = None

            # Parse sqft (Bayut uses "sqft" not "area_sqft")
            sqft = None
            sqft_str = card.get("sqft") or card.get("area_sqft", "")
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
                "reducedPrice": bool(card.get("reduced_badge") or card.get("reducedPrice", False)),
            })

        # listing_count from scraper or card_count or len(cards)
        listing_count = item.get("listing_count") or item.get("card_count") or len(cards)
        # listing_count may be None (CAPTCHA blocked)
        if listing_count is None:
            listing_count = 0

        areas.append({
            "area": item.get("area", "unknown"),
            "listingCount": listing_count,
            "listings": listings,
        })

    return {
        "scrapedAt": collected_at,
        "areas": areas,
    }


def normalize_bayut(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize Bayut listing data to monthly metrics.

    Aggregates by area (and property type) to produce listing market metrics.
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
        metrics = normalize_bayut(data, collected_at)

        # Output metrics
        print(json.dumps(metrics, indent=2))

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
