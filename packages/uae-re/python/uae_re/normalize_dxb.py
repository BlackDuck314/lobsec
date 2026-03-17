#!/usr/bin/env python3
"""
DXB airport passengers normalization module.

Reads DXB HTML fact file JSON (paragraphs array) and produces normalized metrics:

Dubai-level metrics:
- dubai|dxb_annual_passengers
- dubai|dxb_yoy_growth_pct
- dubai|dxb_flight_movements
- dubai|dxb_q4_passengers
- dubai|dxb_busiest_month_passengers
- dubai|dxb_top_market_passengers

All metrics include available_date (NORM-02 compliance).
Data is ANNUAL — measurement_date is Jan 1 of the reference year.
"""

import json
import re
import sys
from typing import Any

from .schemas.dxb_schema import validate_dxb_json


def extract_reference_year(text: str) -> int | None:
    """Extract the reference year from DXB fact file text (e.g., '2025 Annual Traffic')."""
    match = re.search(r'(\d{4})\s+annual\s+traffic', text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    # Fallback: look for any 4-digit year near "annual"
    match = re.search(r'annual.*?(\d{4})|(\d{4}).*?annual', text, re.IGNORECASE)
    if match:
        return int(match.group(1) or match.group(2))
    return None


def normalize_dxb(paragraphs: list[str], collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DXB airport fact file paragraphs to annual metrics.

    Args:
        paragraphs: List of text paragraphs from the fact file HTML scrape.
        collected_at: ISO timestamp of collection.

    Returns:
        List of normalized metric records.
    """
    import pandas as pd

    # Join all paragraphs for regex matching
    text = "\n".join(p for p in paragraphs if isinstance(p, str))
    text_lower = text.lower()

    # Determine reference year
    ref_year = extract_reference_year(text)
    if ref_year is None:
        # Fall back to prior year (fact file published in current year for prior year)
        collected = pd.to_datetime(collected_at)
        ref_year = collected.year - 1

    measurement_date = f"{ref_year}-01-01"
    metrics = []

    # 1. Annual passengers: "95.2 million guests"
    annual_match = re.search(
        r'annual\s+traffic\s+(?:with|of)\s+([\d.]+)\s*million\s*(?:guests|passengers)',
        text_lower,
    )
    if annual_match:
        annual_pax = float(annual_match.group(1)) * 1_000_000
        if annual_pax > 10_000_000:  # Sanity check
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dxb_annual_passengers",
                "value": annual_pax,
                "available_date": collected_at,
            })

    # 2. YoY growth: "up 3.1% YoY"
    yoy_match = re.search(
        r'up\s+([\d.]+)\s*%\s*(?:y[/\-]?o[/\-]?y|year.on.year)',
        text_lower,
    )
    if yoy_match:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dxb_yoy_growth_pct",
            "value": float(yoy_match.group(1)),
            "available_date": collected_at,
        })

    # 3. Flight movements: "454,800"
    flight_match = re.search(
        r'flight\s+movements?\s+(?:reached|totale?d)\s+([\d,]+)',
        text_lower,
    )
    if flight_match:
        movements = int(flight_match.group(1).replace(",", ""))
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dxb_flight_movements",
            "value": movements,
            "available_date": collected_at,
        })

    # 4. Q4 passengers: "Q4...25.1 million guests"
    q4_match = re.search(
        r'q4.*?([\d.]+)\s*million\s*(?:guests|passengers)',
        text_lower,
    )
    if q4_match:
        q4_pax = float(q4_match.group(1)) * 1_000_000
        metrics.append({
            "measurement_date": f"{ref_year}-10-01",  # Q4 starts Oct 1
            "metric_name": "dubai|dxb_q4_passengers",
            "value": q4_pax,
            "available_date": collected_at,
        })

    # 5. Busiest month passengers: "8.7 million guests"
    busiest_match = re.search(
        r'(?:busiest\s+month|december).*?([\d.]+)\s*million\s*(?:guests|passengers)',
        text_lower,
    )
    if busiest_match:
        busiest_pax = float(busiest_match.group(1)) * 1_000_000
        metrics.append({
            "measurement_date": f"{ref_year}-12-01",  # December
            "metric_name": "dubai|dxb_busiest_month_passengers",
            "value": busiest_pax,
            "available_date": collected_at,
        })

    # 6. Top market: "India (11.9m)"
    market_match = re.search(
        r'(?:top\s+destination\s+countries?|top\s+markets?)[:\s]+(\w[\w\s]+?)\s*\(([\d.]+)m\)',
        text_lower,
    )
    if market_match:
        top_market_pax = float(market_match.group(2)) * 1_000_000
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|dxb_top_market_passengers",
            "value": top_market_pax,
            "available_date": collected_at,
        })

    return metrics


def main() -> None:
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads and validates JSON file, normalizes, and outputs to stdout.
    """
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        # Validate and load JSON file
        data = validate_dxb_json(file_path)

        # Concatenate all paragraphs from all pages
        all_paragraphs = []
        for page in data:
            all_paragraphs.extend(page.get("paragraphs", []))

        # Normalize
        normalized = normalize_dxb(all_paragraphs, collected_at)

        # Add source field to each record
        for record in normalized:
            record["source"] = input_data["source"]

        json.dump(normalized, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
