#!/usr/bin/env python3
"""
MOHRE work permits normalization module.

Reads scraped MOHRE press release/statistical report data (JSON) and produces
normalized monthly metrics:

Dubai-level metrics:
- dubai|mohre_total_permits
- dubai|mohre_permits_tech
- dubai|mohre_permits_construction
- dubai|mohre_permits_hospitality
- dubai|mohre_permits_finance
- dubai|mohre_permits_healthcare

All metrics include available_date (NORM-02 compliance).

Handles both press release text and structured statistical report tables.
"""

import json
import re
import sys
from typing import Any

import pandas as pd

from .schemas.mohre_schema import validate_mohre_json


def extract_permit_numbers(text: str) -> dict[str, int]:
    """
    Extract work permit numbers from press release text.

    Patterns:
    - "X,XXX work permits"
    - "X,XXX new permits issued"
    - Sector breakdown tables or lists
    """
    results = {}

    # Total permits pattern
    total_pattern = r'(\d{1,3}(?:,\d{3})*)\s*(?:work\s+)?permits?\s*(?:issued|granted)?'
    matches = re.findall(total_pattern, text.lower())
    if matches:
        # Take the largest number (likely total)
        numbers = [int(m.replace(',', '')) for m in matches]
        results['total'] = max(numbers)

    # Sector keywords
    sectors = {
        'tech': ['technology', 'it sector', 'software', 'digital', 'tech sector'],
        'construction': ['construction', 'building', 'civil engineering'],
        'hospitality': ['hospitality', 'hotel', 'tourism', 'f&b', 'food and beverage'],
        'finance': ['finance', 'banking', 'financial services'],
        'healthcare': ['healthcare', 'medical', 'health sector', 'hospital']
    }

    for sector, keywords in sectors.items():
        for keyword in keywords:
            # Look for numbers near sector keywords
            pattern = rf'{keyword}[:\s]+(\d{{1,3}}(?:,\d{{3}})*)'
            match = re.search(pattern, text.lower())
            if match:
                results[sector] = int(match.group(1).replace(',', ''))
                break

    return results


def normalize_mohre(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize MOHRE work permit data to monthly metrics.

    Extracts total permits and sector breakdown from press releases or
    statistical reports.
    """
    # Validate JSON structure
    validate_mohre_json(data)

    # Extract measurement date from scrapedAt (use start of month)
    scraped_at = pd.to_datetime(data["scrapedAt"])
    measurement_date = scraped_at.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    # Check if we have any articles with data
    if not data["articles"]:
        # No data - return empty (will trigger empty collection warning)
        return metrics

    # Aggregate permit data across all articles
    total_permits = 0
    sector_permits = {
        'tech': 0,
        'construction': 0,
        'hospitality': 0,
        'finance': 0,
        'healthcare': 0
    }

    for article in data["articles"]:
        # Extract from structured fields if available
        if article.get("total_permits"):
            total_permits += article["total_permits"]

        # Extract sector breakdown if available
        if article.get("sector_breakdown"):
            for sector, count in article["sector_breakdown"].items():
                sector_lower = sector.lower()
                if sector_lower in sector_permits:
                    sector_permits[sector_lower] += count

        # Fall back to text extraction
        full_text = article.get("full_text", "")
        if full_text:
            extracted = extract_permit_numbers(full_text)
            if 'total' in extracted and total_permits == 0:
                total_permits = extracted['total']

            for sector in sector_permits:
                if sector in extracted:
                    sector_permits[sector] += extracted[sector]

    # Generate metrics only if we have data
    if total_permits > 0:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|mohre_total_permits",
            "value": int(total_permits),
            "available_date": collected_at,
        })

    # Add sector metrics
    for sector, count in sector_permits.items():
        if count > 0:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"dubai|mohre_permits_{sector}",
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

        # Load raw MOHRE data
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Add source to raw data
        raw_data["source"] = input_data["source"]

        # Normalize
        normalized = normalize_mohre(raw_data, collected_at)

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
