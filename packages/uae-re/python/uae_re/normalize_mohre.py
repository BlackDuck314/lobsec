#!/usr/bin/env python3
"""
MOHRE Observatory normalization module.

Reads MOHRE Observatory dashboard JSON (stat_cards + chart_labels) and produces
normalized annual metrics:

UAE-level metrics (from stat_cards):
- uae|mohre_workforce_growth_pct
- uae|mohre_establishment_growth_pct
- uae|mohre_emiratisation_count
- uae|mohre_skilled_worker_growth_pct
- uae|mohre_female_leadership_pct
- uae|mohre_youth_workforce_pct

UAE-level metrics (from chart_labels):
- uae|mohre_emiratisation_yearly (time series 2021-2025)

All metrics include available_date (NORM-02 compliance).
Data is ANNUAL -- measurement_date is Jan 1 of the reference year.
"""

import json
import re
import sys
from typing import Any

from .schemas.mohre_schema import validate_mohre_json


def extract_stat_card_metrics(
    stat_cards: list[str], collected_at: str
) -> list[dict[str, Any]]:
    """Extract metrics from MOHRE stat_cards text blocks."""
    metrics = []
    seen_labels: set[str] = set()

    # Determine reference year from cards
    ref_year = None
    for card in stat_cards:
        year_match = re.search(r'in\s+(\d{4})', card)
        if year_match:
            ref_year = int(year_match.group(1))
            break

    if ref_year is None:
        ref_year = int(collected_at[:4])

    measurement_date = f"{ref_year}-01-01"

    # Metric mapping: (label keyword(s), metric_name, is_count)
    METRIC_MAP = [
        (["workforce growth"], "uae|mohre_workforce_growth_pct", False),
        (["establishment growth"], "uae|mohre_establishment_growth_pct", False),
        (["total uae national"], "uae|mohre_emiratisation_count", True),
        (["skilled worker", "growth"], "uae|mohre_skilled_worker_growth_pct", False),
        (["female workers", "leadership"], "uae|mohre_female_leadership_pct", False),
        (["youth workforce"], "uae|mohre_youth_workforce_pct", False),
    ]

    for card in stat_cards:
        if not isinstance(card, str) or len(card.strip()) < 3:
            continue

        # Pattern: "176,125\n Total UAE National Employees..." or "12.4 %\n Workforce Growth..."
        matches = re.findall(
            r'([\d,]+\.?\d*)\s*%?\s*\n\s+(.*?)(?:\n|$)', card
        )

        for value_str, label in matches:
            label_lower = label.strip().lower()

            for keywords, metric_name, is_count in METRIC_MAP:
                if all(kw in label_lower for kw in keywords):
                    if metric_name in seen_labels:
                        continue  # De-duplicate
                    seen_labels.add(metric_name)

                    value = float(value_str.replace(",", ""))
                    if is_count:
                        value = int(value)

                    metrics.append({
                        "measurement_date": measurement_date,
                        "metric_name": metric_name,
                        "value": value,
                        "available_date": collected_at,
                    })
                    break

    return metrics


def extract_emiratisation_chart(
    chart_labels: list[str], collected_at: str
) -> list[dict[str, Any]]:
    """Extract Emiratisation yearly time series from Chart.js configs."""
    metrics = []

    for label_str in chart_labels:
        if not isinstance(label_str, str):
            continue

        # Only process the Emiratisation chart
        if "uae nationals" not in label_str.lower() and "emirat" not in label_str.lower():
            continue

        # Extract labels (years) and data (counts)
        year_match = re.search(r'labels:\[([^\]]+)\]', label_str)
        data_match = re.search(r'data:\[([^\]]+)\]', label_str)

        if year_match and data_match:
            years = [y.strip().strip('"').strip("'") for y in year_match.group(1).split(",")]
            values = [float(v.strip()) for v in data_match.group(1).split(",")]

            for year_str, value in zip(years, values):
                try:
                    year = int(year_str)
                except ValueError:
                    continue

                metrics.append({
                    "measurement_date": f"{year}-01-01",
                    "metric_name": "uae|mohre_emiratisation_yearly",
                    "value": int(value),
                    "available_date": collected_at,
                })

            break  # Only process first matching chart

    return metrics


def normalize_mohre(
    stat_cards: list[str], chart_labels: list[str], collected_at: str
) -> list[dict[str, Any]]:
    """
    Normalize MOHRE Observatory data to annual metrics.

    Args:
        stat_cards: List of stat card text blocks.
        chart_labels: List of Chart.js config strings.
        collected_at: ISO timestamp of collection.

    Returns:
        List of normalized metric records.
    """
    metrics = []
    metrics.extend(extract_stat_card_metrics(stat_cards, collected_at))
    metrics.extend(extract_emiratisation_chart(chart_labels, collected_at))
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
        data = validate_mohre_json(file_path)

        # Aggregate stat_cards and chart_labels from all pages
        all_stat_cards = []
        all_chart_labels = []
        for page in data:
            all_stat_cards.extend(page.get("stat_cards", []))
            all_chart_labels.extend(page.get("chart_labels", []))

        # Normalize
        normalized = normalize_mohre(all_stat_cards, all_chart_labels, collected_at)

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
