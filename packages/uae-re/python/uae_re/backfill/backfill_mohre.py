#!/usr/bin/env python3
"""
MOHRE Observatory historical backfill.

Extracts comparative prior-year values from stat card text and unnamed
chart time series (charts 0, 2, 4, 6) from the existing MOHRE JSON.

The stat cards contain phrases like "12.4% compared to 10.9% in 2024"
which give us the 2024 value for that metric.

Charts 0, 2, 4, 6 have unnamed 2021-2025 time series. These are extracted
as fallback ONLY if the total mohre-permits row count is < 16 after
comparative extraction.

Expected: 1 comparative row + up to 20 chart rows if fallback needed.
Target: 16+ total mohre-permits rows.
"""

import json
import re
import sqlite3
import sys

from . import DB_PATH, insert_metric

JSON_PATH = "/opt/lobsec/data/raw/mohre-permits/2026-03-17.json"
SOURCE = "mohre-permits"
AVAILABLE_DATE = "2026-03-17T00:00:00Z"

# Metric mapping for stat card comparative extraction
COMPARATIVE_MAP = [
    (["workforce growth"], "uae|mohre_workforce_growth_pct"),
    (["establishment growth"], "uae|mohre_establishment_growth_pct"),
    (["skilled worker", "growth"], "uae|mohre_skilled_worker_growth_pct"),
    (["female workers", "leadership"], "uae|mohre_female_leadership_pct"),
    (["youth workforce"], "uae|mohre_youth_workforce_pct"),
]

# Comparative regex: "12.4% compared to 10.9% in 2024"
COMPARATIVE_RE = re.compile(
    r'([\d,.]+)\s*%?\s*compared\s+to\s+([\d,.]+)\s*%?\s*in\s+(\d{4})',
    re.IGNORECASE,
)


def extract_comparative_values(stat_cards: list[str]) -> list[tuple[str, float, int]]:
    """
    Extract prior-year comparative values from stat card text.

    Returns list of (metric_name, value, year) tuples.
    """
    results: list[tuple[str, float, int]] = []
    seen_metrics: set[str] = set()

    for card in stat_cards:
        if not isinstance(card, str):
            continue

        # Find all comparative patterns in this card
        for match in COMPARATIVE_RE.finditer(card):
            prior_value = float(match.group(2).replace(",", ""))
            prior_year = int(match.group(3))

            # Find surrounding context (200 chars before match) to identify metric
            start = max(0, match.start() - 200)
            context = card[start : match.end()].lower()

            for keywords, metric_name in COMPARATIVE_MAP:
                if metric_name in seen_metrics:
                    continue
                if all(kw in context for kw in keywords):
                    results.append((metric_name, prior_value, prior_year))
                    seen_metrics.add(metric_name)
                    break

    return results


def extract_chart_data(chart_labels: list[str]) -> list[tuple[str, list[tuple[int, float]]]]:
    """
    Extract time series data from unnamed charts (0, 2, 4, 6).

    Returns list of (metric_name, [(year, value), ...]) tuples.
    """
    chart_metrics = [
        (0, "uae|mohre_chart_0_index"),
        (2, "uae|mohre_chart_2_index"),
        (4, "uae|mohre_chart_4_index"),
        (6, "uae|mohre_chart_6_index"),
    ]

    results: list[tuple[str, list[tuple[int, float]]]] = []

    for chart_idx, metric_name in chart_metrics:
        if chart_idx >= len(chart_labels):
            continue

        cl = chart_labels[chart_idx]
        if not isinstance(cl, str) or not cl.strip():
            continue

        labels_m = re.search(r'labels:\[([^\]]+)\]', cl)
        data_m = re.search(r'data:\[([^\]]+)\]', cl)

        if labels_m and data_m:
            years = [
                y.strip().strip('"').strip("'")
                for y in labels_m.group(1).split(",")
            ]
            values = [float(v.strip()) for v in data_m.group(1).split(",")]

            series = []
            for year_str, value in zip(years, values):
                try:
                    year = int(year_str)
                    series.append((year, value))
                except ValueError:
                    continue

            if series:
                results.append((metric_name, series))

    return results


def main() -> None:
    """Run MOHRE Observatory backfill."""
    print("=== MOHRE Observatory Backfill ===")

    with open(JSON_PATH) as f:
        data = json.load(f)

    # Aggregate stat_cards and chart_labels from all pages
    all_stat_cards: list[str] = []
    all_chart_labels: list[str] = []
    for page in data:
        all_stat_cards.extend(page.get("stat_cards", []))
        all_chart_labels.extend(page.get("chart_labels", []))

    db = sqlite3.connect(DB_PATH)
    inserted = 0

    try:
        # Step 1: Extract comparative values from stat cards
        comparatives = extract_comparative_values(all_stat_cards)
        for metric_name, value, year in comparatives:
            insert_metric(
                db, SOURCE, f"{year}-01-01", metric_name, value, AVAILABLE_DATE,
            )
            inserted += 1
            print(f"  Comparative: {metric_name} = {value} ({year})")

        db.commit()

        # Step 2: Check if we need chart fallback
        cursor = db.execute(
            "SELECT COUNT(*) FROM normalized_monthly WHERE source=?", (SOURCE,)
        )
        current_count = cursor.fetchone()[0]
        print(f"\n  Current {SOURCE} rows: {current_count}")

        if current_count < 16:
            print("  Below 16 rows -- extracting unnamed charts as fallback")
            chart_data = extract_chart_data(all_chart_labels)

            for metric_name, series in chart_data:
                for year, value in series:
                    insert_metric(
                        db, SOURCE, f"{year}-01-01", metric_name, value, AVAILABLE_DATE,
                    )
                    inserted += 1
                print(f"  Chart: {metric_name} = {len(series)} years ({series[0][0]}-{series[-1][0]})")

            db.commit()

        # Final count
        cursor = db.execute(
            "SELECT COUNT(*) FROM normalized_monthly WHERE source=?", (SOURCE,)
        )
        total = cursor.fetchone()[0]
        print(f"\nInserted {inserted} new rows for source '{SOURCE}'")
        print(f"Total {SOURCE} rows in DB: {total}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
