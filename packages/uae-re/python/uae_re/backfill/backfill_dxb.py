#!/usr/bin/env python3
"""
DXB Airport historical backfill.

Downloads 3 press release pages from media.dubaiairports.ae and extracts
annual passenger data for 2022, 2023, and 2024.

Falls back to hardcoded known values if download fails (verified historical
facts from official Dubai Airports press releases).

Inserts:
- dubai|dxb_annual_passengers for 2022, 2023, 2024
- dubai|dxb_yoy_growth_pct for 2023 and 2024
- dubai|dxb_flight_movements for 2022 and 2024
- dubai|dxb_q4_passengers for 2022 and 2023
- dubai|dxb_cargo_tonnes for 2023 and 2024

Expected: 10-14 new rows across 2022-2024.
"""

import re
import sqlite3
import sys
from typing import Any

from . import DB_PATH, insert_metric

SOURCE = "dxb-passengers"

# Press release URLs
PRESS_RELEASES = {
    2022: "https://media.dubaiairports.ae/dxb-has-a-banner-year-with-annual-traffic-exceeding-66m-passengers-in-2022/",
    2023: "https://media.dubaiairports.ae/dxb-smashes-targets-with-87-million-guests-in-2023-rising-317-from-previous-year/",
    2024: "https://media.dubaiairports.ae/dxb-records-highest-annual-traffic-in-2024-celebrating-a-decade-as-the-worlds-busiest-international-airport/",
}

# Known data from research (verified via WebFetch of press releases)
# Used as fallback if download fails
KNOWN_DATA: dict[int, dict[str, float]] = {
    2022: {
        "dubai|dxb_annual_passengers": 66_069_981,
        "dubai|dxb_flight_movements": 343_339,
        "dubai|dxb_q4_passengers": 19_729_155,
    },
    2023: {
        "dubai|dxb_annual_passengers": 86_994_365,
        "dubai|dxb_q4_passengers": 22_400_000,
        "dubai|dxb_cargo_tonnes": 1_800_000,
    },
    2024: {
        "dubai|dxb_annual_passengers": 92_300_000,
        "dubai|dxb_flight_movements": 440_300,
        "dubai|dxb_cargo_tonnes": 2_200_000,
    },
}

# YoY growth (calculated from known annual figures)
KNOWN_GROWTH: dict[int, float] = {
    # 2022: no 2021 data in scope
    2023: round((86_994_365 - 66_069_981) / 66_069_981 * 100, 1),  # 31.7%
    2024: round((92_300_000 - 86_994_365) / 86_994_365 * 100, 1),  # 6.1%
}


def strip_html(html: str) -> str:
    """Remove HTML tags and decode common entities."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = text.replace("&nbsp;", " ")
    text = text.replace("&amp;", "&")
    text = text.replace("&#8217;", "'")
    text = text.replace("&#8211;", "-")
    text = text.replace("&#8212;", "--")
    return text


def extract_metrics_from_text(text: str, year: int) -> dict[str, float]:
    """
    Extract DXB metrics from press release plain text.

    Returns dict mapping metric_name -> value.
    """
    metrics: dict[str, float] = {}
    text_lower = text.lower()

    # 1. Annual passengers: try exact count first, then million format
    # "66,069,981 passengers" or "66.1 million guests/passengers"
    exact_match = re.search(
        r'([\d,]+)\s*(?:guests|passengers)\s*(?:in\s+\d{4}|during)',
        text_lower,
    )
    if exact_match:
        pax = int(exact_match.group(1).replace(",", ""))
        if pax > 10_000_000:
            metrics["dubai|dxb_annual_passengers"] = pax

    if "dubai|dxb_annual_passengers" not in metrics:
        # Try "XX million guests/passengers"
        million_match = re.search(
            r'([\d.]+)\s*million\s*(?:guests|passengers)',
            text_lower,
        )
        if million_match:
            pax = float(million_match.group(1)) * 1_000_000
            if pax > 10_000_000:
                metrics["dubai|dxb_annual_passengers"] = pax

    # 2. Flight movements: "343,339 flight movements" or "440,300 flights"
    flight_match = re.search(
        r'([\d,]+)\s*(?:flight\s*movements?|flights?\s*movements?)',
        text_lower,
    )
    if flight_match:
        movements = int(flight_match.group(1).replace(",", ""))
        if movements > 100_000:
            metrics["dubai|dxb_flight_movements"] = movements

    # 3. Q4 passengers: "Q4...XX million" or "fourth quarter...XX million"
    q4_match = re.search(
        r'(?:q4|fourth\s+quarter|oct(?:ober)?\s*-?\s*dec(?:ember)?)[^.]*?([\d,.]+)\s*million\s*(?:guests|passengers)',
        text_lower,
    )
    if q4_match:
        q4_pax = float(q4_match.group(1).replace(",", "")) * 1_000_000
        if q4_pax > 1_000_000:
            metrics["dubai|dxb_q4_passengers"] = q4_pax

    if "dubai|dxb_q4_passengers" not in metrics:
        # Try exact Q4 count
        q4_exact = re.search(
            r'(?:q4|fourth\s+quarter)[^.]*?([\d,]+)\s*(?:guests|passengers)',
            text_lower,
        )
        if q4_exact:
            q4_pax = int(q4_exact.group(1).replace(",", ""))
            if q4_pax > 1_000_000:
                metrics["dubai|dxb_q4_passengers"] = q4_pax

    # 4. Cargo: "X.X million tonnes of cargo" or "cargo...X.X million tonnes"
    cargo_match = re.search(
        r'([\d.]+)\s*million\s*(?:metric\s*)?tonn?e?s?\s*(?:of\s*)?(?:cargo|freight)',
        text_lower,
    )
    if not cargo_match:
        cargo_match = re.search(
            r'cargo[^.]*?([\d.]+)\s*million\s*(?:metric\s*)?tonn?e?s?',
            text_lower,
        )
    if cargo_match:
        cargo = float(cargo_match.group(1)) * 1_000_000
        if cargo > 100_000:
            metrics["dubai|dxb_cargo_tonnes"] = cargo

    return metrics


def download_press_release(url: str) -> str | None:
    """Download a press release page and return its text content."""
    try:
        import requests

        resp = requests.get(url, timeout=30, headers={
            "User-Agent": "Mozilla/5.0 (compatible; lobsec-backfill/1.0)",
        })
        resp.raise_for_status()
        return strip_html(resp.text)
    except Exception as e:
        print(f"  WARNING: Download failed for {url}: {e}", file=sys.stderr)
        return None


def main() -> None:
    """Run DXB historical backfill."""
    print("=== DXB Airport Historical Backfill ===")

    db = sqlite3.connect(DB_PATH)
    inserted = 0

    try:
        for year in sorted(PRESS_RELEASES.keys()):
            url = PRESS_RELEASES[year]
            available_date = f"{year + 1}-01-20T00:00:00Z"
            print(f"\n--- {year} ---")

            # Try downloading press release
            text = download_press_release(url)
            if text:
                extracted = extract_metrics_from_text(text, year)
                print(f"  Extracted {len(extracted)} metrics from press release")
            else:
                extracted = {}
                print("  Using hardcoded known values (download failed)")

            # Merge with known data (known values fill gaps or override bad extractions)
            year_data = KNOWN_DATA.get(year, {}).copy()

            for metric_name, value in extracted.items():
                # Use extracted value if reasonable, otherwise keep known
                if metric_name not in year_data:
                    year_data[metric_name] = value
                else:
                    known_val = year_data[metric_name]
                    # If extracted value is within 5% of known value, use known (more precise)
                    if abs(value - known_val) / known_val < 0.05:
                        pass  # Keep known value
                    else:
                        # Extracted value differs significantly -- use extracted
                        year_data[metric_name] = value

            # Insert all metrics for this year
            for metric_name, value in year_data.items():
                if metric_name == "dubai|dxb_q4_passengers":
                    mdate = f"{year}-10-01"
                else:
                    mdate = f"{year}-01-01"

                insert_metric(db, SOURCE, mdate, metric_name, value, available_date)
                inserted += 1
                print(f"  {metric_name} = {value:,.0f}")

            # Insert YoY growth if available
            if year in KNOWN_GROWTH:
                growth = KNOWN_GROWTH[year]
                insert_metric(
                    db, SOURCE, f"{year}-01-01",
                    "dubai|dxb_yoy_growth_pct", growth, available_date,
                )
                inserted += 1
                print(f"  dubai|dxb_yoy_growth_pct = {growth}%")

        db.commit()
        print(f"\nInserted {inserted} rows for source '{SOURCE}'")

        # Verify
        cursor = db.execute(
            "SELECT COUNT(*) FROM normalized_monthly WHERE source=?", (SOURCE,)
        )
        total = cursor.fetchone()[0]
        print(f"Total {SOURCE} rows in DB: {total}")

        # Show all DXB rows
        print("\nAll DXB rows:")
        for row in db.execute(
            "SELECT metric_name, measurement_date, value FROM normalized_monthly WHERE source=? ORDER BY metric_name, measurement_date",
            (SOURCE,),
        ):
            print(f"  {row[0]} | {row[1]} | {row[2]:,.0f}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
