#!/usr/bin/env python3
"""
DXB airport passengers normalization module.

Reads DXB PDF factsheets and produces normalized monthly metrics:

Dubai-level metrics:
- dubai|dxb_total_passengers
- dubai|dxb_arrivals
- dubai|dxb_departures
- dubai|dxb_transit

All metrics include available_date (NORM-02 compliance).

Uses pdfplumber for table extraction from PDF factsheets.
"""

import json
import sys
from typing import Any

import pandas as pd
import pdfplumber

from .schemas.dxb_schema import validate_dxb_pdf


def extract_passenger_tables(pdf_path: str) -> dict[str, Any]:
    """
    Extract passenger statistics from DXB PDF factsheet.

    Expected structure:
    - First 3-5 pages: Summary tables with passenger counts
    - Headers: "Passengers", "Arrivals", "Departures", "Transit"

    Returns dict with extracted values.
    """
    data = {
        "total_passengers": None,
        "arrivals": None,
        "departures": None,
        "transit": None,
    }

    with pdfplumber.open(pdf_path) as pdf:
        # Target first 5 pages (summary section)
        for page_num in range(min(5, len(pdf.pages))):
            page = pdf.pages[page_num]
            tables = page.extract_tables()

            for table in tables:
                if not table or len(table) < 2:
                    continue

                # Identify table by header keywords
                header = " ".join(str(cell) for cell in table[0] if cell).lower()

                if "passenger" in header or "traffic" in header:
                    # Process passenger table
                    for row in table[1:]:
                        if len(row) < 2:
                            continue

                        label = str(row[0]).lower() if row[0] else ""

                        # Find value column (first numeric column)
                        value = None
                        for cell in row[1:]:
                            if cell:
                                value_str = str(cell).replace(',', '').replace(' ', '')
                                try:
                                    value = int(value_str)
                                    break
                                except ValueError:
                                    continue

                        if value is None:
                            continue

                        if "total" in label and "passenger" in label:
                            data["total_passengers"] = value
                        elif "arrival" in label:
                            data["arrivals"] = value
                        elif "departure" in label:
                            data["departures"] = value
                        elif "transit" in label:
                            data["transit"] = value

    # Sanity check: DXB handles millions of passengers/month
    if data["total_passengers"] and data["total_passengers"] < 100_000:
        raise ValueError(f"Total passengers {data['total_passengers']} is suspiciously low (expected >100K)")

    return data


def normalize_dxb(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DXB airport PDF data to monthly metrics.

    Extracts passenger counts via pdfplumber table extraction.
    """
    # Validate PDF exists
    validate_dxb_pdf(file_path)

    # Extract measurement date from collected_at (use start of month)
    collected = pd.to_datetime(collected_at)
    measurement_date = collected.to_period("M").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    try:
        # Extract data from PDF
        extracted = extract_passenger_tables(file_path)

        # Generate metrics
        if extracted["total_passengers"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dxb_total_passengers",
                "value": int(extracted["total_passengers"]),
                "available_date": collected_at,
            })

        if extracted["arrivals"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dxb_arrivals",
                "value": int(extracted["arrivals"]),
                "available_date": collected_at,
            })

        if extracted["departures"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dxb_departures",
                "value": int(extracted["departures"]),
                "available_date": collected_at,
            })

        if extracted["transit"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|dxb_transit",
                "value": int(extracted["transit"]),
                "available_date": collected_at,
            })

    except Exception as e:
        # PDF extraction failed - output error for Telegram manual-entry fallback
        raise ValueError(
            f"DXB PDF extraction failed. Please provide manually: "
            f"total_passengers, arrivals, departures, transit. Error: {e}"
        )

    return metrics


def main():
    """
    Main entry point for Python normalization bridge.

    Reads JSON input from stdin (format: {filePath, source, collectedAt}),
    loads PDF, normalizes, and outputs to stdout.
    """
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        # Normalize (PDF file path is the input)
        normalized = normalize_dxb(file_path, collected_at)

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
