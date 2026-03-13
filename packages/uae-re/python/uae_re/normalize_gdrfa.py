#!/usr/bin/env python3
"""
GDRFA visa transactions normalization module.

Reads GDRFA quarterly PDF reports and produces normalized quarterly metrics:

Dubai-level metrics:
- dubai|gdrfa_total_issued
- dubai|gdrfa_employment_visa
- dubai|gdrfa_golden_visa
- dubai|gdrfa_family_visa
- dubai|gdrfa_total_cancelled
- dubai|gdrfa_net_flow

All metrics include available_date (NORM-02 compliance).

Uses pdfplumber for table extraction from quarterly PDF reports.
"""

import json
import sys
from typing import Any

import pandas as pd
import pdfplumber

from .schemas.gdrfa_schema import validate_gdrfa_pdf


def extract_visa_tables(pdf_path: str) -> dict[str, Any]:
    """
    Extract visa statistics from GDRFA quarterly PDF.

    Expected structure:
    - Pages 2-5: Visa statistics tables
    - Tables: Visa Issuances by Type, Visa Cancellations, Golden Visa breakdown

    Returns dict with extracted values.
    """
    data = {
        "total_issued": None,
        "employment_visa": None,
        "golden_visa": None,
        "family_visa": None,
        "total_cancelled": None,
        "net_flow": None,
    }

    with pdfplumber.open(pdf_path) as pdf:
        # Target pages 2-5 (0-indexed: 1-4)
        for page_num in range(1, min(5, len(pdf.pages))):
            page = pdf.pages[page_num]
            tables = page.extract_tables()

            for table in tables:
                if not table or len(table) < 2:
                    continue

                # Identify table by header keywords
                header = " ".join(str(cell) for cell in table[0] if cell).lower()

                if "visa" in header and "issued" in header:
                    # Process issuance table
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

                        if "employment" in label or "work" in label:
                            data["employment_visa"] = value
                        elif "golden" in label:
                            data["golden_visa"] = value
                        elif "family" in label or "residence" in label:
                            data["family_visa"] = value
                        elif "total" in label:
                            data["total_issued"] = value

                if "cancellation" in header or "cancelled" in header:
                    # Process cancellation table
                    for row in table[1:]:
                        if len(row) < 2:
                            continue

                        label = str(row[0]).lower() if row[0] else ""
                        if "total" in label:
                            # Find value column
                            for cell in row[1:]:
                                if cell:
                                    value_str = str(cell).replace(',', '').replace(' ', '')
                                    try:
                                        data["total_cancelled"] = int(value_str)
                                        break
                                    except ValueError:
                                        continue

    # Compute net flow
    if data["total_issued"] and data["total_cancelled"]:
        data["net_flow"] = data["total_issued"] - data["total_cancelled"]

    return data


def normalize_gdrfa(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize GDRFA visa PDF data to quarterly metrics.

    Extracts visa statistics via pdfplumber table extraction.
    """
    # Validate PDF exists
    validate_gdrfa_pdf(file_path)

    # Extract measurement date from collected_at (use start of quarter)
    collected = pd.to_datetime(collected_at)
    measurement_date = collected.to_period("Q").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    try:
        # Extract data from PDF
        extracted = extract_visa_tables(file_path)

        # Generate metrics
        if extracted["total_issued"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|gdrfa_total_issued",
                "value": int(extracted["total_issued"]),
                "available_date": collected_at,
            })

        if extracted["employment_visa"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|gdrfa_employment_visa",
                "value": int(extracted["employment_visa"]),
                "available_date": collected_at,
            })

        if extracted["golden_visa"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|gdrfa_golden_visa",
                "value": int(extracted["golden_visa"]),
                "available_date": collected_at,
            })

        if extracted["family_visa"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|gdrfa_family_visa",
                "value": int(extracted["family_visa"]),
                "available_date": collected_at,
            })

        if extracted["total_cancelled"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|gdrfa_total_cancelled",
                "value": int(extracted["total_cancelled"]),
                "available_date": collected_at,
            })

        if extracted["net_flow"] is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|gdrfa_net_flow",
                "value": int(extracted["net_flow"]),
                "available_date": collected_at,
            })

    except Exception as e:
        # PDF extraction failed - output error for Telegram manual-entry fallback
        raise ValueError(
            f"GDRFA PDF extraction failed. Please provide manually: "
            f"total_issued, employment_visa, golden_visa, family_visa, "
            f"total_cancelled. Error: {e}"
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
        normalized = normalize_gdrfa(file_path, collected_at)

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
