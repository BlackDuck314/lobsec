#!/usr/bin/env python3
"""
CBUAE remittance outflows normalization module.

Reads CBUAE quarterly balance of payments PDF reports and produces normalized
quarterly metrics:

UAE-level metrics (national data):
- uae|cbuae_personal_remittances
- uae|cbuae_workers_remittances
- uae|cbuae_total_outflows

All metrics include available_date (NORM-02 compliance).

Uses pdfplumber for table extraction from quarterly PDF reports.
Extracts ALL tables from PDF, filters for remittance data during normalization.
"""

import json
import sys
from typing import Any

import pandas as pd
import pdfplumber

from .schemas.remittances_schema import validate_remittances_pdf


def extract_remittance_tables(pdf_path: str) -> dict[str, Any]:
    """
    Extract remittance statistics from CBUAE balance of payments PDF.

    Expected structure:
    - Balance of payments tables throughout PDF
    - Remittance data usually in "Current Account" or "Primary/Secondary Income" sections
    - Values in millions AED (standard CBUAE reporting unit)

    Returns dict with extracted values.
    """
    data = {
        "personal_remittances": None,
        "workers_remittances": None,
        "total_outflows": None,
    }

    with pdfplumber.open(pdf_path) as pdf:
        # Extract ALL tables from entire PDF
        for page_num in range(len(pdf.pages)):
            page = pdf.pages[page_num]
            tables = page.extract_tables()

            for table in tables:
                if not table or len(table) < 2:
                    continue

                # Identify table by header keywords
                header = " ".join(str(cell) for cell in table[0] if cell).lower()

                # Look for remittance-related tables
                if any(keyword in header for keyword in ["remittance", "personal transfers", "workers", "balance of payments"]):
                    # Process remittance table
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
                                    value = float(value_str)
                                    break
                                except ValueError:
                                    continue

                        if value is None:
                            continue

                        if "personal" in label and "remittance" in label:
                            data["personal_remittances"] = value
                        elif "workers" in label and "remittance" in label:
                            data["workers_remittances"] = value
                        elif "total" in label and ("remittance" in label or "outflow" in label):
                            data["total_outflows"] = value

    # If total not found, compute from components
    if data["total_outflows"] is None and data["personal_remittances"] and data["workers_remittances"]:
        data["total_outflows"] = data["personal_remittances"] + data["workers_remittances"]

    return data


def normalize_remittances(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize CBUAE remittance PDF data to quarterly metrics.

    Extracts remittance statistics via pdfplumber table extraction.
    """
    # Validate PDF exists
    validate_remittances_pdf(file_path)

    # Extract measurement date from collected_at (use start of quarter)
    collected = pd.to_datetime(collected_at)
    measurement_date = collected.to_period("Q").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    try:
        # Extract data from PDF
        extracted = extract_remittance_tables(file_path)

        # Generate metrics (UAE-level, not Dubai-specific)
        if extracted["personal_remittances"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "uae|cbuae_personal_remittances",
                "value": float(extracted["personal_remittances"]),
                "available_date": collected_at,
            })

        if extracted["workers_remittances"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "uae|cbuae_workers_remittances",
                "value": float(extracted["workers_remittances"]),
                "available_date": collected_at,
            })

        if extracted["total_outflows"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "uae|cbuae_total_outflows",
                "value": float(extracted["total_outflows"]),
                "available_date": collected_at,
            })

    except Exception as e:
        # PDF extraction failed - output error for Telegram manual-entry fallback
        raise ValueError(
            f"CBUAE PDF extraction failed. Please provide manually: "
            f"personal_remittances, workers_remittances, total_outflows "
            f"(values in millions AED). Error: {e}"
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
        normalized = normalize_remittances(file_path, collected_at)

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
