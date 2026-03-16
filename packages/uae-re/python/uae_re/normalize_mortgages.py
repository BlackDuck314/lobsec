#!/usr/bin/env python3
"""
CBUAE mortgage rates and outstanding normalization module.

Reads CBUAE quarterly mortgage/lending statistics PDF reports and produces
normalized quarterly metrics:

UAE-level metrics (national data — not Dubai-specific):
- uae|cbuae_eibor_3m
- uae|cbuae_mortgage_outstanding_aed
- uae|cbuae_new_mortgage_count

All metrics include available_date (NORM-02 compliance).

Uses pdfplumber for table extraction from quarterly PDF reports.
Page targeting covers all pages with header detection for mortgage/EIBOR tables.
Sanity validation: EIBOR should be between 0% and 15%.
"""

import json
import sys
from typing import Any

import pandas as pd
import pdfplumber

from .schemas.mortgages_schema import validate_mortgages_pdf, validate_eibor_rate


def extract_mortgage_tables(pdf_path: str) -> dict[str, Any]:
    """
    Extract mortgage statistics from CBUAE quarterly lending PDF.

    Expected structure:
    - Mortgage and lending statistics tables throughout PDF
    - EIBOR rate table (3-month, 6-month, overnight)
    - Mortgage outstanding balance table (AED millions)
    - New mortgage issuance count

    Header detection: look for 'eibor', 'mortgage', 'lending' keywords.
    Values in millions AED (standard CBUAE reporting unit).

    Returns dict with extracted values or None for missing fields.
    """
    data = {
        "eibor_rate": None,
        "mortgage_outstanding_aed": None,
        "new_mortgage_count": None,
    }

    with pdfplumber.open(pdf_path) as pdf:
        for page_num in range(len(pdf.pages)):
            page = pdf.pages[page_num]
            tables = page.extract_tables()

            for table in tables:
                if not table or len(table) < 2:
                    continue

                # Identify table by header keywords
                header = " ".join(str(cell) for cell in table[0] if cell).lower()

                # EIBOR rate table
                if any(keyword in header for keyword in ["eibor", "interbank offered", "interest rate"]):
                    for row in table[1:]:
                        if len(row) < 2:
                            continue
                        label = str(row[0]).lower() if row[0] else ""
                        # Target 3-month EIBOR specifically
                        if "3" in label and "month" in label or "3m" in label:
                            value = _parse_numeric(row)
                            if value is not None:
                                data["eibor_rate"] = value

                # Mortgage outstanding table
                elif any(keyword in header for keyword in ["mortgage", "lending", "housing loan", "real estate loan"]):
                    for row in table[1:]:
                        if len(row) < 2:
                            continue
                        label = str(row[0]).lower() if row[0] else ""

                        if "outstanding" in label or "balance" in label or "total mortgage" in label:
                            value = _parse_numeric(row)
                            if value is not None:
                                data["mortgage_outstanding_aed"] = value

                        elif "new" in label and ("mortgage" in label or "loan" in label or "issued" in label):
                            value = _parse_numeric(row)
                            if value is not None:
                                data["new_mortgage_count"] = value

    return data


def _parse_numeric(row: list) -> float | None:
    """
    Parse first numeric value from a table row (skip label column).

    Args:
        row: Table row as list of cell values

    Returns:
        Parsed float or None if no numeric value found
    """
    for cell in row[1:]:
        if cell:
            value_str = str(cell).replace(',', '').replace(' ', '').replace('%', '')
            try:
                return float(value_str)
            except ValueError:
                continue
    return None


def normalize_mortgages(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize CBUAE mortgage PDF data to quarterly metrics.

    Extracts EIBOR rate, mortgage outstanding, and new mortgage count
    via pdfplumber table extraction.

    Args:
        file_path: Path to downloaded PDF
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records
    """
    # Validate PDF exists and is readable
    validate_mortgages_pdf(file_path)

    # Extract measurement date from collected_at (use start of quarter)
    collected = pd.to_datetime(collected_at)
    measurement_date = collected.to_period("Q").to_timestamp().strftime("%Y-%m-%d")

    metrics = []

    try:
        extracted = extract_mortgage_tables(file_path)

        # EIBOR 3-month rate — with sanity validation
        if extracted["eibor_rate"] is not None:
            try:
                validate_eibor_rate(extracted["eibor_rate"])
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": "uae|cbuae_eibor_3m",
                    "value": float(extracted["eibor_rate"]),
                    "available_date": collected_at,
                })
            except ValueError as e:
                # Log sanity failure but continue with other metrics
                print(f"EIBOR sanity check failed: {e}", file=sys.stderr)

        # Mortgage outstanding balance (AED millions)
        if extracted["mortgage_outstanding_aed"] is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "uae|cbuae_mortgage_outstanding_aed",
                "value": float(extracted["mortgage_outstanding_aed"]),
                "available_date": collected_at,
            })

        # New mortgage count
        if extracted["new_mortgage_count"] is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "uae|cbuae_new_mortgage_count",
                "value": float(extracted["new_mortgage_count"]),
                "available_date": collected_at,
            })

    except Exception as e:
        # PDF extraction failed — output error for Telegram manual-entry fallback
        raise ValueError(
            f"CBUAE mortgages PDF extraction failed. Please provide manually: "
            f"eibor_rate (%), mortgage_outstanding_aed (millions AED), new_mortgage_count. "
            f"Error: {e}"
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
        normalized = normalize_mortgages(file_path, collected_at)

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
