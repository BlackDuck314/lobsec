#!/usr/bin/env python3
"""
KHDA school enrollment normalization module.

Reads KHDA annual census PDF reports and produces normalized annual metrics:

Dubai-level metrics:
- dubai|khda_total_enrollment
- dubai|khda_enrollment_british
- dubai|khda_enrollment_american
- dubai|khda_enrollment_indian
- dubai|khda_enrollment_ib
- dubai|khda_enrollment_ministry
- dubai|khda_withdrawal_rate

All metrics include available_date (NORM-02 compliance).

Uses pdfplumber for table extraction from annual census PDF reports.
Test against 2024-25 published reports.
"""

import json
import sys
from typing import Any

import pandas as pd
import pdfplumber

from .schemas.khda_schema import validate_khda_pdf


def extract_enrollment_tables(pdf_path: str) -> dict[str, Any]:
    """
    Extract school enrollment statistics from KHDA census PDF.

    Expected structure:
    - First 10 pages: Enrollment summary tables
    - Headers: "Enrollment", "Students", "Curriculum", "Schools"
    - Curriculum types: British, American, Indian, IB, Ministry

    Returns dict with extracted values.
    """
    data = {
        "total_enrollment": None,
        "british": None,
        "american": None,
        "indian": None,
        "ib": None,
        "ministry": None,
        "withdrawal_rate": None,
    }

    with pdfplumber.open(pdf_path) as pdf:
        # Target first 10 pages (enrollment summary section)
        for page_num in range(min(10, len(pdf.pages))):
            page = pdf.pages[page_num]
            tables = page.extract_tables()

            for table in tables:
                if not table or len(table) < 2:
                    continue

                # Identify table by header keywords
                header = " ".join(str(cell) for cell in table[0] if cell).lower()

                if "enrollment" in header or "student" in header or "curriculum" in header:
                    # Process enrollment table
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

                        if "total" in label and ("enrollment" in label or "student" in label):
                            data["total_enrollment"] = value
                        elif "british" in label or "uk" in label:
                            data["british"] = value
                        elif "american" in label or "us" in label:
                            data["american"] = value
                        elif "indian" in label or "cbse" in label:
                            data["indian"] = value
                        elif "ib" in label or "international baccalaureate" in label:
                            data["ib"] = value
                        elif "ministry" in label or "moe" in label:
                            data["ministry"] = value
                        elif "withdrawal" in label or "dropout" in label:
                            # Withdrawal rate is usually a percentage
                            if value < 100:  # Likely a percentage
                                data["withdrawal_rate"] = value

    # Sanity check: Dubai has 300K+ private school students
    if data["total_enrollment"] and data["total_enrollment"] < 100_000:
        raise ValueError(
            f"Total enrollment {data['total_enrollment']} is suspiciously low "
            f"(expected >100K for Dubai private schools)"
        )

    return data


def normalize_khda(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize KHDA enrollment PDF data to annual metrics.

    Extracts enrollment counts via pdfplumber table extraction.
    Uses September as measurement date (start of academic year).
    """
    # Validate PDF exists
    validate_khda_pdf(file_path)

    # Extract measurement date from collected_at (use September of that year)
    collected = pd.to_datetime(collected_at)
    # Academic year starts in September
    measurement_date = pd.Timestamp(year=collected.year, month=9, day=1).strftime("%Y-%m-%d")

    metrics = []

    try:
        # Extract data from PDF
        extracted = extract_enrollment_tables(file_path)

        # Generate metrics
        if extracted["total_enrollment"]:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|khda_total_enrollment",
                "value": int(extracted["total_enrollment"]),
                "available_date": collected_at,
            })

        curricula = ["british", "american", "indian", "ib", "ministry"]
        for curriculum in curricula:
            if extracted[curriculum]:
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"dubai|khda_enrollment_{curriculum}",
                    "value": int(extracted[curriculum]),
                    "available_date": collected_at,
                })

        if extracted["withdrawal_rate"] is not None:
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": "dubai|khda_withdrawal_rate",
                "value": float(extracted["withdrawal_rate"]),
                "available_date": collected_at,
            })

    except Exception as e:
        # PDF extraction failed - output error for Telegram manual-entry fallback
        raise ValueError(
            f"KHDA PDF extraction failed. Please provide manually: "
            f"total_enrollment, british, american, indian, ib, ministry, "
            f"withdrawal_rate. Error: {e}"
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
        normalized = normalize_khda(file_path, collected_at)

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
