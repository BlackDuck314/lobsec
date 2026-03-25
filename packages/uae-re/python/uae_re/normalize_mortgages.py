#!/usr/bin/env python3
"""
CBUAE Banking Indicators normalization module.

Reads CBUAE Banking Indicators PDF (single-page wide table with monthly data
broken down by Abu Dhabi, Dubai, and Other Emirates) and produces normalized
monthly metrics.

The actual PDF format is a single large table with rows like:
  Row 6:  1.Gross Bank Assets
  Row 7:  2.Gross Credit
  Row 11: Private Sector (credit)
  Row 13: Individual (personal/mortgage lending)
  Row 22: 4.Bank Deposits
  Row 29: Capital & Reserves

Columns: per-emirate (AD, DXB, OE) x 12 months + pct-change columns + All Banks.

Extracted metrics (UAE totals = AD + DXB + OE, in billions AED):
- uae|cbuae_gross_credit_aed_bn
- uae|cbuae_private_sector_credit_aed_bn
- uae|cbuae_individual_lending_aed_bn  (closest proxy for mortgage/personal lending)
- uae|cbuae_bank_deposits_aed_bn
- uae|cbuae_capital_reserves_aed_bn

All metrics include available_date (NORM-02 compliance).
"""

import json
import re
import sys
from typing import Any

import pandas as pd
import pdfplumber

from .schemas.mortgages_schema import validate_mortgages_pdf


# Row labels we want to extract (case-insensitive substring match)
# Maps (search_label, metric_suffix, max_row) -- max_row prevents matching
# a label that appears in multiple sections (e.g. "Private Sector" under
# both Gross Credit and Bank Deposits).
TARGET_ROWS = [
    ("2.gross credit", "gross_credit_aed_bn", 20),
    ("private sector", "private_sector_credit_aed_bn", 16),  # under Gross Credit only
    ("individual", "individual_lending_aed_bn", 16),          # under Gross Credit only
    ("4.bank deposits", "bank_deposits_aed_bn", 30),
    ("capital & reserves", "capital_reserves_aed_bn", 40),
]


def _find_latest_month_columns(table: list[list]) -> tuple[list[int], str]:
    """
    Find the column indices for the latest month's AD, DXB, OE data.

    Scans header row (row 3) for month labels like 'Dec-25 **', 'Nov-25', etc.
    The latest non-percentage month column set is returned.

    Returns:
        (column_indices, month_label) where column_indices has 3 elements [AD, DXB, OE]
    """
    header_row = table[3] if len(table) > 3 else []

    # Find all month columns (they have patterns like 'Jan-25', 'Dec-24', etc.)
    month_cols = []
    for k, v in enumerate(header_row):
        if v and re.match(r'[A-Z][a-z]{2}-\d{2}', str(v).strip().replace(' **', '')):
            month_cols.append((k, str(v).strip().replace(' **', '')))

    if not month_cols:
        return ([], "")

    # The last month column is the most recent data
    last_col, last_label = month_cols[-1]
    # Each month has 3 sub-columns: AD (col), DXB (col+1), OE (col+2)
    return ([last_col, last_col + 1, last_col + 2], last_label)


def _parse_cell(cell) -> float | None:
    """Parse a numeric cell value, handling commas and whitespace."""
    if cell is None:
        return None
    s = str(cell).replace(',', '').replace(' ', '').replace('%', '').strip()
    if not s or s == '-' or s == 'None':
        return None
    try:
        return float(s)
    except ValueError:
        return None


def extract_banking_indicators(pdf_path: str) -> list[dict[str, Any]]:
    """
    Extract banking indicators from CBUAE Banking Indicators PDF.

    The PDF contains a single wide table with monthly data per emirate.
    We extract the latest month's data by summing AD + DXB + OE for target rows.

    Returns list of dicts with keys: metric_suffix, value, month_label
    """
    results = []

    with pdfplumber.open(pdf_path) as pdf:
        page = pdf.pages[0]
        tables = page.extract_tables()

        if not tables:
            return results

        table = tables[0]
        cols, month_label = _find_latest_month_columns(table)

        if not cols:
            return results

        # Scan rows for target labels
        matched = set()
        for row_idx in range(6, len(table)):
            row = table[row_idx]
            label = str(row[0]).lower().strip() if row[0] else ""

            for search_label, metric_suffix, max_row in TARGET_ROWS:
                if metric_suffix in matched:
                    continue  # Already found this metric
                if row_idx > max_row:
                    continue  # Past the section where this label is relevant
                if search_label in label:
                    # Sum AD + DXB + OE
                    vals = [_parse_cell(row[c]) for c in cols if c < len(row)]
                    valid_vals = [v for v in vals if v is not None]

                    if len(valid_vals) == 3:
                        total = sum(valid_vals)
                        results.append({
                            "metric_suffix": metric_suffix,
                            "value": round(total, 2),
                            "month_label": month_label,
                        })
                        matched.add(metric_suffix)
                    break  # Only match first occurrence per target

    return results


def normalize_mortgages(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize CBUAE Banking Indicators PDF to monthly metrics.

    Extracts key banking indicators (credit, deposits, capital) from
    the wide-format Banking Indicators table via pdfplumber.

    Args:
        file_path: Path to downloaded PDF
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records
    """
    validate_mortgages_pdf(file_path)

    collected = pd.to_datetime(collected_at)

    metrics = []

    try:
        extracted = extract_banking_indicators(file_path)

        for item in extracted:
            # Derive measurement_date from month_label (e.g. 'Dec-25' -> '2025-12-01')
            try:
                month_dt = pd.to_datetime(item["month_label"], format="%b-%y")
                measurement_date = month_dt.strftime("%Y-%m-%d")
            except Exception:
                # Fallback to start of quarter from collected_at
                measurement_date = collected.to_period("Q").to_timestamp().strftime("%Y-%m-%d")

            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"uae|cbuae_{item['metric_suffix']}",
                "value": item["value"],
                "available_date": collected_at,
            })

    except Exception as e:
        raise ValueError(
            f"CBUAE Banking Indicators PDF extraction failed: {e}"
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
