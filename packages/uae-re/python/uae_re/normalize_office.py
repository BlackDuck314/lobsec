#!/usr/bin/env python3
"""
Commercial office reports normalization module (COLL-28).

Reads scraped JLL/CBRE/Savills Dubai office market data (JSON) and produces
normalized quarterly metrics:

Dubai-level aggregated metrics (mean across available firms):
- dubai|office_vacancy_rate_pct     — Grade A office vacancy rate (%)
- dubai|office_absorption_sqft      — net absorption (sq ft, negative = contraction)
- dubai|office_prime_rent_aed_sqft  — prime rent (AED/sq ft/year)
- dubai|office_total_stock_sqft     — total Grade A office stock (sq ft)

Per-source metrics (cross-validation across firms):
- dubai|office_jll_vacancy          — JLL vacancy rate
- dubai|office_cbre_vacancy         — CBRE vacancy rate
- dubai|office_savills_vacancy      — Savills vacancy rate
- dubai|office_jll_prime_rent       — JLL prime rent
- dubai|office_cbre_prime_rent      — CBRE prime rent
- dubai|office_savills_prime_rent   — Savills prime rent

All metrics include available_date (NORM-02 compliance).
Returns empty list if no reports found (graceful — all 3 firms may gate content).
PDF extraction supported via pdfplumber for gated reports.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from .schemas.office_schema import validate_office_json


def _extract_pdf_office_metrics(pdf_path: str) -> dict[str, float | None]:
    """
    Extract office market metrics from downloaded PDF using pdfplumber.

    Searches for keyword-identified tables with vacancy, absorption, rent, stock.
    Returns dict with extracted values (None if not found).
    """
    try:
        import pdfplumber  # type: ignore
    except ImportError:
        return {}

    result: dict[str, float | None] = {
        "vacancy_rate_pct": None,
        "absorption_sqft": None,
        "prime_rent_aed_sqft": None,
        "total_stock_sqft": None,
    }

    def _parse_value(text: str) -> float | None:
        """Extract first numeric value from text."""
        clean = re.sub(r"[%,]", "", text)
        match = re.search(r"-?\d+(?:\.\d+)?", clean)
        if match:
            try:
                return float(match.group())
            except ValueError:
                return None
        return None

    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                tables = page.extract_tables()
                for table in tables:
                    # Look for header row with known office keywords
                    headers = [str(cell).lower() for cell in (table[0] or []) if cell]
                    header_text = " ".join(headers)

                    if not any(kw in header_text for kw in
                               ["vacancy", "absorption", "rent", "stock"]):
                        continue

                    # Extract data from table rows
                    for row in table[1:]:
                        if not row:
                            continue
                        row_cells = [str(cell) if cell else "" for cell in row]
                        row_text = " ".join(row_cells).lower()

                        if "vacancy" in row_text and result["vacancy_rate_pct"] is None:
                            for cell in row_cells[1:]:
                                val = _parse_value(cell)
                                if val is not None and 0 <= val <= 100:
                                    result["vacancy_rate_pct"] = val
                                    break

                        if "absorption" in row_text and result["absorption_sqft"] is None:
                            for cell in row_cells[1:]:
                                val = _parse_value(cell)
                                if val is not None:
                                    result["absorption_sqft"] = val
                                    break

                        if ("rent" in row_text or "aed" in row_text) and result["prime_rent_aed_sqft"] is None:
                            for cell in row_cells[1:]:
                                val = _parse_value(cell)
                                if val is not None and val > 0:
                                    result["prime_rent_aed_sqft"] = val
                                    break

                        if ("stock" in row_text or "total" in row_text) and result["total_stock_sqft"] is None:
                            for cell in row_cells[1:]:
                                val = _parse_value(cell)
                                if val is not None and val > 0:
                                    result["total_stock_sqft"] = val
                                    break

    except Exception:
        pass

    return result


def normalize_office(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize commercial office report data to quarterly metrics.

    Args:
        data: Dictionary with scrapedAt and reports list
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records. Empty if no data available.
    """
    validate_office_json(data)

    if not data.get("reports"):
        return []

    # Measurement date: start of quarter
    scraped_at = pd.to_datetime(data["scrapedAt"])
    quarter_start = scraped_at.to_period("Q").to_timestamp()
    measurement_date = quarter_start.strftime("%Y-%m-%d")

    metrics: list[dict[str, Any]] = []
    reports = data["reports"]

    # Per-source metric accumulators for cross-validation
    vacancy_by_source: dict[str, float] = {}
    absorption_by_source: dict[str, float] = {}
    rent_by_source: dict[str, float] = {}
    stock_by_source: dict[str, float] = {}

    for report in reports:
        source = (report.get("report_source") or "").lower().strip()
        if not source:
            continue

        vacancy = report.get("vacancy_rate_pct")
        absorption = report.get("absorption_sqft")
        rent = report.get("prime_rent_aed_sqft")
        total_stock = report.get("total_stock_sqft")
        pdf_url = report.get("pdf_url") or report.get("pdf_path")

        # Try PDF extraction if JSON fields are incomplete
        if pdf_url and Path(pdf_url).exists():
            if not all([vacancy, rent]):
                pdf_metrics = _extract_pdf_office_metrics(pdf_url)
                vacancy = vacancy or pdf_metrics.get("vacancy_rate_pct")
                absorption = absorption or pdf_metrics.get("absorption_sqft")
                rent = rent or pdf_metrics.get("prime_rent_aed_sqft")
                total_stock = total_stock or pdf_metrics.get("total_stock_sqft")

        # Record per-source metrics
        if vacancy is not None:
            vacancy_by_source[source] = float(vacancy)
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"dubai|office_{source}_vacancy",
                "value": float(vacancy),
                "available_date": collected_at,
            })

        if rent is not None:
            rent_by_source[source] = float(rent)
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"dubai|office_{source}_prime_rent",
                "value": float(rent),
                "available_date": collected_at,
            })

        if absorption is not None:
            absorption_by_source[source] = float(absorption)

        if total_stock is not None:
            stock_by_source[source] = float(total_stock)

    # Aggregate metrics (mean across available firms)
    if vacancy_by_source:
        avg_vacancy = sum(vacancy_by_source.values()) / len(vacancy_by_source)
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|office_vacancy_rate_pct",
            "value": round(avg_vacancy, 2),
            "available_date": collected_at,
        })

    if absorption_by_source:
        avg_absorption = sum(absorption_by_source.values()) / len(absorption_by_source)
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|office_absorption_sqft",
            "value": round(avg_absorption, 0),
            "available_date": collected_at,
        })

    if rent_by_source:
        avg_rent = sum(rent_by_source.values()) / len(rent_by_source)
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|office_prime_rent_aed_sqft",
            "value": round(avg_rent, 2),
            "available_date": collected_at,
        })

    if stock_by_source:
        avg_stock = sum(stock_by_source.values()) / len(stock_by_source)
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|office_total_stock_sqft",
            "value": round(avg_stock, 0),
            "available_date": collected_at,
        })

    return metrics


def normalize(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """Module-level normalize entry point (matches framework convention)."""
    import os
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return normalize_office(data, collected_at)


def main() -> None:
    """
    Main entry point for Python normalization bridge.

    Reads {filePath, source, collectedAt} from stdin.
    Outputs normalized metrics as JSON to stdout.
    """
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]
        source = input_data.get("source", "commercial-office-reports")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        metrics = normalize_office(data, collected_at)

        for record in metrics:
            record["source"] = source

        json.dump(metrics, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
