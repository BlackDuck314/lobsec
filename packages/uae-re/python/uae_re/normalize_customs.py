#!/usr/bin/env python3
"""
Dubai customs household imports normalization module (COLL-22).

Reads scraped Dubai Customs / CBUAE trade statistics data (JSON) and produces
normalized quarterly metrics tracking household goods import volumes as a
proxy for residential occupancy and household formation:

Dubai-level metrics:
- dubai|customs_furniture_imports_aed     — HS chapter 94 (furniture, lighting, prefab)
- dubai|customs_household_goods_aed       — HS chapters 73+85 (steel articles + electrical)
- dubai|customs_total_imports_aed         — total imports for context
- dubai|customs_household_share_pct       — (furniture + household) / total * 100

All metrics include available_date (NORM-02 compliance).
Returns empty list if no trade data available (graceful for unavailable quarters).

Note: If PDF was downloaded, the TS collector passes the PDF path for pdfplumber
extraction. The normalizer handles both JSON summary and PDF extraction modes.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from .schemas.customs_schema import validate_customs_json


def _extract_pdf_metrics(pdf_path: str) -> dict[str, float | None]:
    """
    Extract HS-code metrics from downloaded PDF using pdfplumber.

    Searches for HS chapter keywords: Chapter 94 (furniture), Chapter 73 (steel),
    Chapter 85 (electrical equipment). Extracts adjacent numeric values.

    Returns dict with furniture_imports_aed, household_goods_aed, total_imports_aed.
    """
    try:
        import pdfplumber  # type: ignore
    except ImportError:
        return {}

    result: dict[str, float | None] = {
        "furniture_imports_aed": None,
        "household_goods_imports_aed": None,
        "total_imports_aed": None,
    }

    def _parse_value(text: str) -> float | None:
        """Extract numeric value from text (handles commas and AED suffixes)."""
        matches = re.findall(r"[\d,]+(?:\.\d+)?", text.replace(",", ""))
        if matches:
            try:
                return float(matches[0])
            except (ValueError, IndexError):
                return None
        return None

    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                tables = page.extract_tables()
                for table in tables:
                    for row in table:
                        if not row:
                            continue
                        row_text = " ".join(str(cell) for cell in row if cell)
                        row_lower = row_text.lower()

                        # HS Chapter 94: furniture
                        if "chapter 94" in row_lower or "94xx" in row_lower or (
                            "furniture" in row_lower and "import" in row_lower
                        ):
                            val = _parse_value(row_text)
                            if val and val > 0:
                                result["furniture_imports_aed"] = val

                        # HS Chapters 73 + 85: household goods
                        if ("chapter 73" in row_lower or "chapter 85" in row_lower or
                                "iron" in row_lower or "electrical equipment" in row_lower):
                            val = _parse_value(row_text)
                            if val and val > 0:
                                # Accumulate if multiple chapters
                                existing = result.get("household_goods_imports_aed") or 0.0
                                result["household_goods_imports_aed"] = existing + val

                        # Total imports row
                        if ("total" in row_lower and "import" in row_lower and
                                len(row) > 1):
                            val = _parse_value(row_text)
                            if val and val > result.get("total_imports_aed") or 0:
                                result["total_imports_aed"] = val
    except Exception:
        pass

    return result


def normalize_customs(data: dict, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize Dubai customs household imports data to quarterly metrics.

    Args:
        data: Dictionary with scrapedAt, import values (or pdf_url for PDF mode)
        collected_at: ISO timestamp of collection

    Returns:
        List of normalized metric records. Empty if no data available.
    """
    validate_customs_json(data)

    # Measurement date: start of quarter
    scraped_at = pd.to_datetime(data["scrapedAt"])
    quarter_start = scraped_at.to_period("Q").to_timestamp()
    measurement_date = quarter_start.strftime("%Y-%m-%d")

    metrics: list[dict[str, Any]] = []

    # Try to get values from JSON, fall back to PDF extraction
    furniture = data.get("furniture_imports_aed")
    household_goods = data.get("household_goods_imports_aed")
    total_imports = data.get("total_imports_aed")

    # If PDF is available and JSON extraction incomplete, try PDF
    pdf_url = data.get("pdf_url") or data.get("pdf_path")
    if pdf_url and Path(pdf_url).exists() and not all([furniture, total_imports]):
        pdf_metrics = _extract_pdf_metrics(pdf_url)
        furniture = furniture or pdf_metrics.get("furniture_imports_aed")
        household_goods = household_goods or pdf_metrics.get("household_goods_imports_aed")
        total_imports = total_imports or pdf_metrics.get("total_imports_aed")

    # No data available — return empty (graceful failure)
    if not any([furniture, household_goods, total_imports]):
        return []

    # Record available metrics
    if furniture is not None:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|customs_furniture_imports_aed",
            "value": float(furniture),
            "available_date": collected_at,
        })

    if household_goods is not None:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|customs_household_goods_aed",
            "value": float(household_goods),
            "available_date": collected_at,
        })

    if total_imports is not None:
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|customs_total_imports_aed",
            "value": float(total_imports),
            "available_date": collected_at,
        })

    # Household share percentage
    if furniture is not None and total_imports and total_imports > 0:
        combined = (furniture or 0.0) + (household_goods or 0.0)
        share_pct = (combined / total_imports) * 100.0
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": "dubai|customs_household_share_pct",
            "value": round(share_pct, 2),
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
    return normalize_customs(data, collected_at)


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
        source = input_data.get("source", "customs-imports")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        metrics = normalize_customs(data, collected_at)

        for record in metrics:
            record["source"] = source

        json.dump(metrics, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
