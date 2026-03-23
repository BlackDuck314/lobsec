"""
World Bank Indicators Normalizer (MACRO-01)

Reads raw JSON from the World Bank collector and produces normalized
monthly records for ingestion into the normalized_monthly table.

Metrics produced:
- uae|wb_gdp_growth_pct
- uae|wb_cpi_inflation_pct
- uae|wb_fdi_inflows_usd
- uae|wb_trade_pct_gdp
- uae|wb_population

All World Bank dates are year strings ("2024") mapped to measurement_date "YYYY-01-01".
available_date comes from the collectedAt field in the raw JSON.

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str, "source": str} from stdin
  Write: [{measurement_date, metric_name, value, available_date, source}, ...] to stdout
"""

import json
import sys
from typing import Any

from .schemas.worldbank_schema import validate_worldbank_json


# Map collector labels to normalized metric names
LABEL_TO_METRIC = {
    "gdp_growth_pct": "uae|wb_gdp_growth_pct",
    "cpi_inflation_pct": "uae|wb_cpi_inflation_pct",
    "fdi_inflows_usd": "uae|wb_fdi_inflows_usd",
    "trade_pct_gdp": "uae|wb_trade_pct_gdp",
    "population": "uae|wb_population",
}


def normalize_worldbank(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize World Bank JSON data to monthly metrics.

    Args:
        file_path: Path to raw JSON file from collector.
        collected_at: ISO timestamp when data was collected.

    Returns:
        List of NormalizedRecord dicts.
    """
    validate_worldbank_json(file_path)

    with open(file_path) as f:
        data = json.load(f)

    # Use collectedAt from raw data if available, else use provided value
    available_date = data.get("collectedAt", collected_at)
    # Truncate to date portion for available_date
    if "T" in available_date:
        available_date = available_date[:10]

    indicators = data.get("indicators", {})
    metrics = []

    for label, records in indicators.items():
        metric_name = LABEL_TO_METRIC.get(label)
        if not metric_name:
            print(f"WARNING: Unknown indicator label '{label}', skipping", file=sys.stderr)
            continue

        for record in records:
            value = record.get("value")
            if value is None:
                continue

            year = record.get("date", "")
            if not year:
                continue

            metrics.append({
                "measurement_date": f"{year}-01-01",
                "metric_name": metric_name,
                "value": float(value),
                "available_date": available_date,
            })

    print(f"Normalized {len(metrics)} World Bank records", file=sys.stderr)
    return metrics


def main() -> None:
    """Entry point for Python normalization bridge."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        normalized = normalize_worldbank(file_path, collected_at)

        # Add source field to each record
        for record in normalized:
            record["source"] = input_data["source"]

        json.dump(normalized, sys.stdout)

    except Exception as e:
        error_msg = {"error": str(e), "type": type(e).__name__}
        json.dump(error_msg, sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
