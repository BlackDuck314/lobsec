"""
S&P Global PMI Normalizer (MACRO-03)

Reads raw JSON from the PMI collector and produces a single normalized
metric for ingestion into the normalized_monthly table.

Metric produced:
- uae|spglobal_pmi_headline  (index 0-100, typically 40-65)

If the collector could not extract a PMI value (pmi_value is null),
the normalizer returns an empty list (no rows to insert).

measurement_date is set to the first of the month from collectedAt.
available_date comes from the collectedAt field in the raw JSON.

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str, "source": str} from stdin
  Write: [{measurement_date, metric_name, value, available_date, source}, ...] to stdout
"""

import json
import sys
from typing import Any

from .schemas.pmi_schema import validate_pmi_json


def normalize_pmi(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize PMI JSON data to a single monthly metric.

    Args:
        file_path: Path to raw JSON file from collector.
        collected_at: ISO timestamp when data was collected.

    Returns:
        List of NormalizedRecord dicts (0 or 1 item).
    """
    validate_pmi_json(file_path)

    with open(file_path) as f:
        data = json.load(f)

    pmi_value = data.get("pmi_value")
    if pmi_value is None:
        print("PMI value is null, returning empty list", file=sys.stderr)
        return []

    # Use collectedAt from raw data if available, else use provided value
    available_date = data.get("collectedAt", collected_at)
    # Truncate to date portion
    if "T" in available_date:
        available_date = available_date[:10]

    # measurement_date = first of the month from collectedAt
    date_str = available_date[:7]  # YYYY-MM
    measurement_date = f"{date_str}-01"

    metric = {
        "measurement_date": measurement_date,
        "metric_name": "uae|spglobal_pmi_headline",
        "value": float(pmi_value),
        "available_date": available_date,
    }

    print(f"Normalized PMI: {pmi_value} for {measurement_date}", file=sys.stderr)
    return [metric]


def main() -> None:
    """Entry point for Python normalization bridge."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        normalized = normalize_pmi(file_path, collected_at)

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
