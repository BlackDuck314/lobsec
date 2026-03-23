"""
CBUAE Expanded Monetary Data Normalizer (CBUAE-01)

Reads raw JSON from the CBUAE QER PDF collector and produces normalized
quarterly records for money supply, interest rates, and banking metrics.

Metrics produced (8 per quarter):
- uae|cbuae_m1_aed_bn — Narrow money supply (AED billions)
- uae|cbuae_m2_aed_bn — Money supply M2 (AED billions)
- uae|cbuae_m3_aed_bn — Broad money supply (AED billions)
- uae|cbuae_base_rate_pct — CBUAE base interest rate (%)
- uae|cbuae_eibor_3m_pct — 3-month EIBOR rate (%)
- uae|cbuae_total_assets_aed_bn — Banking sector total assets (AED billions)
- uae|cbuae_gross_credit_aed_bn — Gross domestic credit (AED billions)
- uae|cbuae_bank_deposits_aed_bn — Bank deposits (AED billions)

Quarter label mapping: Q1=01-01, Q2=04-01, Q3=07-01, Q4=10-01

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str, "source": str} from stdin
  Write: [{measurement_date, metric_name, value, available_date, source}, ...] to stdout
"""

import json
import re
import sys
from typing import Any

from .schemas.cbuae_expanded_schema import validate_cbuae_expanded_json


# Quarter start dates
QUARTER_TO_DATE = {
    "Q1": "01-01",
    "Q2": "04-01",
    "Q3": "07-01",
    "Q4": "10-01",
}

# Raw JSON key -> normalized metric name
METRIC_MAP = {
    "m1_aed_bn": "uae|cbuae_m1_aed_bn",
    "m2_aed_bn": "uae|cbuae_m2_aed_bn",
    "m3_aed_bn": "uae|cbuae_m3_aed_bn",
    "base_rate_pct": "uae|cbuae_base_rate_pct",
    "eibor_3m_pct": "uae|cbuae_eibor_3m_pct",
    "total_assets_aed_bn": "uae|cbuae_total_assets_aed_bn",
    "gross_credit_aed_bn": "uae|cbuae_gross_credit_aed_bn",
    "bank_deposits_aed_bn": "uae|cbuae_bank_deposits_aed_bn",
}

# Validation ranges: (min, max) for each metric
VALIDATION_RANGES = {
    "m1_aed_bn": (200.0, 3000.0),
    "m2_aed_bn": (500.0, 5000.0),
    "m3_aed_bn": (600.0, 6000.0),
    "base_rate_pct": (0.0, 10.0),
    "eibor_3m_pct": (0.0, 10.0),
    "total_assets_aed_bn": (1000.0, 10000.0),
    "gross_credit_aed_bn": (500.0, 5000.0),
    "bank_deposits_aed_bn": (500.0, 8000.0),
}


def quarter_label_to_date(label: str) -> str | None:
    """Convert a quarter label like '2025-Q4' to a measurement date like '2025-10-01'.

    Args:
        label: Quarter label in format "YYYY-QN".

    Returns:
        Date string "YYYY-MM-DD" or None if unparseable.
    """
    m = re.match(r"(\d{4})-Q([1-4])", label)
    if not m:
        return None
    year = m.group(1)
    quarter = f"Q{m.group(2)}"
    date_suffix = QUARTER_TO_DATE.get(quarter)
    if not date_suffix:
        return None
    return f"{year}-{date_suffix}"


def normalize_cbuae_expanded(
    file_path: str, collected_at: str
) -> list[dict[str, Any]]:
    """Normalize CBUAE expanded JSON data to quarterly metrics.

    For each quarter, produces up to 8 metrics (skips None values).

    Args:
        file_path: Path to raw JSON file from collector.
        collected_at: ISO timestamp when data was collected.

    Returns:
        List of NormalizedRecord dicts.
    """
    validate_cbuae_expanded_json(file_path)

    with open(file_path) as f:
        data = json.load(f)

    # Use collectedAt from raw data if available, else use provided value
    available_date = data.get("collectedAt", collected_at)
    if "T" in available_date:
        available_date = available_date[:10]

    quarters = data.get("quarters", {})
    metrics: list[dict[str, Any]] = []
    skipped = 0
    warnings = 0

    for q_label, q_data in sorted(quarters.items()):
        measurement_date = quarter_label_to_date(q_label)
        if not measurement_date:
            print(
                f"WARNING: Cannot parse quarter label '{q_label}', skipping",
                file=sys.stderr,
            )
            skipped += 1
            continue

        for raw_key, metric_name in METRIC_MAP.items():
            value = q_data.get(raw_key)
            if value is None:
                continue

            # Validate range
            val_range = VALIDATION_RANGES.get(raw_key)
            if val_range:
                vmin, vmax = val_range
                if not (vmin <= value <= vmax):
                    print(
                        f"WARNING: {metric_name} = {value} for {q_label} "
                        f"outside expected range [{vmin}, {vmax}]",
                        file=sys.stderr,
                    )
                    warnings += 1

            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": metric_name,
                "value": float(value),
                "available_date": available_date,
            })

    print(
        f"Normalized {len(metrics)} CBUAE expanded records "
        f"from {len(quarters)} quarters "
        f"({skipped} skipped, {warnings} range warnings)",
        file=sys.stderr,
    )
    return metrics


def main() -> None:
    """Entry point for Python normalization bridge."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        normalized = normalize_cbuae_expanded(file_path, collected_at)

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
