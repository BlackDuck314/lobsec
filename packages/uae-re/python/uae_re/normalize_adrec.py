#!/usr/bin/env python3
"""
ADREC Abu Dhabi normalization module.

Reads transaction, lease, and index data from ADREC CSV exports and produces
normalized monthly metrics:

Transaction metrics:
- {district}|{property_type}|{sale_type}|volume
- {district}|{property_type}|{sale_type}|median_price
- {district}|{property_type}|{sale_type}|rate_per_sqm
- {district}|{property_type}|{sale_type}|total_value
- {district}|{property_type}|offplan_pct (off-plan percentage)
- {district}|{property_type}|ready_pct (ready percentage)
- {district}|{property_type}|primary_pct (primary sale percentage)
- {district}|{property_type}|secondary_pct (secondary sale percentage)

Lease metrics:
- {district}|{property_type}|lease_volume
- {district}|{property_type}|average_rent

Index metrics:
- {district}|{property_type}|price_index

All metrics include available_date (NORM-02 compliance).
"""

import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import pandera as pa

from .schemas.adrec_schema import (
    ADRECTransactionSchema,
    ADRECLeaseSchema,
    ADRECIndexSchema,
)


def normalize_transactions(
    df: pd.DataFrame, collected_at: str
) -> list[dict[str, Any]]:
    """
    Normalize ADREC transaction data to monthly metrics.

    Aggregates by (district, property_type, sale_type) per month.
    """
    # Validate schema
    df = ADRECTransactionSchema.validate(df, lazy=True)

    # Parse registration date
    df["registration_date"] = pd.to_datetime(
        df["registration_date"], errors="coerce"
    )

    # Drop rows with missing critical fields
    df = df.dropna(subset=["registration_date", "price", "district"])

    if df.empty:
        print(
            "WARNING: No valid transactions after filtering",
            file=sys.stderr
        )
        return []

    # Extract month
    df["month"] = df["registration_date"].dt.to_period("M").dt.to_timestamp()

    metrics = []

    # Group by (month, district, property_type, sale_type)
    grouped = df.groupby(
        ["month", "district", "property_type", "sale_type"], dropna=False
    )

    for (month, district, prop_type, sale_type), group in grouped:
        # Skip if any key field is missing
        if pd.isna(district) or pd.isna(prop_type) or pd.isna(sale_type):
            continue

        measurement_date = pd.Timestamp(month).strftime("%Y-%m-%d")
        base_name = f"{district}|{prop_type}|{sale_type}"

        # Volume
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{base_name}|volume",
            "value": len(group),
            "available_date": collected_at,
        })

        # Median price
        median_price = group["price"].median()
        if not pd.isna(median_price):
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{base_name}|median_price",
                "value": float(median_price),
                "available_date": collected_at,
            })

        # Rate per sqm (median)
        if "rate" in group.columns:
            rate_per_sqm = group["rate"].median()
            if not pd.isna(rate_per_sqm):
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"{base_name}|rate_per_sqm",
                    "value": float(rate_per_sqm),
                    "available_date": collected_at,
                })

        # Total value
        total_value = group["price"].sum()
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{base_name}|total_value",
            "value": float(total_value),
            "available_date": collected_at,
        })

    # Compute off-plan vs ready split (by district + property_type)
    sale_type_grouped = df.groupby(
        ["month", "district", "property_type"], dropna=False
    )

    for (month, district, prop_type), group in sale_type_grouped:
        if pd.isna(district) or pd.isna(prop_type):
            continue

        measurement_date = pd.Timestamp(month).strftime("%Y-%m-%d")
        base_name = f"{district}|{prop_type}"

        total = len(group)
        if total == 0:
            continue

        # Off-plan percentage
        offplan_count = len(group[group["sale_type"].str.contains("off-plan", case=False, na=False)])
        offplan_pct = (offplan_count / total) * 100

        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{base_name}|offplan_pct",
            "value": float(offplan_pct),
            "available_date": collected_at,
        })

        # Ready percentage
        ready_count = len(group[group["sale_type"].str.contains("ready", case=False, na=False)])
        ready_pct = (ready_count / total) * 100

        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{base_name}|ready_pct",
            "value": float(ready_pct),
            "available_date": collected_at,
        })

    # Compute primary vs secondary split
    sequence_grouped = df.groupby(
        ["month", "district", "property_type"], dropna=False
    )

    for (month, district, prop_type), group in sequence_grouped:
        if pd.isna(district) or pd.isna(prop_type):
            continue

        measurement_date = pd.Timestamp(month).strftime("%Y-%m-%d")
        base_name = f"{district}|{prop_type}"

        total = len(group)
        if total == 0:
            continue

        # Primary percentage
        primary_count = len(group[group["sequence"].str.contains("primary", case=False, na=False)])
        primary_pct = (primary_count / total) * 100

        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{base_name}|primary_pct",
            "value": float(primary_pct),
            "available_date": collected_at,
        })

        # Secondary percentage
        secondary_count = len(group[group["sequence"].str.contains("secondary", case=False, na=False)])
        secondary_pct = (secondary_count / total) * 100

        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{base_name}|secondary_pct",
            "value": float(secondary_pct),
            "available_date": collected_at,
        })

    return metrics


def normalize_leases(df: pd.DataFrame, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize ADREC lease data to monthly metrics.
    """
    # Validate schema
    df = ADRECLeaseSchema.validate(df, lazy=True)

    # Parse contract date
    df["contract_date"] = pd.to_datetime(df["contract_date"], errors="coerce")

    # Drop rows with missing critical fields
    df = df.dropna(subset=["contract_date", "rent", "district"])

    if df.empty:
        print(
            "WARNING: No valid leases after filtering",
            file=sys.stderr
        )
        return []

    # Extract month
    df["month"] = df["contract_date"].dt.to_period("M").dt.to_timestamp()

    metrics = []

    # Group by (month, district, property_type)
    grouped = df.groupby(["month", "district", "property_type"], dropna=False)

    for (month, district, prop_type), group in grouped:
        if pd.isna(district) or pd.isna(prop_type):
            continue

        measurement_date = pd.Timestamp(month).strftime("%Y-%m-%d")
        base_name = f"{district}|{prop_type}"

        # Lease volume
        metrics.append({
            "measurement_date": measurement_date,
            "metric_name": f"{base_name}|lease_volume",
            "value": len(group),
            "available_date": collected_at,
        })

        # Average rent
        avg_rent = group["rent"].mean()
        if not pd.isna(avg_rent):
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{base_name}|average_rent",
                "value": float(avg_rent),
                "available_date": collected_at,
            })

    return metrics


def normalize_indices(df: pd.DataFrame, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize ADREC price index data.
    """
    # Validate schema
    df = ADRECIndexSchema.validate(df, lazy=True)

    # Parse period
    df["period"] = pd.to_datetime(df["period"], errors="coerce")

    # Drop rows with missing critical fields
    df = df.dropna(subset=["period", "index_value", "district"])

    if df.empty:
        print(
            "WARNING: No valid indices after filtering",
            file=sys.stderr
        )
        return []

    # Extract month
    df["month"] = df["period"].dt.to_period("M").dt.to_timestamp()

    metrics = []

    # Group by (month, district, property_type)
    grouped = df.groupby(["month", "district", "property_type"], dropna=False)

    for (month, district, prop_type), group in grouped:
        if pd.isna(district) or pd.isna(prop_type):
            continue

        measurement_date = pd.Timestamp(month).strftime("%Y-%m-%d")
        base_name = f"{district}|{prop_type}"

        # Price index (use last/most recent value in month)
        index_value = group["index_value"].iloc[-1]
        if not pd.isna(index_value):
            metrics.append({
                "measurement_date": measurement_date,
                "metric_name": f"{base_name}|price_index",
                "value": float(index_value),
                "available_date": collected_at,
            })

    return metrics


def main() -> None:
    """
    Main entry point.

    Reads {filePath, source, collectedAt} from stdin.
    Outputs normalized metrics as JSON to stdout.
    """
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        all_metrics = []

        # Check for transactions file
        transactions_path = Path(file_path)
        if transactions_path.exists() and "transactions" in file_path:
            df = pd.read_csv(file_path)
            all_metrics.extend(normalize_transactions(df, collected_at))

        # Check for leases file (same directory, different suffix)
        leases_path = Path(file_path.replace("transactions", "leases"))
        if leases_path.exists():
            df = pd.read_csv(leases_path)
            all_metrics.extend(normalize_leases(df, collected_at))

        # Check for indices file
        indices_path = Path(file_path.replace("transactions", "indices"))
        if indices_path.exists():
            df = pd.read_csv(indices_path)
            all_metrics.extend(normalize_indices(df, collected_at))

        # Output metrics
        print(json.dumps(all_metrics, indent=2))

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
