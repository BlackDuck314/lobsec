"""
Ejari Rentals Normalization Module

Reads DLD transaction CSV (same as DLD collector), filters to rentals.
Aggregates by (area, property_type) per month with rental-specific metrics.
Derives: rental_volume, avg_rent, avg_rent_per_sqft, rent_yoy_change.

Bridge pattern:
- Read: {filePath, source, collectedAt} from stdin
- Process: Load CSV, validate schema, filter rentals, aggregate
- Write: [{source, measurement_date, metric_name, value, available_date}] to stdout
- Errors: print to stderr, sys.exit(1)

NORM-02: available_date = collectedAt (when data became available to us)
NORM-04: Hard error on schema validation failure
"""

import sys
import json
import pandas as pd
from .schemas.ejari_schema import ejari_schema


def normalize_ejari(file_path: str, source: str, collected_at: str) -> list[dict]:
    """
    Normalize Ejari rental data to monthly aggregated metrics.

    Args:
        file_path: Path to raw DLD CSV file (same as DLD)
        source: Source identifier ("ejari-rentals")
        collected_at: ISO timestamp when data was collected

    Returns:
        List of metric records: [{source, measurement_date, metric_name, value, available_date}]
    """
    # Load CSV
    df = pd.read_csv(file_path)

    # Validate schema with pandera (NORM-04: hard error on failure)
    df = ejari_schema.validate(df)

    # Filter to rental transactions only
    rentals = df[df["trans_group_en"] == "Rent"].copy()

    if rentals.empty:
        return []

    # Parse dates
    rentals["trans_date"] = pd.to_datetime(rentals["trans_date"])

    # Set date as index for resampling
    rentals = rentals.set_index("trans_date")

    # Group by area and property type, then resample to monthly
    metrics = []

    # Get unique area/property combinations
    area_prop_groups = (
        rentals.groupby(["area_name_en", "prop_type_en"])
        .size()
        .reset_index(name="count")
    )

    for _, row in area_prop_groups.iterrows():
        area = row["area_name_en"]
        prop_type = row["prop_type_en"]

        # Skip if area or property type is null
        if pd.isna(area) or pd.isna(prop_type):
            continue

        # Filter to this area/property combination
        subset = rentals[
            (rentals["area_name_en"] == area) & (rentals["prop_type_en"] == prop_type)
        ]

        # Resample to month-end
        monthly = subset.resample("ME")

        # Compute metrics per month
        for month_end, month_data in monthly:
            if month_data.empty:
                continue

            measurement_date = month_end.strftime("%Y-%m-%d")
            metric_prefix = f"{area}|{prop_type}"

            # Rental volume
            volume = len(month_data)
            metrics.append(
                {
                    "source": source,
                    "measurement_date": measurement_date,
                    "metric_name": f"{metric_prefix}|rental_volume",
                    "value": float(volume),
                    "available_date": collected_at,
                }
            )

            # Rent metrics (skip if actual_worth is all null)
            rents = month_data["actual_worth"].dropna()
            if not rents.empty:
                # Average rent
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"{metric_prefix}|avg_rent",
                        "value": float(rents.mean()),
                        "available_date": collected_at,
                    }
                )

            # Rent per sqft metrics (skip if meter_sale_price is all null)
            rent_per_sqft = month_data["meter_sale_price"].dropna()
            if not rent_per_sqft.empty:
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"{metric_prefix}|avg_rent_per_sqft",
                        "value": float(rent_per_sqft.mean()),
                        "available_date": collected_at,
                    }
                )

    # Compute YoY changes and renewal rate estimation
    metrics_df = pd.DataFrame(metrics)

    if not metrics_df.empty:
        metrics_df["measurement_date"] = pd.to_datetime(
            metrics_df["measurement_date"]
        )

        yoy_metrics = []

        # YoY change for avg_rent metric
        for metric_name in metrics_df["metric_name"].unique():
            # Only compute YoY for avg_rent (not volume or rent_per_sqft to avoid duplication)
            if not metric_name.endswith("|avg_rent"):
                continue

            metric_subset = metrics_df[metrics_df["metric_name"] == metric_name].copy()
            metric_subset = metric_subset.sort_values("measurement_date")

            # YoY change: requires 12+ months of data
            if len(metric_subset) >= 12:
                for i in range(12, len(metric_subset)):
                    current = metric_subset.iloc[i]
                    year_ago = metric_subset.iloc[i - 12]

                    if year_ago["value"] != 0:
                        yoy_change = (
                            (current["value"] - year_ago["value"])
                            / year_ago["value"]
                        ) * 100

                        # Create rent_yoy_change metric
                        yoy_metric_name = (
                            "|".join(metric_name.split("|")[:-1])
                            + "|rent_yoy_change"
                        )

                        yoy_metrics.append(
                            {
                                "source": source,
                                "measurement_date": current["measurement_date"].strftime(
                                    "%Y-%m-%d"
                                ),
                                "metric_name": yoy_metric_name,
                                "value": float(yoy_change),
                                "available_date": collected_at,
                            }
                        )

        # Renewal rate estimation: Compare volume to prior month
        # Approximation: if volume increases MoM, it suggests renewals
        # More sophisticated: would require new vs renewal transaction type if available
        for metric_name in metrics_df["metric_name"].unique():
            if not metric_name.endswith("|rental_volume"):
                continue

            metric_subset = metrics_df[metrics_df["metric_name"] == metric_name].copy()
            metric_subset = metric_subset.sort_values("measurement_date")

            # Renewal rate: requires 2+ months of data
            if len(metric_subset) >= 2:
                for i in range(1, len(metric_subset)):
                    current = metric_subset.iloc[i]
                    month_ago = metric_subset.iloc[i - 1]

                    # Simple renewal rate approximation:
                    # renewal_rate = min(current_volume, month_ago_volume) / month_ago_volume * 100
                    # (assumes at least some overlap indicates renewals)
                    if month_ago["value"] > 0:
                        overlap = min(current["value"], month_ago["value"])
                        renewal_rate = (overlap / month_ago["value"]) * 100

                        renewal_metric_name = (
                            "|".join(metric_name.split("|")[:-1])
                            + "|renewal_rate"
                        )

                        yoy_metrics.append(
                            {
                                "source": source,
                                "measurement_date": current["measurement_date"].strftime(
                                    "%Y-%m-%d"
                                ),
                                "metric_name": renewal_metric_name,
                                "value": float(renewal_rate),
                                "available_date": collected_at,
                            }
                        )

        metrics.extend(yoy_metrics)

    return metrics


def main():
    """Entry point: read stdin, normalize, write stdout."""
    try:
        # Read input: {filePath, source, collectedAt}
        input_data = json.load(sys.stdin)

        file_path = input_data["filePath"]
        source = input_data["source"]
        collected_at = input_data["collectedAt"]

        # Normalize
        result = normalize_ejari(file_path, source, collected_at)

        # Write output
        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        # Log errors to stderr
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
