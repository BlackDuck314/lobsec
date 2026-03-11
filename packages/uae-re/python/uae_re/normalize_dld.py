"""
DLD Sales Normalization Module

Reads DLD transaction CSV, filters to sales, aggregates by (area, property_type) per month.
Computes extended metrics: volume, median price, price per sqft, percentiles, YoY, MoM.

Bridge pattern:
- Read: {filePath, source, collectedAt} from stdin
- Process: Load CSV, validate schema, filter sales, aggregate, compute deltas
- Write: [{source, measurement_date, metric_name, value, available_date}] to stdout
- Errors: print to stderr, sys.exit(1)

NORM-02: available_date = collectedAt (when data became available to us)
NORM-04: Hard error on schema validation failure
"""

import sys
import json
import pandas as pd
from .schemas.dld_schema import dld_schema


def normalize_dld(file_path: str, source: str, collected_at: str) -> list[dict]:
    """
    Normalize DLD sales data to monthly aggregated metrics.

    Args:
        file_path: Path to raw DLD CSV file
        source: Source identifier ("dld-sales")
        collected_at: ISO timestamp when data was collected

    Returns:
        List of metric records: [{source, measurement_date, metric_name, value, available_date}]
    """
    # Load CSV
    df = pd.read_csv(file_path)

    # Validate schema with pandera (NORM-04: hard error on failure)
    df = dld_schema.validate(df)

    # Filter to sales transactions only
    sales = df[df["trans_group_en"] == "Sales"].copy()

    if sales.empty:
        return []

    # Parse dates
    sales["trans_date"] = pd.to_datetime(sales["trans_date"])

    # Set date as index for resampling
    sales = sales.set_index("trans_date")

    # Group by area and property type, then resample to monthly
    metrics = []

    # Get unique area/property combinations
    area_prop_groups = (
        sales.groupby(["area_name_en", "prop_type_en"])
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
        subset = sales[
            (sales["area_name_en"] == area) & (sales["prop_type_en"] == prop_type)
        ]

        # Resample to month-end
        monthly = subset.resample("ME")

        # Compute metrics per month
        for month_end, month_data in monthly:
            if month_data.empty:
                continue

            measurement_date = month_end.strftime("%Y-%m-%d")
            metric_prefix = f"{area}|{prop_type}"

            # Volume
            volume = len(month_data)
            metrics.append(
                {
                    "source": source,
                    "measurement_date": measurement_date,
                    "metric_name": f"{metric_prefix}|volume",
                    "value": float(volume),
                    "available_date": collected_at,
                }
            )

            # Price metrics (skip if actual_worth is all null)
            prices = month_data["actual_worth"].dropna()
            if not prices.empty:
                # Median price
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"{metric_prefix}|median_price",
                        "value": float(prices.median()),
                        "available_date": collected_at,
                    }
                )

                # Total value
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"{metric_prefix}|total_value",
                        "value": float(prices.sum()),
                        "available_date": collected_at,
                    }
                )

                # Price percentiles
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"{metric_prefix}|price_p25",
                        "value": float(prices.quantile(0.25)),
                        "available_date": collected_at,
                    }
                )

                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"{metric_prefix}|price_p75",
                        "value": float(prices.quantile(0.75)),
                        "available_date": collected_at,
                    }
                )

            # Price per sqft metrics (skip if meter_sale_price is all null)
            price_per_sqft = month_data["meter_sale_price"].dropna()
            if not price_per_sqft.empty:
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"{metric_prefix}|median_price_per_sqft",
                        "value": float(price_per_sqft.median()),
                        "available_date": collected_at,
                    }
                )

    # Compute YoY and MoM changes
    # Group metrics by metric_name (area|prop_type|metric) and compute deltas
    metrics_df = pd.DataFrame(metrics)

    if not metrics_df.empty:
        metrics_df["measurement_date"] = pd.to_datetime(
            metrics_df["measurement_date"]
        )

        yoy_mom_metrics = []

        for metric_name in metrics_df["metric_name"].unique():
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

                        # Extract base metric name and add _yoy
                        base_metric = metric_name.split("|")[-1]
                        yoy_metric_name = (
                            "|".join(metric_name.split("|")[:-1]) + f"|{base_metric}_yoy"
                        )

                        yoy_mom_metrics.append(
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

            # MoM change: requires 2+ months of data
            if len(metric_subset) >= 2:
                for i in range(1, len(metric_subset)):
                    current = metric_subset.iloc[i]
                    month_ago = metric_subset.iloc[i - 1]

                    if month_ago["value"] != 0:
                        mom_change = (
                            (current["value"] - month_ago["value"])
                            / month_ago["value"]
                        ) * 100

                        # Extract base metric name and add _mom
                        base_metric = metric_name.split("|")[-1]
                        mom_metric_name = (
                            "|".join(metric_name.split("|")[:-1]) + f"|{base_metric}_mom"
                        )

                        yoy_mom_metrics.append(
                            {
                                "source": source,
                                "measurement_date": current["measurement_date"].strftime(
                                    "%Y-%m-%d"
                                ),
                                "metric_name": mom_metric_name,
                                "value": float(mom_change),
                                "available_date": collected_at,
                            }
                        )

        metrics.extend(yoy_mom_metrics)

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
        result = normalize_dld(file_path, source, collected_at)

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
