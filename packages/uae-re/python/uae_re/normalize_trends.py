"""
Google Trends Normalization Module

Reads raw Google Trends JSON output from collect_trends.py and produces
normalized metric records for the analytics database.

For each keyword group, produces:
  - Per-keyword metric: dubai|trends_{group}_{keyword_slug}
  - Group aggregate:    dubai|trends_{group}_avg (mean of all keywords)

Time handling: Google Trends returns weekly data. Metrics are assigned
to the start of the month for monthly normalization (resample to month-start).

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str} from stdin
  Write: [{source, measurement_date, metric_name, value, available_date}] to stdout
  Errors: print to stderr, sys.exit(1)

NORM-02: available_date = collectedAt (when data became available to us)
NORM-04: Hard error on schema validation failure
"""

import json
import sys
from pathlib import Path

import pandas as pd

from .schemas.trends_schema import validate_trends_group


def _keyword_slug(keyword: str) -> str:
    """Convert keyword to slug: lowercase, spaces to underscores."""
    return keyword.lower().replace(" ", "_")


def normalize_trends(file_path: str, collected_at: str) -> list[dict]:
    """Normalize Google Trends data to monthly aggregated metrics.

    Args:
        file_path: Path to raw Google Trends JSON file from collect_trends.py.
        collected_at: ISO timestamp when data was collected (available_date).

    Returns:
        List of metric records: [{source, measurement_date, metric_name, value, available_date}]
    """
    source = "google-trends"

    # Load raw data
    with open(file_path) as f:
        raw = json.load(f)

    groups_data: dict = raw.get("data", {})
    metrics = []

    for group_name, records in groups_data.items():
        if not records:
            print(f"Warning: Empty records for group {group_name}", file=sys.stderr)
            continue

        # Build DataFrame from records list
        df = pd.DataFrame(records)

        if df.empty or "date" not in df.columns:
            print(f"Warning: No date column in group {group_name}", file=sys.stderr)
            continue

        keyword_cols = [c for c in df.columns if c != "date"]
        if not keyword_cols:
            print(f"Warning: No keyword columns in group {group_name}", file=sys.stderr)
            continue

        # Convert numeric columns (pytrends returns ints, may be stored as float after JSON)
        for col in keyword_cols:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        # Validate schema
        try:
            validate_trends_group(df, group_name)
        except Exception as e:
            print(f"Schema validation failed for group {group_name}: {e}", file=sys.stderr)
            raise

        # Parse dates and resample to monthly (use start of month for measurement_date)
        df["date"] = pd.to_datetime(df["date"])
        df = df.set_index("date")

        # Resample weekly data to monthly (mean per keyword per month)
        monthly = df.resample("MS")  # Month Start frequency

        for month_start, month_data in monthly:
            if month_data.empty:
                continue

            measurement_date = month_start.strftime("%Y-%m-%d")

            # Per-keyword metrics
            keyword_values = []
            for kw in keyword_cols:
                col_values = month_data[kw].dropna()
                if col_values.empty:
                    continue

                value = float(col_values.mean())
                keyword_values.append(value)

                slug = _keyword_slug(kw)
                metric_name = f"dubai|trends_{group_name}_{slug}"
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": metric_name,
                        "value": value,
                        "available_date": collected_at,
                    }
                )

            # Group-level aggregate: mean across all keywords for this month
            if keyword_values:
                group_avg = sum(keyword_values) / len(keyword_values)
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"dubai|trends_{group_name}_avg",
                        "value": group_avg,
                        "available_date": collected_at,
                    }
                )

    return metrics


def main() -> None:
    """Entry point: read stdin, normalize, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        result = normalize_trends(file_path, collected_at)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
