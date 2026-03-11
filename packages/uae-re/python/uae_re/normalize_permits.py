"""
Building Permits Normalization Module

Reads building permits CSV, classifies residential vs commercial, aggregates by month.
Tracks permit issuance, withdrawal, and expiry by type and area.

Bridge pattern:
- Read: {filePath, source, collectedAt} from stdin
- Process: Load CSV, validate schema, classify permits, aggregate
- Write: [{source, measurement_date, metric_name, value, available_date}] to stdout
- Errors: print to stderr, sys.exit(1)

NORM-02: available_date = collectedAt (when data became available to us)
NORM-04: Hard error on schema validation failure
"""

import sys
import json
import pandas as pd
from .schemas.permits_schema import permits_schema


def classify_permit_type(row: pd.Series) -> str:
    """
    Classify permit as residential, commercial, or other.

    Checks multiple fields: permit_type, building_type, usage, project_type.
    Returns: "residential", "commercial", or "other"
    """
    # Combine all classification fields into one lowercase string for matching
    fields = []
    for field in ["permit_type", "building_type", "usage", "project_type"]:
        if field in row and pd.notna(row[field]):
            fields.append(str(row[field]).lower())

    combined = " ".join(fields)

    # Residential keywords
    residential_keywords = [
        "residential",
        "villa",
        "apartment",
        "townhouse",
        "flat",
        "housing",
        "dwelling",
    ]

    # Commercial keywords
    commercial_keywords = [
        "commercial",
        "office",
        "retail",
        "industrial",
        "hotel",
        "shopping",
        "warehouse",
        "factory",
    ]

    # Check for matches
    if any(keyword in combined for keyword in residential_keywords):
        return "residential"
    elif any(keyword in combined for keyword in commercial_keywords):
        return "commercial"
    else:
        return "other"


def normalize_permits(file_path: str, source: str, collected_at: str) -> list[dict]:
    """
    Normalize building permits data to monthly aggregated metrics.

    Args:
        file_path: Path to raw permits CSV file
        source: Source identifier ("building-permits")
        collected_at: ISO timestamp when data was collected

    Returns:
        List of metric records: [{source, measurement_date, metric_name, value, available_date}]
    """
    # Load CSV
    df = pd.read_csv(file_path)

    # Validate schema with pandera (NORM-04: hard error on failure)
    df = permits_schema.validate(df)

    if df.empty:
        return []

    # Parse dates
    df["issue_date"] = pd.to_datetime(df["issue_date"])

    # Classify each permit
    df["permit_class"] = df.apply(classify_permit_type, axis=1)

    # Set date as index for resampling
    df = df.set_index("issue_date")

    # Aggregate metrics
    metrics = []

    # Overall metrics by permit class and status
    monthly = df.resample("ME")

    for month_end, month_data in monthly:
        if month_data.empty:
            continue

        measurement_date = month_end.strftime("%Y-%m-%d")

        # Count by permit class
        for permit_class in ["residential", "commercial"]:
            class_data = month_data[month_data["permit_class"] == permit_class]

            if not class_data.empty:
                # Total permits issued for this class
                metrics.append(
                    {
                        "source": source,
                        "measurement_date": measurement_date,
                        "metric_name": f"permits_issued_{permit_class}",
                        "value": float(len(class_data)),
                        "available_date": collected_at,
                    }
                )

        # Count by status (across all classes)
        if "status" in month_data.columns:
            for status in ["withdrawn", "expired"]:
                status_count = month_data[
                    month_data["status"].str.lower().str.contains(status, na=False)
                ].shape[0]

                if status_count > 0:
                    metrics.append(
                        {
                            "source": source,
                            "measurement_date": measurement_date,
                            "metric_name": f"permits_{status}",
                            "value": float(status_count),
                            "available_date": collected_at,
                        }
                    )

    # Per-area metrics (if area field is available)
    area_field = None
    for field in ["area", "zone", "location"]:
        if field in df.columns:
            area_field = field
            break

    if area_field:
        # Get unique areas
        areas = df[area_field].dropna().unique()

        for area in areas:
            area_data = df[df[area_field] == area]
            area_monthly = area_data.resample("ME")

            for month_end, month_data in area_monthly:
                if month_data.empty:
                    continue

                measurement_date = month_end.strftime("%Y-%m-%d")

                # Count by permit class per area
                for permit_class in ["residential", "commercial"]:
                    class_count = month_data[
                        month_data["permit_class"] == permit_class
                    ].shape[0]

                    if class_count > 0:
                        metrics.append(
                            {
                                "source": source,
                                "measurement_date": measurement_date,
                                "metric_name": f"{area}|permits_{permit_class}",
                                "value": float(class_count),
                                "available_date": collected_at,
                            }
                        )

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
        result = normalize_permits(file_path, source, collected_at)

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
