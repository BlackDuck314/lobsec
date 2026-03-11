"""
Monthly normalization and resampling module.

Bridge pattern:
- Read JSON array from stdin: [{date: ISO8601, value: number}, ...]
- Resample to month-end frequency with mean aggregation
- Forward-fill missing values (limit=1)
- Write normalized JSON to stdout
"""

import sys
import json
import pandas as pd


def normalize_to_monthly(data: list[dict]) -> list[dict]:
    """
    Normalize time-series data to monthly frequency.

    Args:
        data: List of {date, value} objects

    Returns:
        List of {date, value} objects with monthly resampling
    """
    if not data:
        return []

    # Create DataFrame from input
    df = pd.DataFrame(data)
    df['date'] = pd.to_datetime(df['date'])
    df = df.set_index('date')

    # Resample to month-end with mean aggregation
    monthly = df.resample('ME').mean()

    # Forward-fill missing values (limit 1 month gap)
    monthly = monthly.ffill(limit=1)

    # Convert back to records
    result = monthly.reset_index().to_dict('records')

    # Format dates as ISO8601
    for record in result:
        record['date'] = record['date'].isoformat()

    return result


def main():
    """Entry point: read stdin, normalize, write stdout."""
    try:
        # Read input
        data = json.load(sys.stdin)

        # Normalize
        result = normalize_to_monthly(data)

        # Write output
        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        # Log errors to stderr
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
