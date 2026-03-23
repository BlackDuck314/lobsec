"""
Commodity Price Normalizer (COMM-01, COMM-02)

Reads raw JSON from the Yahoo Finance commodity collector and produces
normalized monthly records for close prices and trading volumes.

Metrics produced (4 total, 2 per commodity):
- uae|brent_crude_close_usd, uae|brent_crude_volume
- uae|gold_xau_close_usd, uae|gold_xau_volume

Timestamps are Unix epoch seconds, converted to YYYY-MM-01 for measurement_date.
Entries where close is None (holiday months) are skipped.

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str, "source": str} from stdin
  Write: [{measurement_date, metric_name, value, available_date, source}, ...] to stdout
"""

import json
import sys
from datetime import datetime, timezone
from typing import Any

from .schemas.commodities_schema import validate_commodities_json


# Yahoo Finance symbol -> normalized label
SYMBOL_TO_LABEL = {
    "BZ=F": "brent_crude",
    "GC=F": "gold_xau",
}


def normalize_commodities(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize commodity JSON data to monthly metrics.

    For each commodity, produces close price and volume as separate metrics.

    Args:
        file_path: Path to raw JSON file from collector.
        collected_at: ISO timestamp when data was collected.

    Returns:
        List of NormalizedRecord dicts.
    """
    validate_commodities_json(file_path)

    with open(file_path) as f:
        data = json.load(f)

    # Use collectedAt from raw data if available, else use provided value
    available_date = data.get("collectedAt", collected_at)
    if "T" in available_date:
        available_date = available_date[:10]

    commodities = data.get("commodities", {})
    metrics = []

    for symbol, commodity_data in commodities.items():
        label = SYMBOL_TO_LABEL.get(symbol)
        if not label:
            print(f"WARNING: Unknown commodity symbol '{symbol}', skipping", file=sys.stderr)
            continue

        timestamps = commodity_data.get("timestamps", [])
        ohlcv = commodity_data.get("ohlcv", {})
        close_prices = ohlcv.get("close", [])
        volumes = ohlcv.get("volume", [])

        if not timestamps:
            print(f"  {symbol}: no timestamp data", file=sys.stderr)
            continue

        for i, ts in enumerate(timestamps):
            # Convert Unix timestamp to datetime
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            # Monthly data: use first of month
            measurement_date = dt.strftime("%Y-%m-01")

            # Close price
            close = close_prices[i] if i < len(close_prices) else None
            if close is not None:
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"uae|{label}_close_usd",
                    "value": float(close),
                    "available_date": available_date,
                })

            # Volume
            volume = volumes[i] if i < len(volumes) else None
            if volume is not None:
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"uae|{label}_volume",
                    "value": float(volume),
                    "available_date": available_date,
                })

        print(f"  {symbol} ({label}): {len(timestamps)} months processed", file=sys.stderr)

    print(f"Normalized {len(metrics)} commodity records", file=sys.stderr)
    return metrics


def main() -> None:
    """Entry point for Python normalization bridge."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        normalized = normalize_commodities(file_path, collected_at)

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
