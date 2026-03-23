"""
DFM Stock Price Normalizer (MACRO-04)

Reads raw JSON from the Yahoo Finance DFM stock collector and produces
normalized monthly records for close prices and trading volumes.

Metrics produced (8 total, 2 per stock):
- uae|dfm_emaar_close, uae|dfm_emaar_volume
- uae|dfm_emaardev_close, uae|dfm_emaardev_volume
- uae|dfm_deyaar_close, uae|dfm_deyaar_volume
- uae|dfm_upp_close, uae|dfm_upp_volume

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

from .schemas.dfm_stocks_schema import validate_dfm_stocks_json


# Yahoo Finance symbol -> normalized label
SYMBOL_TO_LABEL = {
    "EMAAR.AE": "emaar",
    "EMAARDEV.AE": "emaardev",
    "DEYAAR.AE": "deyaar",
    "UPP.AE": "upp",
}


def normalize_dfm_stocks(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize DFM stock JSON data to monthly metrics.

    For each stock, produces close price and volume as separate metrics.

    Args:
        file_path: Path to raw JSON file from collector.
        collected_at: ISO timestamp when data was collected.

    Returns:
        List of NormalizedRecord dicts.
    """
    validate_dfm_stocks_json(file_path)

    with open(file_path) as f:
        data = json.load(f)

    # Use collectedAt from raw data if available, else use provided value
    available_date = data.get("collectedAt", collected_at)
    if "T" in available_date:
        available_date = available_date[:10]

    stocks = data.get("stocks", {})
    metrics = []

    for symbol, stock_data in stocks.items():
        label = SYMBOL_TO_LABEL.get(symbol)
        if not label:
            print(f"WARNING: Unknown stock symbol '{symbol}', skipping", file=sys.stderr)
            continue

        timestamps = stock_data.get("timestamps", [])
        ohlcv = stock_data.get("ohlcv", {})
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
                    "metric_name": f"uae|dfm_{label}_close",
                    "value": float(close),
                    "available_date": available_date,
                })

            # Volume
            volume = volumes[i] if i < len(volumes) else None
            if volume is not None:
                metrics.append({
                    "measurement_date": measurement_date,
                    "metric_name": f"uae|dfm_{label}_volume",
                    "value": float(volume),
                    "available_date": available_date,
                })

        print(f"  {symbol} ({label}): {len(timestamps)} months processed", file=sys.stderr)

    print(f"Normalized {len(metrics)} DFM stock records", file=sys.stderr)
    return metrics


def main() -> None:
    """Entry point for Python normalization bridge."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        normalized = normalize_dfm_stocks(file_path, collected_at)

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
