"""
DFM RE Stock Collector via Yahoo Finance v8 API (MACRO-04)

Fetches monthly OHLCV data for 4 DFM real estate sector stocks from
the Yahoo Finance v8 chart API:
- EMAAR.AE (Emaar Properties PJSC)
- EMAARDEV.AE (Emaar Development PJSC)
- DEYAAR.AE (Deyaar Development PJSC)
- UPP.AE (Union Properties PJSC)

Note: DAMAC.AE was delisted in Feb 2022 (taken private). Replaced by EMAARDEV.AE.

Bridge pattern:
  Read:  {"outputDir": "/opt/lobsec/data/raw"} from stdin
  Write: {"filePath": str, "rowCount": int} to stdout
  Errors: print to stderr, sys.exit(1)
"""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


# DFM RE sector stocks (Yahoo Finance symbols)
STOCKS = ["EMAAR.AE", "EMAARDEV.AE", "DEYAAR.AE", "UPP.AE"]

# Yahoo Finance v8 chart API base URLs (query2 more reliable, query1 as fallback)
YF_BASE_URLS = [
    "https://query2.finance.yahoo.com/v8/finance/chart",
    "https://query1.finance.yahoo.com/v8/finance/chart",
]

# Required User-Agent header (Yahoo Finance blocks requests without it)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)


def collect_dfm_stocks(output_dir: str) -> dict:
    """Fetch monthly OHLCV data for DFM RE stocks.

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int}
    """
    stocks_dir = Path(output_dir) / "dfm-stocks"
    stocks_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = stocks_dir / f"{today}.json"
    collected_at = datetime.now(timezone.utc).isoformat()

    stocks_data = {}
    total_rows = 0

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    for idx, symbol in enumerate(STOCKS):
        print(f"Fetching {symbol} from Yahoo Finance...", file=sys.stderr)

        # Try each base URL until one succeeds
        data = None
        for base_url in YF_BASE_URLS:
            url = f"{base_url}/{symbol}"
            try:
                resp = requests.get(
                    url,
                    params={"interval": "1mo", "range": "5y"},
                    headers=headers,
                    timeout=30,
                )
                if resp.status_code == 429:
                    print(f"  Rate limited on {base_url}, trying next...", file=sys.stderr)
                    time.sleep(2)
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.exceptions.HTTPError:
                print(f"  HTTP error on {base_url}, trying next...", file=sys.stderr)
                time.sleep(1)
                continue

        if data is None:
            print(f"  WARNING: All endpoints failed for {symbol}", file=sys.stderr)
            stocks_data[symbol] = {"timestamps": [], "ohlcv": {}}
            continue

        try:

            chart = data.get("chart", {})
            error = chart.get("error")
            if error:
                print(
                    f"  WARNING: Yahoo Finance error for {symbol}: {error}",
                    file=sys.stderr,
                )
                stocks_data[symbol] = {"timestamps": [], "ohlcv": {}}
                continue

            results = chart.get("result", [])
            if not results:
                print(f"  WARNING: No results for {symbol}", file=sys.stderr)
                stocks_data[symbol] = {"timestamps": [], "ohlcv": {}}
                continue

            result = results[0]
            timestamps = result.get("timestamp", [])
            quote = result.get("indicators", {}).get("quote", [{}])[0]

            stocks_data[symbol] = {
                "timestamps": timestamps,
                "ohlcv": {
                    "open": quote.get("open", []),
                    "high": quote.get("high", []),
                    "low": quote.get("low", []),
                    "close": quote.get("close", []),
                    "volume": quote.get("volume", []),
                },
            }

            total_rows += len(timestamps)
            print(f"  {symbol}: {len(timestamps)} monthly records", file=sys.stderr)

        except Exception as e:
            print(f"  WARNING: Failed to fetch {symbol}: {e}", file=sys.stderr)
            stocks_data[symbol] = {"timestamps": [], "ohlcv": {}}

        # Rate limiting: pause between requests
        if idx < len(STOCKS) - 1:
            time.sleep(1)

    output = {
        "collectedAt": collected_at,
        "stocks": stocks_data,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Wrote {total_rows} total records to {out_path}", file=sys.stderr)
    return {"filePath": str(out_path), "rowCount": total_rows}


def main() -> None:
    """Entry point: read stdin, collect, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        output_dir = input_data.get("outputDir", "/opt/lobsec/data/raw")

        result = collect_dfm_stocks(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
