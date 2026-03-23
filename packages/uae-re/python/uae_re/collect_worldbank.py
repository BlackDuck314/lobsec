"""
World Bank Indicators API Collector (MACRO-01)

Fetches 5 macro-economic indicators for UAE (country code ARE) from the
World Bank v2 REST API. Returns annual data from 2000 to present.

Indicators:
- NY.GDP.MKTP.KD.ZG: GDP growth (annual %)
- FP.CPI.TOTL.ZG: Inflation, consumer prices (annual %)
- BX.KLT.DINV.CD.WD: FDI, net inflows (BoP, current US$)
- NE.TRD.GNFS.ZS: Trade (% of GDP)
- SP.POP.TOTL: Population, total

Bridge pattern:
  Read:  {"outputDir": "/opt/lobsec/data/raw"} from stdin
  Write: {"filePath": str, "rowCount": int} to stdout
  Errors: print to stderr, sys.exit(1)
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


# World Bank indicator codes -> metric labels
INDICATORS = {
    "NY.GDP.MKTP.KD.ZG": "gdp_growth_pct",
    "FP.CPI.TOTL.ZG": "cpi_inflation_pct",
    "BX.KLT.DINV.CD.WD": "fdi_inflows_usd",
    "NE.TRD.GNFS.ZS": "trade_pct_gdp",
    "SP.POP.TOTL": "population",
}

# World Bank API base URL
WB_BASE_URL = "https://api.worldbank.org/v2/country/ARE/indicator"


def collect_worldbank(output_dir: str) -> dict:
    """Fetch World Bank indicators for UAE.

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int}
    """
    wb_dir = Path(output_dir) / "worldbank-macro"
    wb_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = wb_dir / f"{today}.json"
    collected_at = datetime.now(timezone.utc).isoformat()

    indicators_data = {}
    total_rows = 0

    for code, label in INDICATORS.items():
        url = f"{WB_BASE_URL}/{code}"
        print(f"Fetching World Bank indicator {code} ({label})...", file=sys.stderr)

        try:
            resp = requests.get(
                url,
                params={
                    "format": "json",
                    "per_page": 50,
                    "date": "2000:2026",
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            # Response is [pagination_meta, [records...]]
            if isinstance(data, list) and len(data) > 1 and isinstance(data[1], list):
                records = data[1]
                # Filter out records with null values
                valid_records = [
                    {"date": r["date"], "value": r["value"]}
                    for r in records
                    if r.get("value") is not None
                ]
                indicators_data[label] = valid_records
                total_rows += len(valid_records)
                print(
                    f"  {label}: {len(valid_records)} records (of {len(records)} total)",
                    file=sys.stderr,
                )
            else:
                print(f"  {label}: unexpected response format, skipping", file=sys.stderr)
                indicators_data[label] = []

        except Exception as e:
            print(f"  WARNING: Failed to fetch {code}: {e}", file=sys.stderr)
            indicators_data[label] = []

    output = {
        "collectedAt": collected_at,
        "indicators": indicators_data,
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

        result = collect_worldbank(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
