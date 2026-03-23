"""
IMF DataMapper API Collector (MACRO-02)

Fetches 6 WEO indicators for UAE (country code ARE) from the IMF
DataMapper API. Returns annual data from 1980 to ~2030 (includes
WEO forecasts for future years).

Indicators:
- NGDP_RPCH: Real GDP growth (%)
- PCPIPCH: Inflation rate, avg consumer prices (%)
- BCA_NGDPD: Current account balance (% of GDP)
- LP: Population (millions)
- NGDPD: GDP, current prices (USD billions)
- LUR: Unemployment rate (%)

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


# IMF DataMapper indicator codes
INDICATORS = [
    "NGDP_RPCH",   # Real GDP growth %
    "PCPIPCH",     # Inflation rate %
    "BCA_NGDPD",   # Current account balance % of GDP
    "LP",          # Population millions
    "NGDPD",       # GDP USD billions
    "LUR",         # Unemployment rate %
]

# IMF DataMapper API base URL
IMF_BASE_URL = "https://www.imf.org/external/datamapper/api/v1"


def collect_imf(output_dir: str) -> dict:
    """Fetch IMF DataMapper indicators for UAE.

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int}
    """
    imf_dir = Path(output_dir) / "imf-weo"
    imf_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = imf_dir / f"{today}.json"
    collected_at = datetime.now(timezone.utc).isoformat()

    indicators_data = {}
    total_rows = 0

    for code in INDICATORS:
        url = f"{IMF_BASE_URL}/{code}/ARE"
        print(f"Fetching IMF indicator {code}...", file=sys.stderr)

        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            # Response: {values: {CODE: {ARE: {YEAR: VALUE}}}}
            values = data.get("values", {}).get(code, {}).get("ARE", {})

            if values:
                # Convert to {year: value} dict, skip None values
                year_values = {
                    year: val
                    for year, val in values.items()
                    if val is not None
                }
                indicators_data[code] = year_values
                total_rows += len(year_values)
                print(
                    f"  {code}: {len(year_values)} year records",
                    file=sys.stderr,
                )
            else:
                print(f"  {code}: no data found for ARE", file=sys.stderr)
                indicators_data[code] = {}

        except Exception as e:
            print(f"  WARNING: Failed to fetch {code}: {e}", file=sys.stderr)
            indicators_data[code] = {}

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

        result = collect_imf(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
