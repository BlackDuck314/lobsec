"""
IMF DataMapper Normalizer with Forecast Separation (MACRO-02)

Reads raw JSON from the IMF collector and produces normalized monthly
records. CRITICAL: Separates historical data from WEO forecasts.

Historical metrics (year <= current year):
- uae|imf_weo_gdp_growth_pct
- uae|imf_weo_inflation_pct
- uae|imf_weo_current_account_pct_gdp
- uae|imf_weo_population_mn
- uae|imf_weo_gdp_usd_bn
- uae|imf_weo_unemployment_pct

Forecast metrics (year > current year):
- uae|imf_weo_forecast_gdp_growth_pct
- uae|imf_weo_forecast_inflation_pct
- uae|imf_weo_forecast_current_account_pct_gdp
- uae|imf_weo_forecast_population_mn
- uae|imf_weo_forecast_gdp_usd_bn
- uae|imf_weo_forecast_unemployment_pct

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str, "source": str} from stdin
  Write: [{measurement_date, metric_name, value, available_date, source}, ...] to stdout
"""

import json
import sys
from datetime import datetime
from typing import Any

from .schemas.imf_schema import validate_imf_json


# IMF indicator code -> metric label suffix
CODE_TO_LABEL = {
    "NGDP_RPCH": "gdp_growth_pct",
    "PCPIPCH": "inflation_pct",
    "BCA_NGDPD": "current_account_pct_gdp",
    "LP": "population_mn",
    "NGDPD": "gdp_usd_bn",
    "LUR": "unemployment_pct",
}


def normalize_imf(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """
    Normalize IMF DataMapper JSON data to monthly metrics.

    Separates historical from forecast data based on current year.

    Args:
        file_path: Path to raw JSON file from collector.
        collected_at: ISO timestamp when data was collected.

    Returns:
        List of NormalizedRecord dicts.
    """
    validate_imf_json(file_path)

    with open(file_path) as f:
        data = json.load(f)

    # Use collectedAt from raw data if available, else use provided value
    available_date = data.get("collectedAt", collected_at)
    if "T" in available_date:
        available_date = available_date[:10]

    indicators = data.get("indicators", {})
    metrics = []

    # Current year for forecast separation (not hardcoded)
    current_year = datetime.now().year

    for code, year_values in indicators.items():
        label = CODE_TO_LABEL.get(code)
        if not label:
            print(f"WARNING: Unknown IMF indicator code '{code}', skipping", file=sys.stderr)
            continue

        for year_str, value in year_values.items():
            if value is None:
                continue

            try:
                year = int(year_str)
            except (ValueError, TypeError):
                print(f"WARNING: Invalid year '{year_str}' for {code}, skipping", file=sys.stderr)
                continue

            # Determine if this is historical or forecast
            if year > current_year:
                metric_name = f"uae|imf_weo_forecast_{label}"
            else:
                metric_name = f"uae|imf_weo_{label}"

            metrics.append({
                "measurement_date": f"{year}-01-01",
                "metric_name": metric_name,
                "value": float(value),
                "available_date": available_date,
            })

    print(
        f"Normalized {len(metrics)} IMF records "
        f"(cutoff year={current_year} for forecast separation)",
        file=sys.stderr,
    )
    return metrics


def main() -> None:
    """Entry point for Python normalization bridge."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        normalized = normalize_imf(file_path, collected_at)

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
