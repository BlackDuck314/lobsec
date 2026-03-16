"""
Google Trends Data Collection Module (COLL-14 + COLL-27)

Fetches interest-over-time data for 6 keyword groups from Google Trends
via pytrends, scoped to UAE (geo=AE). Covers:
  - buy_intent:      property purchase intent signals
  - rent_intent:     rental demand signals
  - expat_lifecycle: expat arrival/departure lifecycle
  - distress:        tenancy distress signals
  - luxury:          luxury segment demand
  - exit_moving:     departure intent (COLL-27 proxy — moving company inquiries)

Bridge pattern:
  Read:  {"outputDir": "/opt/lobsec/data/raw"} from stdin
  Write: {"filePath": str, "rowCount": int} to stdout
  Errors: print to stderr, sys.exit(1)

Rate limiting: random 5-15s sleep between groups to avoid HTTP 429.
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pytrends.request import TrendReq


# Six keyword groups per CONTEXT.md decisions.
# exit_moving group implements COLL-27 (moving company inquiries as Google Trends proxy).
KEYWORD_GROUPS: dict[str, list[str]] = {
    "buy_intent": ["buy apartment Dubai", "Dubai property investment", "off-plan Dubai"],
    "rent_intent": ["rent apartment Dubai", "Dubai rental", "furnished flat Dubai"],
    "expat_lifecycle": ["Dubai work visa", "UAE job", "move to Dubai", "Golden Visa Dubai"],
    "distress": ["break tenancy Dubai", "cancel Ejari", "move out Dubai"],
    "luxury": ["luxury villa Dubai", "penthouse Dubai", "premium apartment Dubai"],
    "exit_moving": ["moving companies dubai", "international movers dubai", "leaving Dubai"],
}


def collect_trends(output_dir: str) -> dict:
    """Fetch Google Trends data for all 6 keyword groups.

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int} where rowCount is total data points.
    """
    # Prepare output directory
    trends_dir = Path(output_dir) / "google-trends"
    trends_dir.mkdir(parents=True, exist_ok=True)

    collected_at = datetime.now(timezone.utc).isoformat()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = trends_dir / f"{today}.json"

    # Check for proxy configuration
    proxy_url = os.getenv("NINJA_PROXY_URL", "")
    proxies = [proxy_url] if proxy_url else []

    # Initialize pytrends with UAE timezone (UTC+4 = 240 minutes)
    pytrends = TrendReq(
        hl="en-US",
        tz=240,
        timeout=(10, 25),
        retries=3,
        backoff_factor=0.5,
        proxies=proxies,
    )

    collected_data: dict[str, list[dict]] = {}
    total_records = 0

    for group_idx, (group_name, keywords) in enumerate(KEYWORD_GROUPS.items()):
        print(f"Fetching group {group_idx + 1}/{len(KEYWORD_GROUPS)}: {group_name}", file=sys.stderr)

        try:
            # Build payload: interest over time, last 12 months, UAE geo
            pytrends.build_payload(
                kw_list=keywords,
                geo="AE",
                timeframe="today 12-m",
            )

            df = pytrends.interest_over_time()

            if df.empty:
                print(f"Warning: No data returned for group {group_name}", file=sys.stderr)
                collected_data[group_name] = []
                continue

            # Drop the 'isPartial' column if present (boolean flag, not data)
            if "isPartial" in df.columns:
                df = df.drop(columns=["isPartial"])

            # Convert to list of records: [{date, kw1, kw2, ...}]
            df.index = df.index.astype(str)  # Convert DatetimeIndex to ISO strings
            records = df.reset_index().rename(columns={"date": "date"}).to_dict(orient="records")
            collected_data[group_name] = records
            total_records += len(records)
            print(f"  Got {len(records)} data points for {group_name}", file=sys.stderr)

        except Exception as e:
            print(f"Warning: Failed to fetch group {group_name}: {e}", file=sys.stderr)
            collected_data[group_name] = []

        # Rate limiting: random sleep between groups (skip after last)
        if group_idx < len(KEYWORD_GROUPS) - 1:
            sleep_secs = random.uniform(5, 15)
            print(f"  Sleeping {sleep_secs:.1f}s before next group...", file=sys.stderr)
            time.sleep(sleep_secs)

    # Write raw output
    output = {
        "collectedAt": collected_at,
        "data": collected_data,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {total_records} records to {out_path}", file=sys.stderr)
    return {"filePath": str(out_path), "rowCount": total_records}


def main() -> None:
    """Entry point: read stdin, collect, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        output_dir = input_data.get("outputDir", "/opt/lobsec/data/raw")

        result = collect_trends(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
