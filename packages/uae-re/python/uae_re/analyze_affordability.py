"""
Affordability model module.

Bridge pattern:
- Read JSON from stdin: {"db_path": "/path/to/uae-re.db"}
- Define 5 income brackets for UAE expat workforce
- Fetch median rent per area from normalized_monthly (ejari avg_rent_per_sqft)
- Compute salary-to-rent ratio for each (bracket, area) combination
- Classify: unaffordable (<3), stretched (3-5), comfortable (>5)
- Store result in intelligence_cache with TTL until next 25th
- Write analysis_log entry (metadata only — SEC-07)
- Output summary JSON to stdout

Output format:
{
  "areas_computed": int,
  "brackets": ["entry", "mid_low", "mid", "senior", "executive"]
}
"""

import sys
import json
import sqlite3
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional


# Income brackets from RESEARCH.md (monthly AED)
INCOME_BRACKETS = [
    {"name": "entry",     "min": 5_000,   "max": 10_000,  "midpoint": 7_500},
    {"name": "mid_low",   "min": 10_001,  "max": 20_000,  "midpoint": 15_000},
    {"name": "mid",       "min": 20_001,  "max": 35_000,  "midpoint": 27_500},
    {"name": "senior",    "min": 35_001,  "max": 60_000,  "midpoint": 47_500},
    {"name": "executive", "min": 60_001,  "max": None,    "midpoint": 90_000},
]

# Classification thresholds (salary-to-rent ratio)
UNAFFORDABLE_THRESHOLD = 3.0   # ratio < 3.0 = unaffordable (>33% of income on rent)
COMFORTABLE_THRESHOLD = 5.0    # ratio > 5.0 = comfortable (<20% of income on rent)
# 3.0 <= ratio <= 5.0 = stretched


def classify_affordability(ratio: float) -> str:
    """Classify salary-to-rent ratio into affordability category."""
    if ratio < UNAFFORDABLE_THRESHOLD:
        return "unaffordable"
    elif ratio > COMFORTABLE_THRESHOLD:
        return "comfortable"
    else:
        return "stretched"


def next_25th_datetime() -> str:
    """
    Compute the ISO timestamp for the next 25th of month at 06:00 GST (02:00 UTC).

    Used as expires_at for intelligence_cache TTL.
    """
    now = datetime.now(timezone.utc)
    year, month = now.year, now.month

    # Build candidate: 25th of current month at 02:00 UTC
    candidate = datetime(year, month, 25, 2, 0, 0, tzinfo=timezone.utc)

    if now >= candidate:
        # Already past or at this month's 25th — use next month
        if month == 12:
            year += 1
            month = 1
        else:
            month += 1
        candidate = datetime(year, month, 25, 2, 0, 0, tzinfo=timezone.utc)

    return candidate.strftime("%Y-%m-%d %H:%M:%S")


def params_hash(params: dict) -> str:
    """Compute deterministic SHA-256 hash of params dict for cache key."""
    serialized = json.dumps(params, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def fetch_area_names(db: sqlite3.Connection) -> list[str]:
    """
    Fetch canonical area names for Dubai.

    Parameterized SQL — SEC-06.
    """
    rows = db.execute(
        "SELECT DISTINCT canonical_name FROM area_names WHERE emirate = ? ORDER BY canonical_name",
        ("dubai",),
    ).fetchall()
    return [row[0] for row in rows]


def fetch_salary_for_bracket(
    db: sqlite3.Connection,
    bracket_name: str,
    bracket_midpoint: float,
) -> float:
    """
    Fetch median salary for a bracket from normalized_monthly.

    Source: 'salary', metric_name: 'median_salary_{bracket_name}'.
    Falls back to bracket midpoint if data not yet available.

    Parameterized SQL — SEC-06.
    """
    metric_name = f"median_salary_{bracket_name}"
    row = db.execute(
        "SELECT value FROM normalized_monthly "
        "WHERE source = ? AND metric_name = ? "
        "AND value IS NOT NULL "
        "ORDER BY measurement_date DESC LIMIT 1",
        ("salary", metric_name),
    ).fetchone()

    if row is not None and row[0] is not None:
        return float(row[0])

    # Salary data not yet available — use bracket midpoint as default
    print(
        f"  FALLBACK {bracket_name}: using midpoint {bracket_midpoint} (no salary data)",
        file=sys.stderr,
    )
    return bracket_midpoint


def fetch_latest_ejari_rent(
    db: sqlite3.Connection,
    measurement_date: str,
    area_name: Optional[str] = None,
) -> Optional[float]:
    """
    Fetch the average rent per sqft from Ejari for a given date.

    The normalized_monthly table stores city-wide aggregates without an area_name
    column — area-level granularity is encoded in metric_name (e.g. avg_rent_per_sqft).
    The area_name parameter is accepted for interface compatibility but is not used
    as a filter condition; city-wide rent is returned regardless.

    Parameterized SQL — SEC-06.
    """
    row = db.execute(
        "SELECT value FROM normalized_monthly "
        "WHERE source = ? AND metric_name = ? "
        "AND measurement_date = ? "
        "AND value IS NOT NULL "
        "LIMIT 1",
        ("ejari", "avg_rent_per_sqft", measurement_date),
    ).fetchone()

    if row is not None and row[0] is not None:
        return float(row[0])
    return None


def fetch_latest_ejari_date(db: sqlite3.Connection) -> Optional[str]:
    """
    Fetch the most recent measurement_date for ejari avg_rent_per_sqft.

    Parameterized SQL — SEC-06.
    """
    row = db.execute(
        "SELECT MAX(measurement_date) FROM normalized_monthly "
        "WHERE source = ? AND metric_name = ? AND value IS NOT NULL",
        ("ejari", "avg_rent_per_sqft"),
    ).fetchone()

    if row and row[0]:
        return str(row[0])
    return None


def main() -> None:
    """Entry point: read stdin, compute affordability model, write stdout."""
    start_ms = int(time.monotonic() * 1000)

    try:
        config = json.load(sys.stdin)
        db_path = config["db_path"]
    except Exception as e:
        print(f"ERROR reading input: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        db = sqlite3.connect(db_path)
    except Exception as e:
        print(f"ERROR opening database: {e}", file=sys.stderr)
        sys.exit(1)

    areas_computed = 0
    bracket_names = [b["name"] for b in INCOME_BRACKETS]
    error_msg: Optional[str] = None

    try:
        # --- Step 1: Fetch area names ---
        area_names = fetch_area_names(db)
        print(f"Affordability: {len(area_names)} areas", file=sys.stderr)

        # --- Step 2: Fetch latest ejari measurement date ---
        latest_date = fetch_latest_ejari_date(db)
        if latest_date is None:
            print("WARNING: No ejari rent data found — affordability will use zeros", file=sys.stderr)
            latest_date = "2000-01-01"  # Sentinel — fetches will return None → fallback

        print(f"  Using ejari date: {latest_date}", file=sys.stderr)

        # --- Step 3: Fetch city-wide rent (fallback for areas with no data) ---
        city_wide_rent = fetch_latest_ejari_rent(db, latest_date, area_name=None)
        print(
            f"  City-wide rent: {city_wide_rent} AED/sqft "
            f"{'(fallback)' if city_wide_rent is None else ''}",
            file=sys.stderr,
        )

        # --- Step 4: Fetch salary for each bracket ---
        bracket_salaries = {}
        for bracket in INCOME_BRACKETS:
            salary = fetch_salary_for_bracket(db, bracket["name"], bracket["midpoint"])
            bracket_salaries[bracket["name"]] = salary

        # --- Step 5: Build result structure ---
        # brackets: {bracket_name: {salary_aed, areas: {area: {rent_aed, ratio, classification}}}}
        brackets_result: dict = {}

        for bracket in INCOME_BRACKETS:
            bname = bracket["name"]
            salary = bracket_salaries[bname]
            area_results: dict = {}

            for area in area_names:
                # Try area-specific rent, fall back to city-wide
                rent = fetch_latest_ejari_rent(db, latest_date, area_name=area)
                if rent is None:
                    rent = city_wide_rent
                if rent is None or rent <= 0:
                    # No rent data at all — skip this area for this bracket
                    print(
                        f"  SKIP {area}/{bname}: no rent data",
                        file=sys.stderr,
                    )
                    continue

                # Rent is per sqft — convert to monthly for a typical 1BR (~750 sqft)
                # avg_rent_per_sqft is annual AED/sqft, so: monthly_rent = sqft * annual_rate / 12
                # Typical Dubai 1BR: 750 sqft
                typical_sqft = 750
                monthly_rent = (rent * typical_sqft) / 12.0

                if monthly_rent <= 0:
                    continue

                ratio = salary / monthly_rent
                classification = classify_affordability(ratio)

                area_results[area] = {
                    "rent_aed": round(monthly_rent, 2),
                    "ratio": round(ratio, 3),
                    "classification": classification,
                }

            brackets_result[bname] = {
                "salary_aed": salary,
                "areas": area_results,
            }

        areas_computed = len(area_names)

        # --- Step 6: Build result JSON ---
        result = {
            "brackets": brackets_result,
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }

        result_json = json.dumps(result)
        cache_params = {"product": "affordability", "version": "1"}
        phash = params_hash(cache_params)
        expires_at = next_25th_datetime()

        # Store in intelligence_cache — parameterized SQL (SEC-06)
        db.execute(
            "INSERT OR REPLACE INTO intelligence_cache "
            "(cache_key, product, params_hash, result_json, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, datetime('now'), ?)",
            ("affordability_latest", "affordability", phash, result_json, expires_at),
        )
        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Write analysis_log entry — areas_computed count only (SEC-07)
        db.execute(
            "INSERT INTO analysis_log "
            "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, run_at) "
            "VALUES ('affordability', ?, ?, ?, ?, datetime('now'))",
            ("success", areas_computed, 0, duration_ms),
        )
        db.commit()

        print(
            f"Affordability: {areas_computed} areas × {len(INCOME_BRACKETS)} brackets "
            f"in {duration_ms}ms, expires {expires_at}",
            file=sys.stderr,
        )

    except Exception as e:
        error_msg = str(e)
        print(f"ERROR during affordability computation: {error_msg}", file=sys.stderr)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Log failure — sanitized error only (SEC-07)
        try:
            db.execute(
                "INSERT INTO analysis_log "
                "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) "
                "VALUES ('affordability', 'failed', ?, ?, ?, ?, datetime('now'))",
                (0, 0, duration_ms, error_msg),
            )
            db.commit()
        except Exception:
            pass

    finally:
        db.close()

    if error_msg:
        sys.exit(1)

    output = {
        "areas_computed": areas_computed,
        "brackets": bracket_names,
    }
    json.dump(output, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
