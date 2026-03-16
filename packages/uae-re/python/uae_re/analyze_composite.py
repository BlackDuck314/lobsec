"""
Composite index computation module.

Bridge pattern:
- Read JSON from stdin: {"db_path": "/path/to/uae-re.db"}
- Read significant Granger results from granger_results table
- Z-score normalize each signal's recent 12 months from normalized_monthly
- Compute weighted composite per area AND city-wide
- Scale to [-1, +1] via tanh(raw/2)
- Write results to composite_scores table
- Write analysis_log entry (metadata only — SEC-07)
- Output summary JSON to stdout

Output format:
{
  "areas_computed": int,
  "city_wide_score": float,
  "city_wide_zone": str
}
"""

import sys
import json
import sqlite3
import time
import math
from typing import Optional

import numpy as np


# Signals that have area-level granularity (produced per canonical_name)
# These are the sources where normalized_monthly rows have area_name populated
AREA_LEVEL_SOURCES = {"bayut", "propertyfinder", "ejari"}

# City-wide signals (no area dimension) — contribute to all area composites
CITY_WIDE_SOURCES = {
    "dxb", "gdrfa", "dewa", "khda", "rta", "remittances", "mohre", "salary",
    "jobs", "trends", "permits", "adrec", "dld",
}


def get_zone(score: float) -> str:
    """Map score to named zone."""
    if score <= -0.3:
        return "strong_sell"
    elif score >= 0.3:
        return "strong_buy"
    else:
        return "neutral"


def zscore_normalize(values: list[float]) -> list[float]:
    """
    Z-score normalize a list of floats.

    Returns list of z-scores: (x - mean) / std.
    Returns all-zeros if std is near zero (constant series).
    """
    arr = np.array(values, dtype=float)
    mean = arr.mean()
    std = arr.std()
    if std < 1e-10:
        return [0.0] * len(values)
    return ((arr - mean) / std).tolist()


def fetch_area_names(db: sqlite3.Connection) -> list[str]:
    """
    Fetch 20 canonical area names for Dubai from area_names table.

    Parameterized SQL — SEC-06.
    """
    rows = db.execute(
        "SELECT DISTINCT canonical_name FROM area_names WHERE emirate = ? ORDER BY canonical_name",
        ("dubai",),
    ).fetchall()
    return [row[0] for row in rows]


def fetch_signal_zscore(
    db: sqlite3.Connection,
    source: str,
    metric_name: str,
    area_name: Optional[str] = None,
    months: int = 12,
) -> Optional[float]:
    """
    Fetch the z-score of the most recent value for a (source, metric_name) pair.

    If area_name provided, filter to that area (for area-level signals).
    Uses the last `months` observations for z-score normalization.
    Returns None if fewer than 2 observations (can't compute z-score).

    Parameterized SQL — SEC-06.
    """
    if area_name is not None:
        rows = db.execute(
            "SELECT value FROM normalized_monthly "
            "WHERE source = ? AND metric_name = ? AND area_name = ? "
            "AND value IS NOT NULL "
            "ORDER BY measurement_date DESC LIMIT ?",
            (source, metric_name, area_name, months),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT value FROM normalized_monthly "
            "WHERE source = ? AND metric_name = ? "
            "AND value IS NOT NULL "
            "ORDER BY measurement_date DESC LIMIT ?",
            (source, metric_name, months),
        ).fetchall()

    values = [row[0] for row in rows]

    if len(values) < 2:
        return None

    # Values are DESC — reverse to get chronological order for z-score
    values.reverse()
    z_scores = zscore_normalize(values)
    # Return z-score of the most recent value (last in chronological order)
    return z_scores[-1]


def fetch_significant_signals(
    db: sqlite3.Connection,
) -> list[dict]:
    """
    Fetch significant Granger results from the most recent test run.

    Takes the most recent run by grouping on (signal_source, signal_metric, target)
    and taking latest tested_at.

    Returns list of {signal_source, signal_metric, target, weight, best_lag}.
    Parameterized SQL — SEC-06.
    """
    rows = db.execute(
        "SELECT g.signal_source, g.signal_metric, g.target, g.weight, g.best_lag "
        "FROM granger_results g "
        "INNER JOIN ("
        "  SELECT signal_source, signal_metric, target, MAX(tested_at) AS max_at "
        "  FROM granger_results "
        "  WHERE significant = 1 "
        "  GROUP BY signal_source, signal_metric, target"
        ") latest ON g.signal_source = latest.signal_source "
        "  AND g.signal_metric = latest.signal_metric "
        "  AND g.target = latest.target "
        "  AND g.tested_at = latest.max_at "
        "WHERE g.significant = 1 "
        "ORDER BY g.weight DESC",
    ).fetchall()

    return [
        {
            "signal_source": row[0],
            "signal_metric": row[1],
            "target": row[2],
            "weight": row[3],
            "best_lag": row[4],
        }
        for row in rows
    ]


def compute_composite(
    signal_zscores: list[tuple[str, str, float, float]],
) -> tuple[float, int, int]:
    """
    Compute weighted composite score from (source, metric, weight, zscore) tuples.

    Returns (raw_weighted_avg, component_count, total_applicable).
    component_count = number of signals with data.
    total_applicable = total signals in the input list.
    """
    total_applicable = len(signal_zscores)
    weighted_sum = 0.0
    weight_sum = 0.0
    component_count = 0

    for source, metric, weight, zscore in signal_zscores:
        weighted_sum += weight * zscore
        weight_sum += weight
        component_count += 1

    if weight_sum < 1e-10 or component_count == 0:
        return 0.0, component_count, total_applicable

    raw = weighted_sum / weight_sum
    # Scale to [-1, +1] via tanh(raw/2) — smooth saturation
    scaled = math.tanh(raw / 2.0)
    return scaled, component_count, total_applicable


def main() -> None:
    """Entry point: read stdin, compute composite index, write stdout."""
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
    city_wide_score = 0.0
    city_wide_zone = "neutral"
    error_msg: Optional[str] = None

    try:
        # --- Step 1: Fetch significant Granger signals ---
        signals = fetch_significant_signals(db)
        print(f"Composite: {len(signals)} significant signals", file=sys.stderr)

        if len(signals) == 0:
            print("WARNING: No significant Granger signals found — writing zero composite", file=sys.stderr)

        # --- Step 2: Fetch 20 Dubai areas ---
        area_names = fetch_area_names(db)
        print(f"Composite: {len(area_names)} areas from area_names table", file=sys.stderr)

        # If no areas in DB yet, use an empty list and only compute city-wide
        if not area_names:
            print("WARNING: No area_names found — skipping per-area composite", file=sys.stderr)

        # --- Step 3: Classify signals by scope ---
        # city_wide_signals: applicable to ALL composites (city-wide sources)
        # area_signals: applicable only to specific area composites (area-level sources)
        city_wide_signal_list = [s for s in signals if s["signal_source"] in CITY_WIDE_SOURCES]
        area_signal_list = [s for s in signals if s["signal_source"] in AREA_LEVEL_SOURCES]

        # --- Step 4: Compute city-wide composite ---
        # Uses only city-wide signals
        city_components: list[tuple[str, str, float, float]] = []

        for sig in city_wide_signal_list:
            source = sig["signal_source"]
            metric = sig["signal_metric"]
            weight = sig["weight"]

            z = fetch_signal_zscore(db, source, metric, area_name=None)
            if z is not None:
                city_components.append((source, metric, weight, z))
            else:
                print(f"  SKIP {source}/{metric}: no data for city-wide", file=sys.stderr)

        city_score, city_count, city_total = compute_composite(city_components)
        city_zone = get_zone(city_score)
        city_wide_score = city_score
        city_wide_zone = city_zone

        # Build components JSON for city-wide
        city_components_json = json.dumps([
            {"source": s, "metric": m, "weight": w, "zscore": round(z, 4)}
            for s, m, w, z in city_components
        ])

        # Write city-wide composite — parameterized SQL (SEC-06)
        db.execute(
            "INSERT OR REPLACE INTO composite_scores "
            "(area, score, zone, component_count, total_components, components_json, computed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
            (
                "dubai",
                round(city_score, 6),
                city_zone,
                city_count,
                city_total + len(area_signal_list),  # total = city-wide + area signals
                city_components_json,
            ),
        )

        print(
            f"  City-wide: score={city_score:.4f} zone={city_zone} "
            f"coverage={city_count}/{city_total + len(area_signal_list)}",
            file=sys.stderr,
        )

        # --- Step 5: Compute per-area composites ---
        for area in area_names:
            # Area composite = city-wide signals + area-specific signals (where area data exists)
            area_components: list[tuple[str, str, float, float]] = []

            # Add city-wide signals (same z-scores as city-wide composite)
            for source, metric, weight, z in city_components:
                area_components.append((source, metric, weight, z))

            # Add area-specific signals
            total_area_signals = len(area_signal_list)
            for sig in area_signal_list:
                source = sig["signal_source"]
                metric = sig["signal_metric"]
                weight = sig["weight"]

                z = fetch_signal_zscore(db, source, metric, area_name=area)
                if z is not None:
                    area_components.append((source, metric, weight, z))
                else:
                    print(
                        f"  SKIP {source}/{metric} for area={area}: no area data",
                        file=sys.stderr,
                    )

            area_score, area_count, area_total = compute_composite(area_components)
            area_zone = get_zone(area_score)

            # Build components JSON
            area_components_json = json.dumps([
                {"source": s, "metric": m, "weight": w, "zscore": round(z, 4)}
                for s, m, w, z in area_components
            ])

            # Write per-area composite — parameterized SQL (SEC-06)
            db.execute(
                "INSERT OR REPLACE INTO composite_scores "
                "(area, score, zone, component_count, total_components, components_json, computed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                (
                    area,
                    round(area_score, 6),
                    area_zone,
                    area_count,
                    area_total,
                    area_components_json,
                ),
            )

            areas_computed += 1
            print(
                f"  Area {area}: score={area_score:.4f} zone={area_zone} "
                f"coverage={area_count}/{area_total}",
                file=sys.stderr,
            )

        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Write analysis_log entry — metadata only, no raw scores (SEC-07)
        db.execute(
            "INSERT INTO analysis_log "
            "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, run_at) "
            "VALUES ('composite', ?, ?, ?, ?, datetime('now'))",
            (
                "success",
                areas_computed + 1,  # +1 for city-wide
                len(signals) - len(city_components) - (areas_computed * len(area_signal_list)),
                duration_ms,
            ),
        )
        db.commit()

        print(
            f"Composite: {areas_computed} areas + city-wide in {duration_ms}ms",
            file=sys.stderr,
        )

    except Exception as e:
        error_msg = str(e)
        print(f"ERROR during composite computation: {error_msg}", file=sys.stderr)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Log failure — sanitized error only (SEC-07)
        try:
            db.execute(
                "INSERT INTO analysis_log "
                "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) "
                "VALUES ('composite', 'failed', ?, ?, ?, ?, datetime('now'))",
                (areas_computed, 0, duration_ms, error_msg),
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
        "city_wide_score": city_wide_score,
        "city_wide_zone": city_wide_zone,
    }
    json.dump(output, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
