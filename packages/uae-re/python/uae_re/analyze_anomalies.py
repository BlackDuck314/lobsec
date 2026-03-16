"""
EWMA-based anomaly detection module.

Bridge pattern:
- Read JSON from stdin: {"db_path": "/path/to/uae-re.db"}
- Monitor 3 specific signal types: DEWA closures, visa cancellations, listing volume
- Compute EWMA mean and std with span=12
- Flag anomalies where |z_score| > 2.0
- Write flagged points to anomaly_flags table
- Write analysis_log entry (metadata only — SEC-07)
- Output summary JSON to stdout

Output format:
{
  "flagged_count": int,
  "by_source": {"dewa": int, "gdrfa": int, "bayut": int}
}
"""

import sys
import json
import sqlite3
import time
from typing import Optional

import pandas as pd


# Monitored signals (per STAT-06 plan spec)
MONITORED_SIGNALS: list[tuple[str, str]] = [
    ("dewa", "disconnections"),          # DEWA closures
    ("gdrfa", "visa_cancellations"),     # visa cancellations
    ("bayut", "listing_count"),          # listing volume (Bayut)
    ("propertyfinder", "listing_count"), # listing volume (PropertyFinder — fallback)
]

# EWMA parameters
EWMA_SPAN = 12
ANOMALY_THRESHOLD = 2.0  # std devs

# Minimum observations needed to run EWMA
MIN_OBSERVATIONS = 12


def detect_anomalies(
    db: sqlite3.Connection,
    source: str,
    metric_name: str,
) -> list[dict]:
    """
    Fetch series from normalized_monthly, compute EWMA, flag anomalies.

    Returns list of flagged point dicts.
    Parameterized SQL — SEC-06.
    """
    rows = db.execute(
        "SELECT measurement_date, value FROM normalized_monthly "
        "WHERE source = ? AND metric_name = ? "
        "AND value IS NOT NULL "
        "ORDER BY measurement_date ASC",
        (source, metric_name),
    ).fetchall()

    if len(rows) < MIN_OBSERVATIONS:
        print(
            f"SKIP {source}/{metric_name}: only {len(rows)} observations (need {MIN_OBSERVATIONS})",
            file=sys.stderr,
        )
        return []

    dates = [row[0] for row in rows]
    values = pd.Series([float(row[1]) for row in rows])

    # Compute EWMA mean and std
    ewma_mean = values.ewm(span=EWMA_SPAN, adjust=False).mean()
    ewma_std = values.ewm(span=EWMA_SPAN, adjust=False).std()

    # Avoid division by zero — replace 0 std with NaN
    ewma_std_safe = ewma_std.replace(0.0, float("nan"))

    # Z-score of each point relative to its EWMA baseline
    z_scores = (values - ewma_mean) / ewma_std_safe

    # Flag anomalies where |z_score| > threshold
    flagged = []
    for i, (date, val, z) in enumerate(zip(dates, values, z_scores)):
        if pd.isna(z):
            continue  # Skip NaN z-scores (early observations with zero std)
        if abs(z) > ANOMALY_THRESHOLD:
            flagged.append({
                "measurement_date": str(date),
                "value": float(val),
                "z_score": float(z),
            })
            print(
                f"  ANOMALY {source}/{metric_name} @ {date}: z={z:.2f}",
                file=sys.stderr,
            )

    return flagged


def main() -> None:
    """Entry point: read stdin, detect anomalies, write stdout."""
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

    total_flagged = 0
    by_source: dict[str, int] = {}
    error_msg: Optional[str] = None

    try:
        # Process each monitored signal
        for source, metric_name in MONITORED_SIGNALS:
            # Clear previous anomaly_flags for this source before inserting — parameterized SQL (SEC-06)
            db.execute(
                "DELETE FROM anomaly_flags WHERE source = ? AND metric_name = ?",
                (source, metric_name),
            )

            flagged = detect_anomalies(db, source, metric_name)

            if flagged:
                for point in flagged:
                    # Write flagged anomaly — parameterized SQL (SEC-06)
                    db.execute(
                        "INSERT INTO anomaly_flags "
                        "(source, metric_name, measurement_date, value, z_score, flagged_at) "
                        "VALUES (?, ?, ?, ?, ?, datetime('now'))",
                        (
                            source,
                            metric_name,
                            point["measurement_date"],
                            point["value"],
                            point["z_score"],
                        ),
                    )

                # Track by primary source (dewa, gdrfa, bayut — propertyfinder falls under bayut category)
                primary_source = "bayut" if source == "propertyfinder" else source
                by_source[primary_source] = by_source.get(primary_source, 0) + len(flagged)
                total_flagged += len(flagged)

                print(
                    f"  {source}/{metric_name}: {len(flagged)} anomalies flagged",
                    file=sys.stderr,
                )
            else:
                print(
                    f"  {source}/{metric_name}: no anomalies",
                    file=sys.stderr,
                )

        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Write analysis_log entry — flagged_count only, no raw values (SEC-07)
        db.execute(
            "INSERT INTO analysis_log "
            "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, run_at) "
            "VALUES ('anomalies', ?, ?, ?, ?, datetime('now'))",
            (
                "success",
                len(MONITORED_SIGNALS),
                0,
                duration_ms,
            ),
        )
        db.commit()

        print(
            f"Anomalies: {total_flagged} total flags across {len(MONITORED_SIGNALS)} signals "
            f"in {duration_ms}ms",
            file=sys.stderr,
        )

    except Exception as e:
        error_msg = str(e)
        print(f"ERROR during anomaly detection: {error_msg}", file=sys.stderr)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Log failure — sanitized error only (SEC-07)
        try:
            db.execute(
                "INSERT INTO analysis_log "
                "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) "
                "VALUES ('anomalies', 'failed', ?, ?, ?, ?, datetime('now'))",
                (0, 0, duration_ms, error_msg),
            )
            db.commit()
        except Exception:
            pass

    finally:
        db.close()

    if error_msg:
        sys.exit(1)

    # Ensure all 3 primary sources appear in output (with 0 if no anomalies)
    output_by_source = {
        "dewa": by_source.get("dewa", 0),
        "gdrfa": by_source.get("gdrfa", 0),
        "bayut": by_source.get("bayut", 0),
    }

    output = {
        "flagged_count": total_flagged,
        "by_source": output_by_source,
    }
    json.dump(output, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
