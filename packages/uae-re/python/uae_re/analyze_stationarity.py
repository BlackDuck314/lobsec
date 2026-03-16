"""
Batch stationarity testing module.

Bridge pattern:
- Read JSON from stdin: {"db_path": "/path/to/uae-re.db"}
- Query all (source, metric_name) pairs from normalized_monthly
- Run ADF + KPSS stationarity test on each series
- Auto-difference non-stationary series and retest
- Write results directly to stationarity_results table (not via stdout)
- Write analysis_log entry (metadata only — SEC-07)
- Output summary JSON to stdout

Output format:
{
  "processed": int,
  "skipped": int,
  "results": [
    {"source": str, "metric": str, "verdict": str, "differenced": bool}
  ]
}
"""

import sys
import json
import sqlite3
import time
from .stationarity import test_stationarity


def process_series(
    db: sqlite3.Connection,
    source: str,
    metric_name: str,
) -> dict | None:
    """
    Fetch, test, and write stationarity result for a single (source, metric_name) pair.

    Returns a summary dict on success, or None if skipped.
    """
    # Fetch values ordered by date — parameterized SQL (SEC-06)
    rows = db.execute(
        "SELECT value FROM normalized_monthly WHERE source = ? AND metric_name = ? "
        "ORDER BY measurement_date ASC",
        (source, metric_name),
    ).fetchall()

    # Filter out NULLs
    series = [row[0] for row in rows if row[0] is not None]

    # Skip if insufficient observations
    if len(series) < 12:
        print(
            f"SKIP {source}/{metric_name}: insufficient data ({len(series)} obs)",
            file=sys.stderr,
        )
        return None

    # Test stationarity on raw series
    result = test_stationarity(series)
    differenced = False
    final_verdict = result.get("verdict", "inconclusive")
    adf = result.get("adf", {})
    kpss = result.get("kpss", {})

    # Auto-differencing: if non-stationary and enough observations, try first difference
    if final_verdict == "non-stationary" and len(series) >= 13:
        diff_series = [series[i] - series[i - 1] for i in range(1, len(series))]
        diff_result = test_stationarity(diff_series)
        differenced = True
        final_verdict = diff_result.get("verdict", "inconclusive")
        adf = diff_result.get("adf", {})
        kpss = diff_result.get("kpss", {})
        print(
            f"DIFF {source}/{metric_name}: re-tested after differencing → {final_verdict}",
            file=sys.stderr,
        )

    # Write result to stationarity_results — parameterized SQL (SEC-06)
    db.execute(
        "INSERT OR REPLACE INTO stationarity_results "
        "(source, metric_name, adf_statistic, adf_pvalue, kpss_statistic, kpss_pvalue, "
        "verdict, differenced, obs_count, tested_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        (
            source,
            metric_name,
            adf.get("statistic"),
            adf.get("pvalue"),
            kpss.get("statistic"),
            kpss.get("pvalue"),
            final_verdict,
            1 if differenced else 0,
            len(series),
        ),
    )

    return {
        "source": source,
        "metric": metric_name,
        "verdict": final_verdict,
        "differenced": differenced,
    }


def main() -> None:
    """Entry point: read stdin, batch-test stationarity, write stdout."""
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

    processed = 0
    skipped = 0
    results: list[dict] = []
    error_msg: str | None = None

    try:
        # Discover all (source, metric_name) pairs
        pairs = db.execute(
            "SELECT DISTINCT source, metric_name FROM normalized_monthly"
        ).fetchall()

        print(f"Found {len(pairs)} (source, metric) pairs", file=sys.stderr)

        for source, metric_name in pairs:
            summary = process_series(db, source, metric_name)
            if summary is None:
                skipped += 1
            else:
                processed += 1
                results.append(summary)

        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Write analysis_log entry — metadata only (SEC-07)
        db.execute(
            "INSERT INTO analysis_log "
            "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, run_at) "
            "VALUES ('stationarity', ?, ?, ?, ?, datetime('now'))",
            ("success", processed, skipped, duration_ms),
        )
        db.commit()

        print(
            f"Stationarity: {processed} processed, {skipped} skipped in {duration_ms}ms",
            file=sys.stderr,
        )

    except Exception as e:
        error_msg = str(e)
        print(f"ERROR during batch stationarity: {error_msg}", file=sys.stderr)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Log failure — sanitized error message only (SEC-07)
        try:
            db.execute(
                "INSERT INTO analysis_log "
                "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) "
                "VALUES ('stationarity', 'failed', ?, ?, ?, ?, datetime('now'))",
                (processed, skipped, duration_ms, error_msg),
            )
            db.commit()
        except Exception:
            pass

    finally:
        db.close()

    if error_msg:
        sys.exit(1)

    output = {
        "processed": processed,
        "skipped": skipped,
        "results": results,
    }
    json.dump(output, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
