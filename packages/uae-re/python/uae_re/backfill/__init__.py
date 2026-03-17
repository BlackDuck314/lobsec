"""
Historical backfill package for UAE RE intelligence system.

Provides standalone scripts that extract multi-year historical data from
existing raw files (PDFs, JSON, HTML) and insert directly into normalized_monthly.

These are one-time scripts, not part of the ongoing collection pipeline.
Each script is idempotent: re-running produces the same database state.
"""

import sqlite3

DB_PATH = "/opt/lobsec/data/uae-re.db"


def insert_metric(
    db: sqlite3.Connection,
    source: str,
    date: str,
    metric: str,
    value: float,
    available_date: str,
) -> None:
    """
    Idempotent upsert: DELETE existing + INSERT new for source+date+metric.

    Args:
        db: SQLite connection (caller must commit).
        source: Source name (must match existing DB patterns exactly).
        date: Measurement date in YYYY-MM-DD format.
        metric: Metric name (e.g., 'dubai|dsc_total_population').
        value: Numeric value.
        available_date: ISO timestamp of when data became available.
    """
    db.execute(
        "DELETE FROM normalized_monthly WHERE source=? AND measurement_date=? AND metric_name=?",
        (source, date, metric),
    )
    db.execute(
        "INSERT INTO normalized_monthly (source, measurement_date, metric_name, value, available_date) VALUES (?,?,?,?,?)",
        (source, date, metric, value, available_date),
    )
