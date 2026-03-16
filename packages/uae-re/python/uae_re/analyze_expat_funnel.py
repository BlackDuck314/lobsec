"""
Expat lifecycle funnel module.

Bridge pattern:
- Read JSON from stdin: {"db_path": "/path/to/uae-re.db"}
- Map 10 funnel stages to their signal sources (LOCKED from CONTEXT.md)
- Compute z-score per signal relative to 12-month history
- Average z-scores per stage to produce stage score
- Compute flow rates (stage-to-stage conversion ratios)
- Compare to previous month for trend indicators
- Generate Telegram-friendly digest text
- Store in intelligence_cache with TTL until next 25th
- Write analysis_log entry (metadata only — SEC-07)
- Output summary JSON to stdout

Output format:
{
  "stages": [...],
  "flow_rates": [...],
  "digest_text": str
}
"""

import sys
import json
import sqlite3
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional


# 10-stage expat lifecycle funnel (LOCKED from CONTEXT.md — non-negotiable)
STAGES = [
    {"name": "Awareness",       "signals": [("trends", "expat_interest")]},
    {"name": "Job Search",      "signals": [("jobs", "total_postings")]},
    {"name": "Visa",            "signals": [("gdrfa", "visa_issuances")]},
    {"name": "Arrival",         "signals": [("dxb", "passenger_arrivals")]},
    {"name": "Housing Search",  "signals": [("bayut", "listing_count"), ("propertyfinder", "listing_count")]},
    {"name": "Lease Signed",    "signals": [("ejari", "new_contracts")]},
    {"name": "Settlement",      "signals": [("dewa", "new_connections"), ("khda", "total_enrollment")]},
    {"name": "Established",     "signals": [("rta", "new_registrations"), ("remittances", "total_personal_remittances")]},
    {"name": "Dissatisfaction", "signals": [("sentiment", "bearish_ratio"), ("bayut", "listing_count")]},
    {"name": "Exit",            "signals": [("gdrfa", "visa_cancellations"), ("dewa", "disconnections")]},
]

# Minimum observations for z-score computation
MIN_OBSERVATIONS = 2

# History window for z-score baseline
HISTORY_MONTHS = 12

# Flow rate denominator floor — avoid division by near-zero
FLOW_RATE_FLOOR = 0.01


def params_hash(params: dict) -> str:
    """Compute deterministic SHA-256 hash of params dict for cache key."""
    serialized = json.dumps(params, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def next_25th_datetime() -> str:
    """
    Compute the ISO timestamp for the next 25th of month at 06:00 GST (02:00 UTC).

    Used as expires_at for intelligence_cache TTL.
    """
    now = datetime.now(timezone.utc)
    year, month = now.year, now.month

    candidate = datetime(year, month, 25, 2, 0, 0, tzinfo=timezone.utc)

    if now >= candidate:
        if month == 12:
            year += 1
            month = 1
        else:
            month += 1
        candidate = datetime(year, month, 25, 2, 0, 0, tzinfo=timezone.utc)

    return candidate.strftime("%Y-%m-%d %H:%M:%S")


def fetch_signal_zscore(
    db: sqlite3.Connection,
    source: str,
    metric_name: str,
    months: int = HISTORY_MONTHS,
) -> Optional[float]:
    """
    Compute z-score of the most recent value for (source, metric_name).

    Fetches last `months` observations, z-scores them.
    Returns z-score of most recent value (latest date).
    Returns None if fewer than MIN_OBSERVATIONS.

    Parameterized SQL — SEC-06.
    """
    rows = db.execute(
        "SELECT value FROM normalized_monthly "
        "WHERE source = ? AND metric_name = ? "
        "AND value IS NOT NULL "
        "ORDER BY measurement_date DESC LIMIT ?",
        (source, metric_name, months),
    ).fetchall()

    values = [float(row[0]) for row in rows]

    if len(values) < MIN_OBSERVATIONS:
        return None

    # Values are DESC — latest is values[0]
    latest = values[0]
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std = variance ** 0.5

    if std < 1e-10:
        return 0.0

    return (latest - mean) / std


def compute_stage_score(
    db: sqlite3.Connection,
    stage: dict,
) -> tuple[float, int, int]:
    """
    Compute the z-score stage score as average of available signal z-scores.

    Returns (score, available_signals, total_signals).
    """
    total_signals = len(stage["signals"])
    z_scores = []

    for source, metric_name in stage["signals"]:
        z = fetch_signal_zscore(db, source, metric_name)
        if z is not None:
            z_scores.append(z)
        else:
            print(
                f"  SKIP signal {source}/{metric_name} for stage '{stage['name']}': no data",
                file=sys.stderr,
            )

    if not z_scores:
        return 0.0, 0, total_signals

    score = sum(z_scores) / len(z_scores)
    return score, len(z_scores), total_signals


def compute_trend(current_score: float, previous_score: Optional[float]) -> str:
    """
    Compare current to previous to determine trend direction.

    Up if delta > 0.05, down if delta < -0.05, flat otherwise.
    """
    if previous_score is None:
        return "flat"
    delta = current_score - previous_score
    if delta > 0.05:
        return "up"
    elif delta < -0.05:
        return "down"
    else:
        return "flat"


def trend_symbol(trend: str) -> str:
    """Return ASCII arrow for trend direction."""
    if trend == "up":
        return "^"
    elif trend == "down":
        return "v"
    else:
        return "-"


def score_to_bar(score: float, width: int = 3) -> str:
    """
    Convert z-score to visual indicator bars.

    Positive = ^ symbols, negative = v symbols.
    Magnitude capped at `width` symbols.
    """
    if score is None:
        return "-"
    magnitude = min(int(abs(score) + 0.5), width)
    if score >= 0:
        return "^" * magnitude if magnitude > 0 else "-"
    else:
        return "v" * magnitude if magnitude > 0 else "-"


def fetch_previous_stage_scores(
    db: sqlite3.Connection,
) -> Optional[dict[str, float]]:
    """
    Query intelligence_cache for the previous expat funnel result.

    Returns dict of {stage_name: score} from the previous run, or None if no history.
    Parameterized SQL — SEC-06.
    """
    row = db.execute(
        "SELECT result_json FROM intelligence_cache "
        "WHERE cache_key = ? "
        "ORDER BY created_at DESC LIMIT 1",
        ("expat_funnel_latest",),
    ).fetchone()

    if row is None:
        return None

    try:
        data = json.loads(row[0])
        stages = data.get("stages", [])
        return {s["name"]: s["score"] for s in stages}
    except Exception:
        return None


def build_digest_text(
    stage_results: list[dict],
    flow_rates: list[dict],
) -> str:
    """
    Build Telegram-friendly text representation of the expat funnel.

    Format:
    EXPAT LIFECYCLE FUNNEL
    1. Awareness     [+0.42] ^^^
    ...
    10. Exit         [-0.15] v

    Flow: Awareness->Job Search: 0.74 | ...
    """
    lines = ["EXPAT LIFECYCLE FUNNEL"]

    for i, stage in enumerate(stage_results, 1):
        name = stage["name"]
        score = stage["score"]
        trend = stage.get("trend", "flat")

        score_str = f"{score:+.2f}"
        bar = score_to_bar(score)
        trend_sym = trend_symbol(trend)

        # Pad name to 15 chars for alignment
        name_padded = name.ljust(15)
        lines.append(f"{i:2}. {name_padded} [{score_str}] {bar} {trend_sym}")

    lines.append("")

    # Flow rates line
    flow_parts = []
    for fr in flow_rates:
        ratio = fr.get("ratio")
        if ratio is not None:
            flow_parts.append(f"{fr['from']}->{fr['to']}: {ratio:.2f}")
        else:
            flow_parts.append(f"{fr['from']}->{fr['to']}: N/A")

    if flow_parts:
        # Split into multiple lines if too long
        lines.append("Flow rates:")
        for part in flow_parts:
            lines.append(f"  {part}")

    return "\n".join(lines)


def main() -> None:
    """Entry point: read stdin, compute expat funnel, write stdout."""
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

    stage_results: list[dict] = []
    flow_rates: list[dict] = []
    digest_text = ""
    error_msg: Optional[str] = None

    try:
        # --- Step 1: Fetch previous stage scores for trend computation ---
        previous_scores = fetch_previous_stage_scores(db)
        if previous_scores is None:
            print("Expat funnel: first run — trends will be 'flat'", file=sys.stderr)
        else:
            print("Expat funnel: previous scores loaded for trend comparison", file=sys.stderr)

        # --- Step 2: Compute stage scores ---
        stage_scores: list[float] = []
        signals_available = 0
        signals_total = 0

        for stage in STAGES:
            score, available, total = compute_stage_score(db, stage)
            trend = compute_trend(score, previous_scores.get(stage["name"]) if previous_scores else None)

            stage_results.append({
                "name": stage["name"],
                "score": round(score, 4),
                "signal_count": available,
                "total_signals": total,
                "trend": trend,
            })

            stage_scores.append(score)
            signals_available += available
            signals_total += total

            print(
                f"  Stage '{stage['name']}': score={score:.4f} signals={available}/{total} trend={trend}",
                file=sys.stderr,
            )

        # --- Step 3: Compute flow rates (stage-to-stage conversion ratios) ---
        for i in range(len(STAGES) - 1):
            from_stage = STAGES[i]["name"]
            to_stage = STAGES[i + 1]["name"]
            from_score = stage_scores[i]
            to_score = stage_scores[i + 1]

            if abs(from_score) < FLOW_RATE_FLOOR:
                # Denominator near zero — ratio undefined
                ratio = None
            else:
                ratio = to_score / from_score

            flow_rates.append({
                "from": from_stage,
                "to": to_stage,
                "ratio": round(ratio, 4) if ratio is not None else None,
            })

        # --- Step 4: Build digest text ---
        digest_text = build_digest_text(stage_results, flow_rates)

        print(f"Expat funnel digest:\n{digest_text}", file=sys.stderr)

        # --- Step 5: Build result JSON ---
        result = {
            "stages": stage_results,
            "flow_rates": flow_rates,
            "digest_text": digest_text,
        }

        result_json = json.dumps(result)
        cache_params = {"product": "expat_funnel", "version": "1"}
        phash = params_hash(cache_params)
        expires_at = next_25th_datetime()

        # Store in intelligence_cache — parameterized SQL (SEC-06)
        db.execute(
            "INSERT OR REPLACE INTO intelligence_cache "
            "(cache_key, product, params_hash, result_json, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, datetime('now'), ?)",
            ("expat_funnel_latest", "expat_funnel", phash, result_json, expires_at),
        )
        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Write analysis_log entry — stage count, signals available count (SEC-07)
        # No raw visa/salary data logged
        db.execute(
            "INSERT INTO analysis_log "
            "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, run_at) "
            "VALUES ('expat_funnel', ?, ?, ?, ?, datetime('now'))",
            (
                "success",
                signals_available,
                signals_total - signals_available,
                duration_ms,
            ),
        )
        db.commit()

        print(
            f"Expat funnel: {len(STAGES)} stages, {signals_available}/{signals_total} signals "
            f"in {duration_ms}ms, expires {expires_at}",
            file=sys.stderr,
        )

    except Exception as e:
        error_msg = str(e)
        print(f"ERROR during expat funnel computation: {error_msg}", file=sys.stderr)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Log failure — sanitized error only (SEC-07)
        try:
            db.execute(
                "INSERT INTO analysis_log "
                "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) "
                "VALUES ('expat_funnel', 'failed', ?, ?, ?, ?, datetime('now'))",
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
        "stages": stage_results,
        "flow_rates": flow_rates,
        "digest_text": digest_text,
    }
    json.dump(output, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
