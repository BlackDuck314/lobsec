"""
Out-of-sample Granger validation module (QUAL-01).

Bridge pattern:
- Read JSON from stdin: {"db_path": "/path/to/uae-re.db"}
- Fetch significant Granger signals from granger_results (most recent per signal/target)
- For each signal: fetch aligned time-series from normalized_monthly
- Skip signals with < 12 total observations (downweight_factor = 1.0, skipped = True)
- For signals with >= 12 observations: chronological 70/30 split (NO random split)
- Re-run Granger test on training set with the same best_lag
- Apply Bonferroni correction with same N as original test (N = current test pairs)
- validated = 1 if significant on both train and test
- validated = 0 and downweight_factor = 0.5 otherwise
- Write results to validation_results table
- Output summary JSON to stdout

Output format:
{
  "validated": int,
  "skipped": int,
  "downweighted": int
}
"""

import sys
import json
import sqlite3
import time

import numpy as np
from statsmodels.tsa.stattools import grangercausalitytests


def chronological_split(
    series_signal: list[float],
    series_target: list[float],
    train_frac: float = 0.7,
) -> tuple[
    list[float], list[float],  # train_signal, train_target
    list[float], list[float],  # test_signal, test_target
]:
    """
    Split two aligned series chronologically — first train_frac into train, rest into test.

    CRITICAL: Chronological split only — series[:train_n] and series[train_n:].
    NO random splitting. Both series split identically (same indices).

    Args:
        series_signal: Signal time series (aligned with series_target)
        series_target: Target time series (aligned with series_signal)
        train_frac: Fraction of data for training (default 0.7 = 70%)

    Returns:
        (train_signal, train_target, test_signal, test_target)
    """
    n = len(series_signal)
    train_n = int(n * train_frac)

    train_signal = series_signal[:train_n]
    train_target = series_target[:train_n]
    test_signal = series_signal[train_n:]
    test_target = series_target[train_n:]

    return train_signal, train_target, test_signal, test_target


def run_granger_subset(
    signal_series: list[float],
    target_series: list[float],
    best_lag: int,
    bonferroni_alpha: float,
) -> bool:
    """
    Run Granger causality test on a subset of data with specified lag.

    Prepares data matrix [target, signal] (both must be split identically).
    Returns True if significant at the Bonferroni-corrected alpha threshold.

    Args:
        signal_series: Signal time series
        target_series: Target time series (same length, same temporal alignment)
        best_lag: Lag to test (from original Granger analysis)
        bonferroni_alpha: Significance threshold after Bonferroni correction

    Returns:
        True if Granger-significant at bonferroni_alpha, False otherwise
    """
    if len(signal_series) < best_lag + 2 or len(target_series) < best_lag + 2:
        return False

    # Stack as 2-column array: [target, signal] — grangercausalitytests convention
    data = np.column_stack([target_series, signal_series])

    try:
        test_result = grangercausalitytests(data, maxlag=best_lag, verbose=False)
        # Check significance at the specified lag only (not best across lags)
        ssr_ftest = test_result[best_lag][0]["ssr_ftest"]
        pvalue = float(ssr_ftest[1])
        return pvalue < bonferroni_alpha
    except Exception as e:
        print(f"  Granger subset test error: {e}", file=sys.stderr)
        return False


def fetch_aligned_series(
    db: sqlite3.Connection,
    source_a: str,
    metric_a: str,
    source_b: str,
    metric_b: str,
) -> tuple[list[float], list[float]]:
    """
    Fetch two series aligned by measurement_date using an INNER JOIN.

    Returns (series_a, series_b) in chronological order.
    Only dates present in both are included.
    Parameterized SQL — SEC-06.
    """
    rows = db.execute(
        "SELECT a.value, b.value "
        "FROM normalized_monthly a "
        "INNER JOIN normalized_monthly b ON a.measurement_date = b.measurement_date "
        "WHERE a.source = ? AND a.metric_name = ? "
        "  AND b.source = ? AND b.metric_name = ? "
        "  AND a.value IS NOT NULL AND b.value IS NOT NULL "
        "ORDER BY a.measurement_date ASC",
        (source_a, metric_a, source_b, metric_b),
    ).fetchall()

    series_a = [row[0] for row in rows]
    series_b = [row[1] for row in rows]
    return series_a, series_b


def main() -> None:
    """Entry point: read stdin, run out-of-sample validation, write stdout."""
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

    validated_count = 0
    skipped_count = 0
    downweighted_count = 0
    error_msg: str | None = None

    # DLD target source/metric mappings
    DLD_SOURCE = "dld"
    TARGET_METRICS = {
        "dld_price": "meter_sale_price",
        "dld_volume": "trans_count",
    }

    try:
        # --- Step 1: Fetch significant Granger signals (most recent per signal/target) ---
        rows = db.execute(
            "SELECT g.signal_source, g.signal_metric, g.target, g.best_lag, g.bonferroni_alpha "
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
            "WHERE g.significant = 1",
        ).fetchall()

        signals = [
            {
                "signal_source": row[0],
                "signal_metric": row[1],
                "target": row[2],
                "best_lag": row[3],
                "bonferroni_alpha": row[4],
            }
            for row in rows
        ]

        print(
            f"Validation: {len(signals)} significant Granger signals to validate",
            file=sys.stderr,
        )

        if not signals:
            print("Validation: no signals to validate — writing empty results", file=sys.stderr)
            duration_ms = int(time.monotonic() * 1000) - start_ms
            output = {"validated": 0, "skipped": 0, "downweighted": 0}
            json.dump(output, sys.stdout)
            sys.stdout.flush()
            db.close()
            return

        # --- Step 2: Validate each signal ---
        for sig in signals:
            signal_source = sig["signal_source"]
            signal_metric = sig["signal_metric"]
            target = sig["target"]
            best_lag = sig["best_lag"]
            bonferroni_alpha = sig["bonferroni_alpha"]

            pair_label = f"{signal_source}/{signal_metric} → {target}"

            # Get the DLD metric for this target
            target_metric = TARGET_METRICS.get(target)
            if target_metric is None:
                print(f"SKIP {pair_label}: unknown target {target!r}", file=sys.stderr)
                skipped_count += 1
                continue

            # Fetch aligned series (chronological order)
            sig_series, tgt_series = fetch_aligned_series(
                db, signal_source, signal_metric, DLD_SOURCE, target_metric
            )

            total_obs = len(sig_series)

            # Skip signals with < 12 total observations
            if total_obs < 12:
                print(
                    f"SKIP {pair_label}: only {total_obs} obs (< 12 required)",
                    file=sys.stderr,
                )
                skipped_count += 1

                # Delete old results and insert skip record
                db.execute(
                    "DELETE FROM validation_results "
                    "WHERE signal_source = ? AND signal_metric = ? AND target = ?",
                    (signal_source, signal_metric, target),
                )
                db.execute(
                    "INSERT INTO validation_results "
                    "(signal_source, signal_metric, target, train_obs, test_obs, "
                    "train_significant, test_significant, validated, downweight_factor, tested_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    (
                        signal_source, signal_metric, target,
                        0, 0,           # train_obs, test_obs (not applicable)
                        0, 0,           # train_significant, test_significant
                        1,              # validated = 1 (skipped = not penalized)
                        1.0,            # downweight_factor = 1.0 (no penalty for skipped)
                    ),
                )
                continue

            # Chronological 70/30 split (NO random splitting, NO sklearn)
            train_sig, train_tgt, test_sig, test_tgt = chronological_split(
                sig_series, sig_series,  # placeholder — we split signal and target together below
                train_frac=0.7,
            )

            # Correct split: split signal and target identically
            train_n = int(total_obs * 0.7)
            train_sig = sig_series[:train_n]
            train_tgt = tgt_series[:train_n]
            test_sig = sig_series[train_n:]
            test_tgt = tgt_series[train_n:]

            train_obs = len(train_sig)
            test_obs = len(test_sig)

            # Need at least best_lag + 2 observations in each split
            if train_obs < (best_lag or 1) + 2 or test_obs < (best_lag or 1) + 2:
                print(
                    f"SKIP {pair_label}: insufficient split size "
                    f"(train={train_obs}, test={test_obs}, lag={best_lag})",
                    file=sys.stderr,
                )
                skipped_count += 1

                db.execute(
                    "DELETE FROM validation_results "
                    "WHERE signal_source = ? AND signal_metric = ? AND target = ?",
                    (signal_source, signal_metric, target),
                )
                db.execute(
                    "INSERT INTO validation_results "
                    "(signal_source, signal_metric, target, train_obs, test_obs, "
                    "train_significant, test_significant, validated, downweight_factor, tested_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    (
                        signal_source, signal_metric, target,
                        train_obs, test_obs,
                        0, 0,
                        1,    # validated = 1 (skipped = not penalized)
                        1.0,  # no penalty
                    ),
                )
                continue

            # Test on training set
            train_significant = run_granger_subset(
                train_sig, train_tgt, best_lag or 1, bonferroni_alpha or 0.05
            )

            # Test on test set
            test_significant = run_granger_subset(
                test_sig, test_tgt, best_lag or 1, bonferroni_alpha or 0.05
            )

            # Determine validation outcome
            # validated = 1 only if significant on both train AND test
            # downweight = 0.5 if not significant on test (overfit or spurious)
            is_validated = train_significant and test_significant
            downweight_factor = 1.0 if is_validated else 0.5

            if is_validated:
                validated_count += 1
                print(
                    f"VALIDATED {pair_label}: train_sig={train_significant} "
                    f"test_sig={test_significant} train_n={train_obs} test_n={test_obs}",
                    file=sys.stderr,
                )
            else:
                downweighted_count += 1
                print(
                    f"DOWNWEIGHTED {pair_label}: train_sig={train_significant} "
                    f"test_sig={test_significant} train_n={train_obs} test_n={test_obs} "
                    f"→ downweight_factor=0.5",
                    file=sys.stderr,
                )

            # Delete old results for this signal and insert new
            db.execute(
                "DELETE FROM validation_results "
                "WHERE signal_source = ? AND signal_metric = ? AND target = ?",
                (signal_source, signal_metric, target),
            )
            db.execute(
                "INSERT INTO validation_results "
                "(signal_source, signal_metric, target, train_obs, test_obs, "
                "train_significant, test_significant, validated, downweight_factor, tested_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                (
                    signal_source, signal_metric, target,
                    train_obs, test_obs,
                    1 if train_significant else 0,
                    1 if test_significant else 0,
                    1 if is_validated else 0,
                    downweight_factor,
                ),
            )

        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        print(
            f"Validation: {validated_count} validated, {skipped_count} skipped, "
            f"{downweighted_count} downweighted in {duration_ms}ms",
            file=sys.stderr,
        )

    except Exception as e:
        error_msg = str(e)
        print(f"ERROR during validation: {error_msg}", file=sys.stderr)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        try:
            db.rollback()
        except Exception:
            pass

    finally:
        db.close()

    if error_msg:
        sys.exit(1)

    output = {
        "validated": validated_count,
        "skipped": skipped_count,
        "downweighted": downweighted_count,
    }
    json.dump(output, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
