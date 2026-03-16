"""
Batch Granger causality testing module.

Bridge pattern:
- Read JSON from stdin: {"db_path": "/path/to/uae-re.db"}
- Query Tier A+B stationary signals from stationarity_results
- Test each signal against DLD price and DLD volume
- Apply Bonferroni correction (N = total test pairs)
- Run cross-correlation lag detection for significant signals
- Write results directly to granger_results table (not via stdout)
- Write analysis_log entry (metadata only — SEC-07)
- Output summary JSON to stdout

Output format:
{
  "tested": int,
  "significant": int,
  "skipped": int,
  "results": [
    {"signal": str, "target": str, "significant": bool, "best_lag": int, "pvalue": float}
  ]
}
"""

import sys
import json
import sqlite3
import time
import numpy as np
from statsmodels.tsa.stattools import grangercausalitytests
from scipy.stats import pearsonr
from .stationarity import test_stationarity


# Tier A sources — primary market signals
TIER_A_SOURCES = {"ejari", "permits", "adrec", "bayut", "propertyfinder", "dewa"}

# Tier B sources — leading indicator signals
TIER_B_SOURCES = {"mohre", "dxb", "gdrfa", "khda", "rta", "jobs", "salary", "remittances"}

# DLD target metrics (excluded from signal testing — they ARE the targets)
DLD_PRICE_METRIC = "meter_sale_price"
DLD_VOLUME_METRIC = "trans_count"
DLD_SOURCE = "dld"

# Granger test maxlag
MAXLAG = 12


def compute_cross_correlation_lag(
    x: list[float], y: list[float], maxlag: int = MAXLAG
) -> int | None:
    """
    Find the lag with highest absolute Pearson correlation between x and y.

    Tests correlation between x(t) and y(t+lag) for lag in [1, maxlag].

    Returns the best lag (1-based), or None if insufficient data.
    """
    if len(x) < maxlag + 2 or len(y) < maxlag + 2:
        return None

    x_arr = np.array(x, dtype=float)
    y_arr = np.array(y, dtype=float)

    best_lag = None
    best_abs_corr = -1.0

    for lag in range(1, maxlag + 1):
        x_slice = x_arr[:-lag]
        y_slice = y_arr[lag:]
        min_len = min(len(x_slice), len(y_slice))
        if min_len < 2:
            continue
        try:
            corr, _ = pearsonr(x_slice[:min_len], y_slice[:min_len])
            if abs(corr) > best_abs_corr:
                best_abs_corr = abs(corr)
                best_lag = lag
        except Exception:
            continue

    return best_lag


def fetch_aligned_series(
    db: sqlite3.Connection,
    source_a: str,
    metric_a: str,
    source_b: str,
    metric_b: str,
) -> tuple[list[float], list[float]]:
    """
    Fetch two series aligned by measurement_date using an INNER JOIN.

    Returns (series_a, series_b) — only dates present in both are included.
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


def get_stationarity_verdict(
    db: sqlite3.Connection, source: str, metric_name: str
) -> str | None:
    """
    Look up the latest stationarity verdict for a (source, metric) pair.

    Returns the verdict string, or None if no record exists.
    Parameterized SQL — SEC-06.
    """
    row = db.execute(
        "SELECT verdict, differenced FROM stationarity_results "
        "WHERE source = ? AND metric_name = ? "
        "ORDER BY tested_at DESC LIMIT 1",
        (source, metric_name),
    ).fetchone()
    if row is None:
        return None
    return row[0]  # verdict


def run_granger_test(
    signal_series: list[float],
    target_series: list[float],
) -> dict | None:
    """
    Run Granger causality from signal → target.

    Prepares data matrix [target, signal] and calls grangercausalitytests.
    Returns dict with best_lag, f_statistic, pvalue, or None on error.
    """
    data = np.column_stack([target_series, signal_series])
    try:
        test_result = grangercausalitytests(data, maxlag=MAXLAG, verbose=False)
        best_lag = None
        best_pvalue = 1.0
        best_fstat = 0.0
        for lag in range(1, MAXLAG + 1):
            ssr_ftest = test_result[lag][0]["ssr_ftest"]
            pval = float(ssr_ftest[1])
            fstat = float(ssr_ftest[0])
            if pval < best_pvalue:
                best_pvalue = pval
                best_fstat = fstat
                best_lag = lag
        return {"best_lag": best_lag, "f_statistic": best_fstat, "pvalue": best_pvalue}
    except Exception as e:
        print(f"  Granger test error: {e}", file=sys.stderr)
        return None


def main() -> None:
    """Entry point: read stdin, batch-test Granger causality, write stdout."""
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

    tested = 0
    significant = 0
    skipped = 0
    results: list[dict] = []
    error_msg: str | None = None

    try:
        # --- Step 1: Identify Tier A+B signal pairs from stationarity_results ---
        # Only include signals where stationarity has been tested (hard gate)
        stat_rows = db.execute(
            "SELECT DISTINCT source, metric_name FROM stationarity_results"
        ).fetchall()

        valid_signals: list[tuple[str, str]] = []
        for source, metric_name in stat_rows:
            if source not in TIER_A_SOURCES and source not in TIER_B_SOURCES:
                continue
            # Exclude DLD metrics that are the targets themselves
            if source == DLD_SOURCE:
                continue
            valid_signals.append((source, metric_name))

        # --- Step 2: Fetch target series (DLD price and DLD volume) ---
        targets = [
            ("dld_price", DLD_SOURCE, DLD_PRICE_METRIC),
            ("dld_volume", DLD_SOURCE, DLD_VOLUME_METRIC),
        ]

        # Filter targets to only those with data
        available_targets = []
        for target_name, target_source, target_metric in targets:
            target_check = db.execute(
                "SELECT COUNT(*) FROM normalized_monthly WHERE source = ? AND metric_name = ? AND value IS NOT NULL",
                (target_source, target_metric),
            ).fetchone()
            if target_check and target_check[0] >= 12:
                available_targets.append((target_name, target_source, target_metric))
            else:
                print(
                    f"SKIP target {target_name}: insufficient data",
                    file=sys.stderr,
                )

        # --- Step 3: Build test pairs and compute Bonferroni N ---
        # N = total valid (signal, target) pairs — compute BEFORE the test loop
        test_pairs: list[tuple[str, str, str, str, str]] = []
        for signal_source, signal_metric in valid_signals:
            for target_name, target_source, target_metric in available_targets:
                test_pairs.append(
                    (signal_source, signal_metric, target_name, target_source, target_metric)
                )

        n_total = len(test_pairs)
        bonferroni_alpha = 0.05 / n_total if n_total > 0 else 0.05

        print(
            f"Granger: {len(valid_signals)} signals × {len(available_targets)} targets = "
            f"{n_total} test pairs, Bonferroni alpha = {bonferroni_alpha:.6f}",
            file=sys.stderr,
        )

        # --- Step 4: Run Granger test for each pair ---
        for (
            signal_source,
            signal_metric,
            target_name,
            target_source,
            target_metric,
        ) in test_pairs:
            pair_label = f"{signal_source}/{signal_metric} → {target_name}"

            # Fetch aligned series
            sig_series, tgt_series = fetch_aligned_series(
                db, signal_source, signal_metric, target_source, target_metric
            )

            if len(sig_series) < 12:
                print(f"SKIP {pair_label}: insufficient aligned data ({len(sig_series)} obs)", file=sys.stderr)
                skipped += 1
                continue

            # Get stationarity verdict from stationarity_results table
            verdict = get_stationarity_verdict(db, signal_source, signal_metric)

            if verdict is None:
                print(f"SKIP {pair_label}: no stationarity record", file=sys.stderr)
                skipped += 1
                continue

            # Apply first-differencing if non-stationary (hard gate)
            if verdict in ("non-stationary", "inconclusive"):
                if len(sig_series) >= 13 and len(tgt_series) >= 13:
                    sig_series = [sig_series[i] - sig_series[i - 1] for i in range(1, len(sig_series))]
                    tgt_series = [tgt_series[i] - tgt_series[i - 1] for i in range(1, len(tgt_series))]
                    # Recheck stationarity after differencing
                    diff_check = test_stationarity(sig_series)
                    if diff_check.get("verdict") in ("non-stationary", "inconclusive"):
                        print(
                            f"SKIP {pair_label}: still non-stationary after differencing",
                            file=sys.stderr,
                        )
                        skipped += 1
                        continue
                else:
                    print(
                        f"SKIP {pair_label}: non-stationary and insufficient data for differencing",
                        file=sys.stderr,
                    )
                    skipped += 1
                    continue

            if len(sig_series) < 12:
                print(f"SKIP {pair_label}: insufficient data after differencing", file=sys.stderr)
                skipped += 1
                continue

            # Run Granger test
            granger = run_granger_test(sig_series, tgt_series)
            if granger is None:
                skipped += 1
                continue

            best_lag = granger["best_lag"]
            best_pvalue = granger["pvalue"]
            best_fstat = granger["f_statistic"]
            is_significant = best_pvalue < bonferroni_alpha
            weight = 1.0 / best_pvalue if is_significant and best_pvalue > 0 else 0.0

            # Cross-correlation lag detection for all tested signals (STAT-04)
            cc_lag = compute_cross_correlation_lag(sig_series, tgt_series, maxlag=MAXLAG)
            if cc_lag is not None:
                best_lag = cc_lag  # Use cross-correlation lag as the stored best_lag

            if is_significant:
                significant += 1
                print(
                    f"SIGNIFICANT {pair_label}: lag={best_lag} p={best_pvalue:.6f} "
                    f"(alpha={bonferroni_alpha:.6f})",
                    file=sys.stderr,
                )
            else:
                print(
                    f"NOT SIG {pair_label}: lag={best_lag} p={best_pvalue:.6f}",
                    file=sys.stderr,
                )

            # Write to granger_results — parameterized SQL (SEC-06)
            db.execute(
                "INSERT OR REPLACE INTO granger_results "
                "(signal_source, signal_metric, target, best_lag, f_statistic, pvalue, "
                "bonferroni_alpha, significant, weight, tested_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                (
                    signal_source,
                    signal_metric,
                    target_name,
                    best_lag,
                    best_fstat,
                    best_pvalue,
                    bonferroni_alpha,
                    1 if is_significant else 0,
                    weight,
                ),
            )

            tested += 1
            results.append(
                {
                    "signal": f"{signal_source}/{signal_metric}",
                    "target": target_name,
                    "significant": is_significant,
                    "best_lag": best_lag,
                    "pvalue": best_pvalue,
                }
            )

        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Write analysis_log entry — metadata only (SEC-07)
        # Log counts and p-value range, NOT individual data values
        pvalues = [r["pvalue"] for r in results]
        pvalue_range = (
            f"min={min(pvalues):.6f} max={max(pvalues):.6f}" if pvalues else "no results"
        )
        db.execute(
            "INSERT INTO analysis_log "
            "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, run_at) "
            "VALUES ('granger', ?, ?, ?, ?, datetime('now'))",
            ("success", tested, skipped, duration_ms),
        )
        db.commit()

        print(
            f"Granger: {tested} tested, {significant} significant, {skipped} skipped "
            f"in {duration_ms}ms (p-value range: {pvalue_range})",
            file=sys.stderr,
        )

    except Exception as e:
        error_msg = str(e)
        print(f"ERROR during batch Granger: {error_msg}", file=sys.stderr)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        # Log failure — sanitized error only (SEC-07)
        try:
            db.execute(
                "INSERT INTO analysis_log "
                "(pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) "
                "VALUES ('granger', 'failed', ?, ?, ?, ?, datetime('now'))",
                (tested, skipped, duration_ms, error_msg),
            )
            db.commit()
        except Exception:
            pass

    finally:
        db.close()

    if error_msg:
        sys.exit(1)

    output = {
        "tested": tested,
        "significant": significant,
        "skipped": skipped,
        "results": results,
    }
    json.dump(output, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
