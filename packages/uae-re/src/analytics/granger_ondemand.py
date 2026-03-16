"""
On-demand Granger causality test for a single signal->target pair.

Input (JSON via stdin):
  {
    "signal": "bayut-listings|avg_asking_price",
    "target": "dld-sales|avg_price_per_sqft",
    "db_path": "/opt/lobsec/data/uae-re.db",
    "max_lag": 6
  }

Output (JSON via stdout):
  {
    "output": "formatted text",
    "significant": true/false,
    "best_lag": N,
    "p_value": float
  }
  OR on error:
  { "error": "message" }
"""

import json
import sys
import sqlite3
import numpy as np
import pandas as pd
from statsmodels.tsa.stattools import adfuller, grangercausalitytests


def run(params: dict) -> dict:
    signal_spec = params["signal"]
    target_spec = params["target"]
    db_path = params["db_path"]
    max_lag = int(params.get("max_lag", 6))

    # Parse source|metric
    if "|" not in signal_spec:
        return {"error": f"signal must be 'source|metric', got: {signal_spec}"}
    if "|" not in target_spec:
        return {"error": f"target must be 'source|metric', got: {target_spec}"}

    sig_source, sig_metric = signal_spec.split("|", 1)
    tgt_source, tgt_metric = target_spec.split("|", 1)

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        sig_df = pd.read_sql_query(
            "SELECT measurement_date, value FROM normalized_monthly WHERE source = ? AND metric = ? ORDER BY measurement_date",
            conn,
            params=(sig_source, sig_metric),
        )
        tgt_df = pd.read_sql_query(
            "SELECT measurement_date, value FROM normalized_monthly WHERE source = ? AND metric = ? ORDER BY measurement_date",
            conn,
            params=(tgt_source, tgt_metric),
        )
    finally:
        conn.close()

    if sig_df.empty:
        return {"error": f"No data for signal: {signal_spec}"}
    if tgt_df.empty:
        return {"error": f"No data for target: {target_spec}"}

    # Align on date
    merged = pd.merge(sig_df, tgt_df, on="measurement_date", suffixes=("_sig", "_tgt"))
    merged = merged.dropna()
    n = len(merged)

    if n < 24:
        return {"error": f"Insufficient observations after alignment: {n} (need >= 24)"}

    sig_vals = merged["value_sig"].values.astype(float)
    tgt_vals = merged["value_tgt"].values.astype(float)

    # ADF stationarity check — difference if non-stationary
    def is_stationary(series: np.ndarray) -> bool:
        result = adfuller(series, autolag="AIC")
        return bool(result[1] < 0.05)

    if not is_stationary(sig_vals):
        sig_vals = np.diff(sig_vals)
        tgt_vals = tgt_vals[1:]

    if not is_stationary(sig_vals):
        # Second difference
        sig_vals = np.diff(sig_vals)
        tgt_vals = tgt_vals[1:]

    if not is_stationary(tgt_vals):
        tgt_vals = np.diff(tgt_vals)
        sig_vals = sig_vals[: len(tgt_vals)]

    if len(sig_vals) < 24:
        return {"error": f"Insufficient observations after differencing: {len(sig_vals)} (need >= 24)"}

    data = np.column_stack([tgt_vals[: len(sig_vals)], sig_vals[: len(tgt_vals)]])

    # Run Granger causality
    gc_results = grangercausalitytests(data, maxlag=max_lag, verbose=False)

    # Extract p-values (ssr_ftest)
    lag_pvals: list[tuple[int, float]] = []
    for lag in range(1, max_lag + 1):
        tests = gc_results[lag][0]
        p = float(tests["ssr_ftest"][1])
        lag_pvals.append((lag, p))

    best_lag, best_p = min(lag_pvals, key=lambda x: x[1])
    significant = best_p < 0.05

    # Format output
    lines = [
        f"Granger Causality Test: {signal_spec} -> {target_spec}",
        f"Observations: {n}",
        f"Best lag: {best_lag} months (p={best_p:.4f})",
        f"Significant: {'yes' if significant else 'no'} (threshold: 0.05)",
        "",
        "All lags:",
    ]
    for lag, p in lag_pvals:
        star = " *" if p < 0.05 else ""
        lines.append(f"  Lag {lag}: p={p:.4f}{star}")

    output_text = "\n".join(lines)

    return {
        "output": output_text,
        "significant": significant,
        "best_lag": best_lag,
        "p_value": best_p,
    }


def main() -> None:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw)
        result = run(params)
    except Exception as exc:
        result = {"error": str(exc)}

    print(json.dumps(result))


if __name__ == "__main__":
    main()
