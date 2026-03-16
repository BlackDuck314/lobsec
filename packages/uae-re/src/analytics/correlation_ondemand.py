"""
On-demand cross-correlation analysis for a single signal<->target pair.

Input (JSON via stdin):
  {
    "signal": "bayut-listings|avg_asking_price",
    "target": "dld-sales|avg_price_per_sqft",
    "db_path": "/opt/lobsec/data/uae-re.db",
    "max_lag": 12
  }

Output (JSON via stdout):
  {
    "output": "formatted text",
    "best_lag": N,
    "correlation": float,
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
from scipy.stats import pearsonr


def run(params: dict) -> dict:
    signal_spec = params["signal"]
    target_spec = params["target"]
    db_path = params["db_path"]
    max_lag = int(params.get("max_lag", 12))

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

    if n < 12:
        return {"error": f"Insufficient observations after alignment: {n} (need >= 12)"}

    sig_vals = merged["value_sig"].values.astype(float)
    tgt_vals = merged["value_tgt"].values.astype(float)

    # Compute cross-correlation for each lag
    lag_results: list[tuple[int, float, float]] = []
    for lag in range(0, max_lag + 1):
        if lag == 0:
            s = sig_vals
            t = tgt_vals
        else:
            # Shift target forward by lag months — signal leads target
            s = sig_vals[:-lag]
            t = tgt_vals[lag:]

        if len(s) < 5:
            break

        r, p = pearsonr(s, t)
        lag_results.append((lag, float(r), float(p)))

    if not lag_results:
        return {"error": "Could not compute any lag correlations (series too short)"}

    best_lag, best_r, best_p = max(lag_results, key=lambda x: abs(x[1]))

    # Format output
    lines = [
        f"Cross-Correlation: {signal_spec} <-> {target_spec}",
        f"Observations: {n}",
        f"Best lag: {best_lag} months (r={best_r:.4f}, p={best_p:.4f})",
        "",
        "All lags:",
    ]
    for lag, r, p in lag_results:
        star = " *" if p < 0.05 else ""
        lines.append(f"  Lag {lag}: r={r:.4f} (p={p:.4f}){star}")

    output_text = "\n".join(lines)

    return {
        "output": output_text,
        "best_lag": best_lag,
        "correlation": best_r,
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
