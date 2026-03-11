"""
Cross-correlation lag detection module.

Bridge pattern:
- Read JSON from stdin: {x: [values...], y: [values...], maxlag: int}
- Compute Pearson correlation for lags 1-maxlag
- Write optimal lag and correlation to stdout
"""

import sys
import json
import numpy as np
from scipy.stats import pearsonr


def find_optimal_lag(x: list[float], y: list[float], maxlag: int = 12) -> dict:
    """
    Find optimal lag for correlation between X and Y.

    Tests correlation between X(t) and Y(t+lag) for lag in [1, maxlag].

    Args:
        x: Leading series
        y: Lagging series
        maxlag: Maximum lag to test (in months)

    Returns:
        {
            "lags": [{lag: int, correlation: float, pvalue: float}, ...],
            "optimal_lag": int,
            "optimal_correlation": float,
            "optimal_pvalue": float
        }
    """
    if len(x) < maxlag + 2 or len(y) < maxlag + 2:
        return {
            "error": f"Insufficient data (need at least {maxlag + 2} observations)",
            "lags": []
        }

    x_arr = np.array(x)
    y_arr = np.array(y)

    results = []
    for lag in range(1, maxlag + 1):
        # Align series with lag
        if lag < len(x_arr) and lag < len(y_arr):
            x_lagged = x_arr[:-lag] if lag > 0 else x_arr
            y_shifted = y_arr[lag:]

            # Ensure same length
            min_len = min(len(x_lagged), len(y_shifted))
            if min_len < 2:
                continue

            x_lagged = x_lagged[:min_len]
            y_shifted = y_shifted[:min_len]

            # Compute Pearson correlation
            corr, pval = pearsonr(x_lagged, y_shifted)

            results.append({
                "lag": lag,
                "correlation": float(corr),
                "pvalue": float(pval)
            })

    if not results:
        return {
            "error": "No valid lag correlations computed",
            "lags": []
        }

    # Find optimal lag (highest absolute correlation)
    optimal = max(results, key=lambda r: abs(r['correlation']))

    return {
        "lags": results,
        "optimal_lag": optimal["lag"],
        "optimal_correlation": optimal["correlation"],
        "optimal_pvalue": optimal["pvalue"]
    }


def main():
    """Entry point: read stdin, compute, write stdout."""
    try:
        # Read input
        data = json.load(sys.stdin)
        x = data['x']
        y = data['y']
        maxlag = data.get('maxlag', 12)

        # Find optimal lag
        result = find_optimal_lag(x, y, maxlag)

        # Write output
        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        # Log errors to stderr
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
