"""
Granger causality testing module.

Bridge pattern:
- Read JSON from stdin: {x: [values...], y: [values...], maxlag: int}
- Check stationarity (hard gate)
- Run Granger causality test
- Write test results to stdout
"""

import sys
import json
import numpy as np
from statsmodels.tsa.stattools import grangercausalitytests
from .stationarity import test_stationarity


def granger_causality(x: list[float], y: list[float], maxlag: int) -> dict:
    """
    Test Granger causality from X to Y.

    Hypothesis: Does X Granger-cause Y?
    - Requires both series to be stationary
    - Tests lags 1 through maxlag
    - Returns F-statistics and p-values for each lag

    Args:
        x: Potential cause series
        y: Effect series
        maxlag: Maximum lag to test

    Returns:
        {
            "x_stationary": verdict,
            "y_stationary": verdict,
            "results": [{lag: int, f_statistic: float, pvalue: float}, ...],
            "recommendation": string
        }
    """
    # Check stationarity (hard gate)
    x_stat = test_stationarity(x)
    y_stat = test_stationarity(y)

    if x_stat["verdict"] != "stationary" or y_stat["verdict"] != "stationary":
        return {
            "x_stationary": x_stat["verdict"],
            "y_stationary": y_stat["verdict"],
            "error": "Both series must be stationary for Granger test",
            "recommendation": "Apply differencing or detrending"
        }

    # Prepare data matrix: [y, x]
    # statsmodels expects [dependent, independent]
    data = np.column_stack([y, x])

    # Run Granger test
    try:
        test_result = grangercausalitytests(data, maxlag=maxlag, verbose=False)

        # Extract F-statistics and p-values
        results = []
        for lag in range(1, maxlag + 1):
            ssr_ftest = test_result[lag][0]['ssr_ftest']
            results.append({
                "lag": lag,
                "f_statistic": float(ssr_ftest[0]),
                "pvalue": float(ssr_ftest[1])
            })

        # Find best lag (lowest p-value)
        best = min(results, key=lambda r: r['pvalue'])

        # Recommendation with Bonferroni correction
        alpha_bonferroni = 0.05 / maxlag
        significant = best['pvalue'] < alpha_bonferroni

        recommendation = (
            f"Granger causality {'detected' if significant else 'not detected'} "
            f"at lag {best['lag']} (p={best['pvalue']:.4f}, "
            f"Bonferroni-corrected alpha={alpha_bonferroni:.4f})"
        )

        return {
            "x_stationary": x_stat["verdict"],
            "y_stationary": y_stat["verdict"],
            "results": results,
            "best_lag": best["lag"],
            "recommendation": recommendation
        }

    except Exception as e:
        return {
            "x_stationary": x_stat["verdict"],
            "y_stationary": y_stat["verdict"],
            "error": f"Granger test failed: {str(e)}"
        }


def main():
    """Entry point: read stdin, test, write stdout."""
    try:
        # Read input
        data = json.load(sys.stdin)
        x = data['x']
        y = data['y']
        maxlag = data.get('maxlag', 12)

        # Test Granger causality
        result = granger_causality(x, y, maxlag)

        # Write output
        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        # Log errors to stderr
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
