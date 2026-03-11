"""
Stationarity testing module (ADF + KPSS).

Bridge pattern:
- Read JSON array from stdin: [value1, value2, ...]
- Run ADF (Augmented Dickey-Fuller) test
- Run KPSS (Kwiatkowski-Phillips-Schmidt-Shin) test
- Write test results to stdout
"""

import sys
import json
from statsmodels.tsa.stattools import adfuller, kpss


def test_stationarity(series: list[float]) -> dict:
    """
    Test time-series stationarity with ADF and KPSS.

    Both tests must agree for a definitive verdict:
    - ADF: H0 = non-stationary (reject if p < 0.05)
    - KPSS: H0 = stationary (reject if p < 0.05)

    Args:
        series: Time-series values

    Returns:
        {
            "adf": {"statistic": float, "pvalue": float, "is_stationary": bool},
            "kpss": {"statistic": float, "pvalue": float, "is_stationary": bool},
            "verdict": "stationary" | "non-stationary" | "inconclusive"
        }
    """
    if len(series) < 12:
        return {
            "error": "Insufficient data (need at least 12 observations)",
            "verdict": "inconclusive"
        }

    # ADF test (H0: non-stationary)
    adf_result = adfuller(series, autolag='AIC')
    adf_stationary = adf_result[1] < 0.05  # Reject H0 if p < 0.05

    # KPSS test (H0: stationary)
    kpss_result = kpss(series, regression='c', nlags='auto')
    kpss_stationary = kpss_result[1] >= 0.05  # Fail to reject H0 if p >= 0.05

    # Verdict: both must agree
    if adf_stationary and kpss_stationary:
        verdict = "stationary"
    elif not adf_stationary and not kpss_stationary:
        verdict = "non-stationary"
    else:
        verdict = "inconclusive"

    return {
        "adf": {
            "statistic": float(adf_result[0]),
            "pvalue": float(adf_result[1]),
            "is_stationary": adf_stationary
        },
        "kpss": {
            "statistic": float(kpss_result[0]),
            "pvalue": float(kpss_result[1]),
            "is_stationary": kpss_stationary
        },
        "verdict": verdict
    }


def main():
    """Entry point: read stdin, test, write stdout."""
    try:
        # Read input
        series = json.load(sys.stdin)

        # Test stationarity
        result = test_stationarity(series)

        # Write output
        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        # Log errors to stderr
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
