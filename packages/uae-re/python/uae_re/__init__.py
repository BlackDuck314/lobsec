"""
UAE Real Estate Analytics Python Package

Provides data science operations for time-series analysis:
- Monthly normalization and resampling
- Stationarity testing (ADF + KPSS)
- Granger causality testing
- Cross-correlation lag detection
- Batch stationarity analysis (analyze_stationarity)
- Batch Granger causality analysis (analyze_granger)
- Composite index computation (analyze_composite)
- EWMA anomaly detection (analyze_anomalies)
- Affordability model (analyze_affordability)
- Expat lifecycle funnel (analyze_expat_funnel)

All modules follow the bridge pattern:
- Read JSON from stdin
- Write results to stdout
- Log/debug to stderr
"""

__version__ = "0.1.0"
