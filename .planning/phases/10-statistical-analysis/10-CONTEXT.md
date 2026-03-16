# Phase 10: Statistical Analysis Pipeline - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Build the statistical analysis pipeline that transforms normalized monthly data into validated leading indicators and derived models. Stationarity testing, Granger causality, cross-correlation lag detection, composite index construction, EWMA anomaly detection, affordability model, and expat lifecycle pipeline. All analysis runs as a monthly batch (25th) via systemd timer (SCHED-06). Security: parameterized SQL (SEC-06), no raw PII in logs (SEC-07).

Requirements: STAT-01, STAT-02, STAT-03, STAT-04, STAT-05, STAT-06, STAT-07, STAT-08, SCHED-06, SEC-06, SEC-07

</domain>

<decisions>
## Implementation Decisions

### Granger Test Scope
- Test all Tier A+B signals (~20) against DLD price AND DLD volume (two targets, ~40 tests total)
- Tier C excluded from Granger (too noisy) — used in composite only if independently validated
- Bonferroni correction: p < 0.05/N where N = number of tests
- Non-stationary series: auto-apply first-differencing and retest ADF+KPSS. If still non-stationary after differencing, skip that signal
- Store all Granger results with timestamp in a `granger_results` table — enables tracking how relationships evolve over time
- Minimum 12 months of data history before running Granger (matches stationarity.py's existing 12-obs minimum)

### Composite Index Design
- Weighting: Granger-derived weights proportional to 1/p-value (stronger causality = higher weight). Non-significant signals get weight 0
- Granularity: per-area (20 areas) AND city-wide Dubai composite. Area-specific signals (listings, rent) contribute to area index; city-wide signals (visa, GDP) contribute to both
- Missing components: compute with available signals, report coverage (e.g., "7/9 components"). Don't block on missing data
- Scale: [-1, +1] with named zones: [-1, -0.3] = Strong Sell, [-0.3, 0.3] = Neutral, [0.3, 1] = Strong Buy

### Expat Funnel Stages
- 10-stage lifecycle funnel with this mapping:
  1. **Awareness**: Google Trends expat keyword group
  2. **Job Search**: LinkedIn/Bayt/Indeed posting volumes
  3. **Visa**: GDRFA visa issuances
  4. **Arrival**: DXB airport passenger arrivals
  5. **Housing Search**: Bayut/PropertyFinder listing view volumes
  6. **Lease Signed**: Ejari new rental contracts
  7. **Settlement**: DEWA new connections + KHDA school enrollment
  8. **Established**: RTA vehicle registrations + CBUAE remittance outflows
  9. **Dissatisfaction**: Reddit sentiment (bearish ratio) + listing volume surge
  10. **Exit**: GDRFA visa cancellations + DEWA disconnections
- Stage scoring: average z-scores of all signals within each stage
- Show both absolute stage levels AND implied flow rates (stage-to-stage conversion ratios)
- Output format: Telegram-friendly text funnel with arrows and ▲▼ trend indicators vs last month

### Pipeline Execution Model
- Full recompute on the 25th of each month (06:00 GST / 02:00 UTC) via SCHED-06 timer
- Pipeline sequence: stationarity → Granger → correlations → composite index → anomalies → affordability → expat funnel
- Run with whatever data is available — report which signals were excluded due to insufficient data. Results improve as more sources come online
- Cache results in intelligence_cache with TTL = time until next 25th. Telegram queries always hit cache, never recompute on the fly
- Monthly digest: after pipeline completes, auto-generate summary message (top movers, new Granger signals, anomalies detected, funnel changes) and push to Telegram

### Claude's Discretion
- EWMA anomaly detection parameters (window size, std dev threshold — STAT-06)
- Affordability model income bracket boundaries (STAT-07)
- Database schema for granger_results, composite_scores, anomaly_flags tables
- Pipeline Python module structure (single orchestrator vs per-analysis modules)
- Telegram digest message formatting and length
- SQL injection prevention approach (parameterized queries implementation)
- PII protection specifics (what metadata vs raw data distinction means per source)

</decisions>

<specifics>
## Specific Ideas

- The expat lifecycle funnel is the unique differentiator — no competitor maps all 28 sources to a lifecycle model. This should be treated as the marquee product.
- Granger results table enables a "relationship evolution" view in future phases — e.g., "MOHRE permits used to lead DLD price by 3 months, now lead by 6 months"
- Named zones on the composite index (Strong Sell/Neutral/Strong Buy) make Telegram responses immediately actionable without requiring statistical literacy
- Monthly digest push to Telegram creates a "magazine" feel — user gets intelligence delivered, not just available on-demand

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `stationarity.py` (91 lines): ADF + KPSS dual test with verdict logic. Already handles the 12-obs minimum and inconclusive case. Needs extension for auto-differencing
- `granger.py` (122 lines): Granger causality with Bonferroni, stationarity hard gate. Core logic exists but needs batch mode (test all signals, not just one pair)
- `correlation.py` (108 lines): Pearson cross-correlation lag detection. Ready to use as-is for STAT-04
- `runPython()` bridge: stdin/stdout JSON I/O established in Phase 6, used by all normalizers and collectors
- `intelligence_cache` table: TTL-based caching with params hash key already in DB schema
- `PythonScriptName` union type: already includes "stationarity", "granger", "correlation" — extend for new modules

### Established Patterns
- Python modules follow bridge pattern: read JSON stdin → compute → write JSON stdout
- All Python modules importable from `uae_re` package
- Pandera schema validation on all data entering the DB
- Normalizers write to `normalized_monthly` table — analysis reads from this
- `collection_log` tracks all collection runs — analysis should have analogous `analysis_log`

### Integration Points
- `normalized_monthly` table: input data source for all analysis
- `intelligence_cache` table: output storage for computed products
- SCHED-06: new systemd timer (25th 02:00 UTC) — follows pattern of existing 4 timers
- `collect.sh` or new `analyze.sh`: orchestrator script following collect.sh pattern
- Plugin tools (Phase 12): will read from intelligence_cache — schema must be stable

</code_context>

<deferred>
## Deferred Ideas

- ARIMA/LSTM price forecasting (ENH-01 in v1.4)
- Monte Carlo simulation for correlation validation (ENH-02 in v1.4)
- Walk-forward cross-validation (ENH-03 in v1.4)
- Custom Granger weight optimization via grid search (ENH-04 in v1.4)
- Interactive web dashboard for analysis results (VIZ-01 in v1.4)
- Distress threshold auto-alerts via Telegram (AUTO-02 in v1.4)

</deferred>

---

*Phase: 10-statistical-analysis*
*Context gathered: 2026-03-16*
