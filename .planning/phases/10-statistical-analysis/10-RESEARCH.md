# Phase 10: Statistical Analysis Pipeline - Research

**Researched:** 2026-03-16
**Domain:** Time-series statistical analysis (statsmodels, scipy), Python batch pipeline, systemd timer, SQLite schema extension
**Confidence:** HIGH — all findings grounded in existing project code; no library uncertainty

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Granger Test Scope**
- Test all Tier A+B signals (~20) against DLD price AND DLD volume (two targets, ~40 tests total)
- Tier C excluded from Granger (too noisy) — used in composite only if independently validated
- Bonferroni correction: p < 0.05/N where N = number of tests
- Non-stationary series: auto-apply first-differencing and retest ADF+KPSS. If still non-stationary after differencing, skip that signal
- Store all Granger results with timestamp in a `granger_results` table — enables tracking how relationships evolve over time
- Minimum 12 months of data history before running Granger (matches stationarity.py's existing 12-obs minimum)

**Composite Index Design**
- Weighting: Granger-derived weights proportional to 1/p-value (stronger causality = higher weight). Non-significant signals get weight 0
- Granularity: per-area (20 areas) AND city-wide Dubai composite. Area-specific signals (listings, rent) contribute to area index; city-wide signals (visa, GDP) contribute to both
- Missing components: compute with available signals, report coverage (e.g., "7/9 components"). Don't block on missing data
- Scale: [-1, +1] with named zones: [-1, -0.3] = Strong Sell, [-0.3, 0.3] = Neutral, [0.3, 1] = Strong Buy

**Expat Funnel Stages**
- 10-stage lifecycle funnel:
  1. Awareness: Google Trends expat keyword group
  2. Job Search: LinkedIn/Bayt/Indeed posting volumes
  3. Visa: GDRFA visa issuances
  4. Arrival: DXB airport passenger arrivals
  5. Housing Search: Bayut/PropertyFinder listing view volumes
  6. Lease Signed: Ejari new rental contracts
  7. Settlement: DEWA new connections + KHDA school enrollment
  8. Established: RTA vehicle registrations + CBUAE remittance outflows
  9. Dissatisfaction: Reddit sentiment (bearish ratio) + listing volume surge
  10. Exit: GDRFA visa cancellations + DEWA disconnections
- Stage scoring: average z-scores of all signals within each stage
- Show both absolute stage levels AND implied flow rates (stage-to-stage conversion ratios)
- Output format: Telegram-friendly text funnel with arrows and ▲▼ trend indicators vs last month

**Pipeline Execution Model**
- Full recompute on the 25th of each month (06:00 GST / 02:00 UTC) via SCHED-06 timer
- Pipeline sequence: stationarity → Granger → correlations → composite index → anomalies → affordability → expat funnel
- Run with whatever data is available — report which signals were excluded due to insufficient data
- Cache results in intelligence_cache with TTL = time until next 25th
- Monthly digest: after pipeline completes, auto-generate summary message and push to Telegram

### Claude's Discretion
- EWMA anomaly detection parameters (window size, std dev threshold — STAT-06)
- Affordability model income bracket boundaries (STAT-07)
- Database schema for granger_results, composite_scores, anomaly_flags tables
- Pipeline Python module structure (single orchestrator vs per-analysis modules)
- Telegram digest message formatting and length
- SQL injection prevention approach (parameterized queries implementation)
- PII protection specifics (what metadata vs raw data distinction means per source)

### Deferred Ideas (OUT OF SCOPE)
- ARIMA/LSTM price forecasting (ENH-01 in v1.4)
- Monte Carlo simulation for correlation validation (ENH-02 in v1.4)
- Walk-forward cross-validation (ENH-03 in v1.4)
- Custom Granger weight optimization via grid search (ENH-04 in v1.4)
- Interactive web dashboard for analysis results (VIZ-01 in v1.4)
- Distress threshold auto-alerts via Telegram (AUTO-02 in v1.4)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| STAT-01 | ADF test on all normalized series, hard gate before Granger; log to `stationarity_results` table | stationarity.py exists (ADF+KPSS); needs batch mode + DB write + auto-differencing extension |
| STAT-02 | KPSS cross-check alongside ADF; flag disagreements for manual review | KPSS already in stationarity.py; disagreement = "inconclusive" verdict already implemented |
| STAT-03 | Granger causality: all Tier A+B signals vs DLD price/volume, Bonferroni p < 0.05/N | granger.py exists (single pair); needs batch mode, auto-differencing, granger_results table write |
| STAT-04 | Cross-correlation lag detection: optimal lag 1-12 months per validated signal | correlation.py exists and is ready to use; needs batch invocation from orchestrator |
| STAT-05 | Composite index: z-score normalized, Granger-derived weights, scaled [-1, +1] | New Python module; reads granger_results + normalized_monthly; writes composite_scores table |
| STAT-06 | EWMA anomaly detection for DEWA closures, visa cancellations, listing volume | New Python module; EWMA via pandas ewm(); writes anomaly_flags table |
| STAT-07 | Affordability model: salary-to-rent ratio by income bracket and area | New Python module; reads normalize_salary + normalize_ejari outputs; writes affordability table |
| STAT-08 | Expat pipeline flow model: 10-stage funnel, z-score aggregation per stage | New Python module; reads 10 source signals; writes expat_funnel table |
| SCHED-06 | Pipeline timer: 25th 06:00 GST (02:00 UTC) recomputes all analysis | New systemd timer + analyze.sh orchestrator script; follows existing timer pattern |
| SEC-06 | Parameterized queries for all user-supplied area names; validate against area allowlist | Use better-sqlite3 prepared statements; area allowlist already in area_names table |
| SEC-07 | PII protection: log only metadata (row count, status), never raw visa/employment data | Log analysis_log entries with row counts, never log series values for GDRFA/MOHRE/salary |
</phase_requirements>

---

## Summary

Phase 10 is primarily a Python data science build on top of a complete and well-structured TypeScript/Python hybrid system. The collection infrastructure (28 sources, normalized_monthly table, Python subprocess bridge, intelligence_cache) is all fully deployed from Phases 6-9. This phase does not require any new collection, external API integration, or infrastructure work — it is pure analytics.

Three of the required Python modules already exist with core logic: `stationarity.py` (91 lines, ADF+KPSS dual test), `granger.py` (122 lines, single-pair Granger with Bonferroni), and `correlation.py` (108 lines, Pearson cross-correlation lag detection). These all use the established bridge pattern (JSON stdin/stdout) and are registered in `PythonScriptName`. They need extension to batch mode and DB write capability, not replacement.

The new work consists of: (1) extending the three existing modules to batch/orchestrator mode, (2) building four new Python modules (composite, anomaly, affordability, expat funnel), (3) creating five new SQLite tables, (4) building a TypeScript pipeline orchestrator that sequences the Python calls, (5) adding an `analyze.sh` shell script and systemd timer for SCHED-06. Security requirements (SEC-06, SEC-07) are handled via better-sqlite3 prepared statements and log filtering — both are straightforward given existing patterns.

**Primary recommendation:** Build the pipeline as a TypeScript orchestrator (`pipeline.ts`) that calls Python modules sequentially via the existing `runPython()` bridge. Python modules handle all statistical computation and write results to SQLite directly. The orchestrator handles sequencing, error recovery, caching, and Telegram digest dispatch.

---

## Standard Stack

### Core (already installed, verified in venv)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| statsmodels | ≥0.14 | ADF, KPSS, grangercausalitytests | Already used in stationarity.py + granger.py; production-proven |
| scipy | ≥1.12 | pearsonr cross-correlation | Already used in correlation.py |
| numpy | ≥1.26 | Array operations, z-score normalization | Used in granger.py and correlation.py |
| pandas | ≥2.2 | ewm() for EWMA, resample, DataFrame ops | Already used in all normalizers |
| better-sqlite3 | ≥9.x (TS) | Parameterized queries, DB writes | Already used throughout; version in package.json |

### Supporting
| Library | Purpose | When to Use |
|---------|---------|-------------|
| json (stdlib) | stdin/stdout bridge I/O | All Python modules use this pattern |
| sys (stdlib) | Entry point, stderr logging | All Python modules use this pattern |
| sqlite3 (stdlib) | Python-side DB writes from analysis modules | Write stationarity_results, granger_results, composite_scores, etc. |
| scipy.stats.zscore | Z-score normalization for composite index | Alternative to manual pandas implementation |

### No New Installations Needed
All required libraries are already in `/opt/lobsec/analytics-venv/`. The venv was built in Phase 6 (INFRA-02) and extended in subsequent phases. No `pip install` needed for Phase 10.

---

## Architecture Patterns

### Existing Bridge Pattern (HIGH confidence — code verified)

All Python modules follow this exact pattern already established in stationarity.py, granger.py, correlation.py:

```python
# Source: /root/lobsec/packages/uae-re/python/uae_re/stationarity.py
def main():
    """Entry point: read stdin, compute, write stdout."""
    try:
        data = json.load(sys.stdin)
        result = compute_something(data)
        json.dump(result, sys.stdout)
        sys.stdout.flush()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

**Rule:** Every new Python module MUST follow this exact pattern. The TS bridge calls `python3 -m uae_re.{module_name}` and reads stdout as JSON.

### TypeScript Pipeline Orchestrator Pattern

The orchestrator is a new TypeScript module at `packages/uae-re/src/analytics/pipeline.ts`. It sequences Python calls using the existing `runPython()` bridge:

```typescript
// Source: pattern from /root/lobsec/packages/uae-re/src/analytics/bridge.ts
import { runPython } from "./bridge.js";

export async function runAnalysisPipeline(db: Database): Promise<PipelineResult> {
  // Step 1: Stationarity (batch)
  const statResult = await runPython<StationarityBatchResult>(
    "analyze_stationarity",  // new batch module
    { sources: tieredSources },
    { defaultTimeoutMs: 120_000 }  // longer timeout for batch
  );
  // ...sequential steps
}
```

**Key:** The orchestrator does NOT perform statistical computation in TypeScript. All math lives in Python. TypeScript handles: DB reads for input data, sequencing, error recovery, cache writes, Telegram dispatch.

### Python Modules with Direct SQLite Writes

For batch analysis modules, have Python write results directly to SQLite using `sqlite3` stdlib. This avoids sending large result sets through the bridge JSON channel:

```python
import sqlite3
import json
import sys

def main():
    data = json.load(sys.stdin)
    db_path = data['db_path']  # passed from TS orchestrator
    series_batch = data['series']

    conn = sqlite3.connect(db_path)
    try:
        results = []
        for source, values in series_batch.items():
            result = test_stationarity(values)
            # Write directly to DB
            conn.execute(
                "INSERT OR REPLACE INTO stationarity_results "
                "(source, metric_name, adf_statistic, adf_pvalue, kpss_statistic, "
                "kpss_pvalue, verdict, tested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (source, result['metric'], result['adf']['statistic'], ...)
            )
            results.append(result)
        conn.commit()
        json.dump({"processed": len(results), "results": results}, sys.stdout)
        sys.stdout.flush()
    finally:
        conn.close()
```

**Why direct DB writes from Python:** Avoids marshaling large batch results through JSON stdout. Keeps DB write logic close to computation. Pattern used by many normalizers already (they write normalized_monthly rows directly).

### EWMA Anomaly Detection Pattern (Claude's Discretion)

Recommended parameters based on statsmodels/pandas documentation and standard practice:
- **Window (span):** 12 months (matches the 12-obs minimum throughout the codebase)
- **Threshold:** ±2 standard deviations from EWMA mean
- **Signals to flag:** DEWA closures, GDRFA visa cancellations, listing volume (per STAT-06)

```python
import pandas as pd

def detect_anomalies_ewma(series: list[float], span: int = 12, threshold: float = 2.0) -> dict:
    s = pd.Series(series)
    ewma = s.ewm(span=span, adjust=False).mean()
    ewma_std = s.ewm(span=span, adjust=False).std()
    z_scores = (s - ewma) / ewma_std.replace(0, float('nan'))
    anomaly_mask = z_scores.abs() > threshold
    return {
        "anomaly_indices": anomaly_mask[anomaly_mask].index.tolist(),
        "z_scores": z_scores.tolist(),
        "threshold": threshold
    }
```

### Affordability Model Income Brackets (Claude's Discretion)

Recommended brackets aligned with UAE salary survey data (Cooper Fitch, Hays) and DED/KHDA context:

| Bracket | Monthly AED | Profile |
|---------|------------|---------|
| Entry | 5,000–10,000 | Service sector, new arrivals |
| Mid-Low | 10,001–20,000 | Admin, junior professionals |
| Mid | 20,001–35,000 | Mid-level professionals |
| Senior | 35,001–60,000 | Managers, specialists |
| Executive | >60,000 | Directors, C-suite |

Salary-to-rent ratio = median monthly salary for bracket / median monthly rent per area. Affordability threshold: ratio < 3 = unaffordable (>33% of gross income on rent).

### Systemd Timer Pattern (HIGH confidence — 4 existing timers verified)

New timer follows the exact pattern of `lobsec-uae-collector-weekly.timer` and others:

```ini
# /etc/systemd/system/lobsec-uae-analyze.timer
[Unit]
Description=UAE RE Statistical Analysis Pipeline (25th 02:00 UTC)
After=lobsec.service

[Timer]
OnCalendar=*-*-25 02:00:00
Persistent=true
Unit=lobsec-uae-analyze.service

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/lobsec-uae-analyze.service
[Unit]
Description=UAE RE Statistical Analysis Pipeline
After=lobsec.service

[Service]
Type=oneshot
User=lobsec
EnvironmentFile=/opt/lobsec/boot/pin.env
ExecStart=/opt/lobsec/bin/analyze.sh
TimeoutStartSec=3600
StandardOutput=append:/opt/lobsec/logs/analyze.log
StandardError=append:/opt/lobsec/logs/analyze.log
```

### analyze.sh Orchestrator Script (follows collect.sh pattern)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Source environment
source /opt/lobsec/.env

# Run analysis pipeline via Node
exec /opt/lobsec/bin/node-wrapper.sh \
  /opt/lobsec/plugins/lobsec-uae-re/dist/cli.js analyze
```

The `analyze` subcommand added to cli.ts triggers `runAnalysisPipeline()`.

---

## New Database Tables (Claude's Discretion)

Five new tables needed. Extend `initSchema()` in `packages/uae-re/src/db/schema.ts`:

### stationarity_results
```sql
CREATE TABLE IF NOT EXISTS stationarity_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  adf_statistic REAL,
  adf_pvalue REAL,
  kpss_statistic REAL,
  kpss_pvalue REAL,
  verdict TEXT NOT NULL CHECK(verdict IN ('stationary', 'non-stationary', 'inconclusive')),
  differenced INTEGER NOT NULL DEFAULT 0,  -- 1 if first-differenced before testing
  obs_count INTEGER,
  tested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_stationarity_source
  ON stationarity_results(source, metric_name, tested_at);
```

### granger_results
```sql
CREATE TABLE IF NOT EXISTS granger_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  signal_source TEXT NOT NULL,
  signal_metric TEXT NOT NULL,
  target TEXT NOT NULL CHECK(target IN ('dld_price', 'dld_volume')),
  best_lag INTEGER,
  f_statistic REAL,
  pvalue REAL,
  bonferroni_alpha REAL,
  significant INTEGER NOT NULL DEFAULT 0,
  weight REAL,  -- 1/pvalue if significant, 0 otherwise
  tested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_granger_signal_target
  ON granger_results(signal_source, target, tested_at);
```

### composite_scores
```sql
CREATE TABLE IF NOT EXISTS composite_scores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  area TEXT NOT NULL,  -- 'dubai' for city-wide, area name for per-area
  score REAL NOT NULL,
  zone TEXT NOT NULL CHECK(zone IN ('strong_sell', 'neutral', 'strong_buy')),
  component_count INTEGER NOT NULL,
  total_components INTEGER NOT NULL,
  computed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_composite_area_date
  ON composite_scores(area, computed_at);
```

### anomaly_flags
```sql
CREATE TABLE IF NOT EXISTS anomaly_flags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  measurement_date TEXT NOT NULL,
  value REAL,
  z_score REAL,
  flagged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### analysis_log (analogous to collection_log, for SEC-07)
```sql
CREATE TABLE IF NOT EXISTS analysis_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pipeline_step TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('success', 'failed', 'skipped')),
  signals_processed INTEGER,
  signals_skipped INTEGER,
  duration_ms INTEGER,
  error TEXT,
  run_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

Note: No `affordability` or `expat_funnel` tables — these results are stored in `intelligence_cache` with product keys `"affordability"` and `"expat_funnel"`, consistent with how Phase 11 intelligence products will be cached.

---

## New Python Modules Needed

| Module | Extends | What It Does | Inputs | Outputs |
|--------|---------|-------------|--------|---------|
| `analyze_stationarity.py` | stationarity.py | Batch mode: test ALL normalized series, auto-difference non-stationary, write to stationarity_results | `{db_path, sources}` | `{processed, skipped, results_summary}` |
| `analyze_granger.py` | granger.py | Batch mode: test all Tier A+B signals against dld_price + dld_volume, write to granger_results | `{db_path}` | `{tested, significant, skipped}` |
| `analyze_composite.py` | new | Read granger_results, z-score normalize, weight by 1/p, scale [-1,+1], write composite_scores | `{db_path}` | `{areas_computed, city_wide_score}` |
| `analyze_anomalies.py` | new | EWMA on DEWA/GDRFA/listings, write anomaly_flags | `{db_path}` | `{flagged_count, by_source}` |
| `analyze_affordability.py` | new | salary-to-rent by bracket+area, store in intelligence_cache | `{db_path}` | `{areas_computed, brackets}` |
| `analyze_expat_funnel.py` | new | 10-stage z-score aggregation, flow rates, store in intelligence_cache | `{db_path}` | `{stages, flow_rates, digest_text}` |

**PythonScriptName union must be extended** in `packages/uae-re/src/analytics/types.ts` with all 6 new module names.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| ADF stationarity | Custom unit root test | `statsmodels.tsa.stattools.adfuller` | Already in stationarity.py, handles lag selection (AIC) |
| KPSS test | Custom | `statsmodels.tsa.stattools.kpss` | Already in stationarity.py |
| Granger causality | Custom VAR regression | `statsmodels.tsa.stattools.grangercausalitytests` | Already in granger.py, handles matrix setup |
| Cross-correlation | Manual lag loop from scratch | Extend correlation.py | Core loop already written |
| EWMA | Manual exponential weighting | `pandas.Series.ewm()` | Handles edge cases (min_periods, NaN, adjust parameter) |
| Z-score normalization | Manual mean/std | `scipy.stats.zscore` or `(s - s.mean()) / s.std()` | One-liner; don't build a class |
| Bonferroni correction | Custom alpha threshold | Apply `alpha / N` directly | Already in granger.py's pattern |
| Cache TTL computation | Custom date math | Compute seconds to next 25th | Simple datetime arithmetic, but be careful with month boundaries |
| Parameterized SQL | String interpolation | `better-sqlite3` prepared statements | SQL injection prevention is SEC-06 |

**Key insight:** This phase extends code that already exists. The risk is over-engineering (new classes, registries, frameworks) when the existing bridge pattern is sufficient.

---

## Common Pitfalls

### Pitfall 1: Granger Test on Non-Stationary Series
**What goes wrong:** `grangercausalitytests()` silently produces spurious results on non-stationary (unit-root) series. The Granger test assumes stationarity.
**Why it happens:** The test doesn't throw; it just returns meaningless F-statistics.
**How to avoid:** The CONTEXT.md decision locks the fix: auto-apply first-differencing and retest ADF+KPSS. Implement in `analyze_granger.py` before calling the causality test. If still non-stationary after differencing, skip the signal and log to analysis_log.
**Warning signs:** Very high F-statistics, p-values near 0 for every signal — probably testing non-stationary series.

### Pitfall 2: Bonferroni Correction Scope
**What goes wrong:** Current granger.py applies Bonferroni correction as `0.05 / maxlag` (within one pair's lag range). For batch mode, the correction must be `0.05 / N_tests` where N = total number of (signal, target) pairs tested.
**Why it happens:** The existing code was designed for single-pair use.
**How to avoid:** Calculate N_total before the batch loop starts. Pass the computed alpha to each test. With ~40 tests, alpha = 0.05/40 = 0.00125.
**Warning signs:** Every signal appears significant — Bonferroni threshold too loose.

### Pitfall 3: Insufficient Data for Most Tier B Sources
**What goes wrong:** Tier B sources (COLL-06 through COLL-13) are pending collection. The analysis pipeline will have very few actual data rows in normalized_monthly for these sources.
**Why it happens:** Phase 8 built the collection infrastructure but production credentials and data scraping may not have populated months of history yet.
**How to avoid:** The CONTEXT.md locks this: "run with whatever data is available, report which signals were excluded due to insufficient data." The minimum is 12 observations (1 year). Implement graceful skip with logging — don't fail the pipeline.
**Warning signs:** Pipeline fails entirely with no output — check for missing NULL handling in the series fetch query.

### Pitfall 4: KPSS p-value Truncation
**What goes wrong:** `statsmodels.tsa.stattools.kpss()` returns a truncated p-value: it's capped at 0.1 (upper bound) and 0.01 (lower bound) because the function interpolates from a critical values table, not a continuous distribution.
**Why it happens:** KPSS doesn't have an analytic p-value formula; statsmodels uses tabulated critical values.
**How to avoid:** This is already handled correctly in stationarity.py: `kpss_stationary = kpss_result[1] >= 0.05`. The code already accounts for this. Just preserve this comparison in batch mode.
**Warning signs:** Getting exactly 0.1 or 0.01 as KPSS p-values for many series — that's normal, not a bug.

### Pitfall 5: Bridge Timeout for Batch Operations
**What goes wrong:** The default `runPython()` timeout is 30 seconds. A batch stationarity test over 20 signals × 2 metrics each, or a batch Granger test over 40 pairs, will exceed 30 seconds.
**Why it happens:** `DEFAULT_CONFIG.defaultTimeoutMs = 30_000` in bridge.ts.
**How to avoid:** Pass `{ defaultTimeoutMs: 300_000 }` (5 minutes) when calling batch analysis modules. The bridge already supports config override.
**Warning signs:** Batch results silently empty with `success: false, error: "Timeout after 30000ms"`.

### Pitfall 6: SQLite WAL + Python sqlite3 Conflict
**What goes wrong:** The DB is opened in WAL mode by the TypeScript layer (better-sqlite3). If Python's sqlite3 stdlib opens the same DB simultaneously for writes, WAL handles this correctly — but only if the Python module opens with `check_same_thread=False` and commits before the TS layer reads.
**Why it happens:** WAL allows concurrent readers but only one writer at a time.
**How to avoid:** The pipeline orchestrator must complete each Python step and confirm its DB write before calling the next step. Sequential execution (which is the locked design) avoids this entirely.
**Warning signs:** `sqlite3.OperationalError: database is locked` in Python stderr.

### Pitfall 7: area_names Table as Area Allowlist (SEC-06)
**What goes wrong:** If area names from user queries are interpolated directly into SQL, SQL injection is possible.
**Why it happens:** Concatenating strings in SQLite queries.
**How to avoid:** Use better-sqlite3 prepared statements: `db.prepare("SELECT * FROM composite_scores WHERE area = ?").get(area)`. Validate area against `area_names` table before any query. The area_names table already exists from Phase 6 (schema.ts, line 17-25).
**Warning signs:** Using template literal SQL strings with user input — always use `?` placeholders.

### Pitfall 8: Telegram Digest Generates Noise When No Data Available
**What goes wrong:** Monthly digest fires on the 25th even when <3 sources have data. Produces an unhelpful "0 signals validated, 0 components in composite" message.
**Why it happens:** Timer runs unconditionally.
**How to avoid:** Add a minimum coverage check in the pipeline: if fewer than 3 Granger-validated signals exist, skip the Telegram digest and log a warning instead. Don't suppress the pipeline run itself — just the digest.

---

## Code Examples

### Batch Stationarity Query (fetching all series from DB)
```typescript
// Source: extend packages/uae-re/src/db/queries.ts
export function getSeriesForSource(
  db: Database.Database,
  source: string,
  metricName: string
): number[] {
  const rows = db.prepare(
    `SELECT value FROM normalized_monthly
     WHERE source = ? AND metric_name = ?
     ORDER BY measurement_date ASC`
  ).all(source, metricName) as { value: number | null }[];
  return rows
    .filter(r => r.value !== null)
    .map(r => r.value as number);
}
```

### Auto-Differencing Extension for stationarity.py
```python
# Extend test_stationarity() in analyze_stationarity.py
def test_stationarity_with_differencing(series: list[float]) -> dict:
    """Test stationarity, auto-difference if non-stationary, retest."""
    result = test_stationarity(series)
    if result["verdict"] == "non-stationary" and len(series) >= 13:
        # First difference: [s[1]-s[0], s[2]-s[1], ...]
        differenced = [series[i] - series[i-1] for i in range(1, len(series))]
        result_diff = test_stationarity(differenced)
        return {
            **result_diff,
            "differenced": True,
            "original_verdict": result["verdict"]
        }
    return {**result, "differenced": False}
```

### Granger Weight Computation
```python
# In analyze_granger.py — after all tests complete
def compute_weight(pvalue: float, significant: bool) -> float:
    """Granger-derived weight: 1/pvalue for significant, 0 for non-significant."""
    if not significant or pvalue <= 0:
        return 0.0
    return 1.0 / pvalue
```

### Composite Index Scaling
```python
# In analyze_composite.py
import numpy as np

def build_composite(weighted_zscores: list[float]) -> float:
    """Build composite index scaled to [-1, +1]."""
    if not weighted_zscores:
        return 0.0
    raw = np.mean(weighted_zscores)
    # Clip to [-1, +1] — tanh provides smooth saturation
    return float(np.tanh(raw / 2))

def zone_label(score: float) -> str:
    if score <= -0.3:
        return "strong_sell"
    elif score >= 0.3:
        return "strong_buy"
    return "neutral"
```

### Expat Funnel Stage Scoring
```python
# In analyze_expat_funnel.py
from scipy.stats import zscore as scipy_zscore

def score_stage(signal_values: dict[str, list[float]]) -> float:
    """Average z-score across all signals for this stage."""
    zscores = []
    for signal, values in signal_values.items():
        if len(values) >= 2:
            z = scipy_zscore(values)
            zscores.append(float(z[-1]))  # Most recent z-score
    return float(np.mean(zscores)) if zscores else 0.0
```

### Cache TTL Computation (next 25th)
```typescript
// In packages/uae-re/src/analytics/pipeline.ts
export function getNextAnalysisDate(): Date {
  const now = new Date();
  const next25th = new Date(now.getFullYear(), now.getMonth(), 25, 2, 0, 0);
  if (now >= next25th) {
    // Already past this month's 25th, use next month's
    next25th.setMonth(next25th.getMonth() + 1);
  }
  return next25th;
}
```

---

## Pipeline Module Structure (Claude's Discretion — Recommendation)

Use **per-analysis modules** (not single orchestrator Python script). Rationale: each module has independent error recovery, different timeouts, and different DB tables. The TypeScript orchestrator handles the sequencing.

```
packages/uae-re/
├── python/uae_re/
│   ├── stationarity.py          # existing (single-pair, used by granger.py)
│   ├── granger.py               # existing (single-pair, used by on-demand tool)
│   ├── correlation.py           # existing (single-pair, used by on-demand tool)
│   ├── analyze_stationarity.py  # NEW: batch mode, writes stationarity_results
│   ├── analyze_granger.py       # NEW: batch mode, writes granger_results
│   ├── analyze_composite.py     # NEW: writes composite_scores
│   ├── analyze_anomalies.py     # NEW: writes anomaly_flags
│   ├── analyze_affordability.py # NEW: writes intelligence_cache
│   └── analyze_expat_funnel.py  # NEW: writes intelligence_cache
└── src/analytics/
    ├── bridge.ts                # existing (no changes)
    ├── types.ts                 # extend PythonScriptName union
    ├── pipeline.ts              # NEW: TypeScript pipeline orchestrator
    └── digest.ts                # NEW: Telegram monthly digest formatter
```

**Preserve existing single-pair modules.** Phase 12 will expose `uae_granger_test` and `uae_correlation` as on-demand Telegram tools — they call the original `granger.py` and `correlation.py` directly.

---

## Tier A+B Signal Inventory for Granger Batch

The orchestrator needs to know which (source, metric) pairs are "Tier A+B signals" to test against DLD targets. Based on REQUIREMENTS.md:

**Tier A signals (COLL-01 to COLL-05, COLL-15):**
- `dld`: meter_sale_price, actual_worth (these ARE the targets — skip as inputs)
- `ejari`: avg_rent_per_sqft, renewal_rate, rent_YoY_change
- `permits`: residential_count, commercial_count
- `adrec`: transaction_volume, avg_price
- `bayut`: listing_count, avg_asking_price, days_on_market, price_reductions
- `propertyfinder`: listing_count, avg_asking_price, days_on_market
- `dewa`: new_connections, disconnections

**Tier B signals (COLL-06 to COLL-13):**
- `mohre`: new_permits_total
- `dxb`: passenger_arrivals
- `gdrfa`: visa_issuances, visa_cancellations
- `khda`: total_enrollment
- `rta`: new_registrations
- `jobs`: total_postings
- `salary`: median_salary (by bracket — may need aggregation)
- `remittances`: total_personal_remittances

**Targets (two):**
- `dld` / `meter_sale_price` — DLD price
- `dld` / `trans_count` (or derived monthly volume) — DLD volume

The orchestrator should query `normalized_monthly` to discover which (source, metric) pairs actually have 12+ months of data, rather than hardcoding the full list. This handles the "run with available data" requirement gracefully.

---

## Security Implementation (SEC-06, SEC-07)

### SEC-06: Parameterized Queries
All TypeScript DB queries in pipeline.ts and queries.ts MUST use prepared statements:
```typescript
// CORRECT
const stmt = db.prepare("SELECT * FROM composite_scores WHERE area = ?");
const row = stmt.get(areaName);

// WRONG — never do this
const row = db.prepare(`SELECT * FROM composite_scores WHERE area = '${areaName}'`).get();
```

Area name validation: before any area-parameterized query, validate against `area_names` table using a prepared query. Return error if not found (matches existing exact-match decision from STATE.md).

### SEC-07: PII Protection in Logs
The `analysis_log` table must NEVER contain:
- Individual visa records (GDRFA source data)
- Individual salary records (salary survey data)
- Individual employment records (MOHRE data)

Log only: `signals_processed` (count), `signals_skipped` (count), `duration_ms`, `status`. The `error` field may contain Python stderr — sanitize before writing: strip any numeric values that could be individual data points. In practice this means: log the exception type and message but not the data values that caused the failure.

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| Single-pair stationarity.py | Batch analyze_stationarity.py | Needed to process all 20+ signals efficiently |
| Manual Bonferroni per-pair | Batch Bonferroni across N total tests | Correct multiple testing correction |
| No auto-differencing | Auto-difference + retest if non-stationary | Locked decision; required for valid Granger |
| Single-pair granger.py | Batch analyze_granger.py with result table | Enables "relationship evolution" view in future phases |
| No pipeline timer | SCHED-06: 25th 02:00 UTC systemd timer | Monthly automated recompute |

---

## Open Questions

1. **DLD volume metric availability**
   - What we know: normalized_monthly receives DLD data via `normalize_dld.py`. The target for Granger is "DLD volume" but the current DLD schema captures `actual_worth` and `meter_sale_price`.
   - What's unclear: Is a monthly transaction count (volume) explicitly stored, or must it be derived by counting rows per month? Check `normalize_dld.py` output schema.
   - Recommendation: Check `/root/lobsec/packages/uae-re/python/uae_re/normalize_dld.py` during Wave 1 planning. If not present, add `trans_count` metric to the normalizer (small change, non-breaking).

2. **Tier B data availability in production**
   - What we know: COLL-06 through COLL-13 are marked "Pending" in REQUIREMENTS.md traceability. Collection infrastructure exists but production scraping may not have populated months of history.
   - What's unclear: How many months of Tier B data actually exist in the production DB today?
   - Recommendation: The pipeline's graceful-skip logic (skip signals with <12 obs) handles this correctly. Design for it explicitly; don't assume data exists. The planner should add a Wave 0 task to query the production DB and document actual data availability.

3. **analyze.sh: node invocation path**
   - What we know: collect.sh exists and follows a specific pattern. The exact node invocation command is not in the files reviewed.
   - What's unclear: Is it `node /opt/lobsec/plugins/lobsec-uae-re/dist/cli.js` or via a wrapper?
   - Recommendation: Read collect.sh during Wave 3 planning to confirm exact pattern before writing analyze.sh.

---

## Sources

### Primary (HIGH confidence)
- `/root/lobsec/packages/uae-re/python/uae_re/stationarity.py` — ADF+KPSS implementation, 12-obs minimum, inconclusive logic
- `/root/lobsec/packages/uae-re/python/uae_re/granger.py` — grangercausalitytests, Bonferroni pattern, stationarity gate
- `/root/lobsec/packages/uae-re/python/uae_re/correlation.py` — Pearson lag detection, ready-to-use
- `/root/lobsec/packages/uae-re/src/analytics/bridge.ts` — runPython() bridge, 30s default timeout, config override
- `/root/lobsec/packages/uae-re/src/analytics/types.ts` — PythonScriptName union (must extend with 6 new names)
- `/root/lobsec/packages/uae-re/src/db/schema.ts` — existing 5 tables; 5 new tables needed
- `/root/lobsec/.planning/phases/10-statistical-analysis/10-CONTEXT.md` — all locked decisions

### Secondary (MEDIUM confidence)
- `/root/lobsec/.planning/REQUIREMENTS.md` — STAT-01..08, SCHED-06, SEC-06..07 definitions
- `/root/lobsec/.planning/STATE.md` — architecture decisions, production environment details
- `/root/lobsec/.planning/ROADMAP.md` — Phase 10 success criteria

### Tertiary (LOW confidence)
- EWMA span=12 and threshold=2.0 recommendations: based on standard time-series anomaly detection practice; not verified against a specific UAE RE benchmark. Adjust based on actual signal noise levels after first pipeline run.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already installed and used in production
- Architecture: HIGH — bridge pattern verified from source code; new modules follow proven pattern
- Pitfalls: HIGH — Bonferroni scope and auto-differencing confirmed from existing code; timeout confirmed from bridge config
- New DB schemas: MEDIUM — design is sound but column choices may need adjustment once DLD volume metric is confirmed
- EWMA parameters: LOW — standard practice recommendation, not UAE-RE-specific

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (30 days — stable stack, no fast-moving dependencies)
