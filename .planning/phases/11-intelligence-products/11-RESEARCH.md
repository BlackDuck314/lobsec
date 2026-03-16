# Phase 11: Intelligence Products - Research

**Researched:** 2026-03-16
**Domain:** TypeScript query wrappers over SQLite analysis tables, Python out-of-sample validation, Telegram formatting
**Confidence:** HIGH — all findings grounded in existing codebase; no external library uncertainty

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Product Architecture**
- All 8 products are thin wrappers: SQL queries + formatting. No re-computation of analysis
- Each product queries independently — no shared data-fetch utilities between products
- No cross-references between products in Telegram output. Each product is self-contained
- Product modules live in `src/products/` directory (new). Separation: analytics/ = computation, products/ = presentation, tools/ = plugin commands (Phase 12)
- Single area per query. No multi-area comparison in one response. Phase 12 tool can support ranked "all areas" list

**Distress Detection (PROD-02)**
- 8 market signals: DLD price YoY decline, listing DOM increase, price reduction count, permit withdrawal rate, DEWA disconnection surge, F&B closure rate, mortgage rate increase, listing-to-transaction ratio
- 9 lifecycle signals: expat funnel stages 2-10 (Job Search through Exit), mapped from existing funnel z-scores
- Weighting: Granger-derived (1/p-value) where available, equal weight for signals without Granger data. Consistent with composite index approach
- Alert threshold: >=0.6 at area-level only. City-wide average hides hyperlocal distress. No city-wide threshold
- Alert behavior: query-only, no proactive push. Distress included in monthly digest if any area crosses threshold. On-demand via Telegram tool in Phase 12

**Telegram Response Formatting**
- Consistent template across all 8 products: header line with emoji + product name, area/scope line, key metrics block, trend indicator (vs last month), data freshness footer
- Verbosity: summary + top 3-5 contributing signals with direction arrows. ~500 chars per area. Quick to scan, actionable
- Data freshness footer: "Data as of: YYYY-MM-DD | Next update: YYYY-MM-DD". Warns if any source is stale (>2x overdue)
- Hard 4K char limit (Telegram) with [truncated] suffix — consistent with existing digest.ts convention

**Out-of-Sample Validation (QUAL-01)**
- 70/30 train/test split. Minimum 12 months total data required (so ~8 train, 4 test)
- Skip validation for signals with <12 months. Report which signals validated vs skipped
- On validation failure (significant on train, not on test): downweight signal by 0.5x in composite. Don't remove entirely — limited test data may cause premature drops
- Validation runs as part of the monthly pipeline (after Granger, before composite). Results stored in a validation_results table. Composite reads validation status to apply downweighting
- Validation results persist — enables tracking confidence evolution over time

**Conditional Forward-Fill (QUAL-03)**
- Apply going forward only — change normalization code to limit forward-fill to 1 period, then NULL for extended outages
- Existing data stays as-is. Next pipeline run naturally picks up improved behavior
- No retroactive cleanup or migration step

### Claude's Discretion
- Exact SQL queries for each product
- Specific emoji choices for product headers
- How to compute derived metrics not already in analysis tables (e.g., listing-to-transaction ratio, permit withdrawal rate)
- validation_results table schema
- Forward-fill implementation details in normalization code
- Trend indicator calculation (vs last month or rolling average)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PROD-01 | Area Buy/Sell Signal Score — 9-component composite, scale -1 to +1, monthly update per area/property type | `composite_scores` table exists with area, score, zone, component_count, components_json; direct SQL read + format |
| PROD-02 | Distress Detection System — 17-signal score (8 market + 9 lifecycle), alert threshold >=0.6 | Reads `granger_results`, `anomaly_flags`, `normalized_monthly` for 8 market signals; reads `intelligence_cache` key `expat_funnel_latest` for 9 lifecycle z-scores |
| PROD-03 | Rental Intelligence Dashboard — 10 metrics: gross yield, rental momentum, vacancy proxy, renewal rate, listing absorption, pipeline pressure, affordability ratio, STR premium, rent-to-income, DOM trend | Sources span `normalized_monthly` (ejari, bayut, permits, airbnb), `intelligence_cache` (affordability_latest); some metrics require derivation |
| PROD-04 | Supply Pipeline Tracker — building permits, DEWA new connections, Jebel Ali cargo, customs household imports, 12-24mo forward curve | All signals in `normalized_monthly` (permits, dewa, port, customs); forward curve via trend extrapolation on recent 6-12mo |
| PROD-05 | Expat Population Flow Dashboard — 10-stage funnel visualization, awareness-to-exit with stage-level metrics | `intelligence_cache` key `expat_funnel_latest` has complete JSON + `digest_text`; PROD-05 can reuse `digest_text` directly |
| PROD-06 | Macro Health Dashboard — 6 signal groups (employment, housing, spending, mobility, sentiment, population), traffic light output (green/amber/red) | All 6 groups map to existing sources in `normalized_monthly`; EWMA anomaly flags in `anomaly_flags`; threshold-based traffic light logic |
| PROD-07 | Off-Plan vs Ready Arbitrage Tracker — premium spread by area, developer incentive monitoring, DLD procedure_name_en filtering | Reads `normalized_monthly` (dld, bayut/propertyfinder); requires off-plan vs ready segmentation from DLD procedure_name_en field |
| PROD-08 | Salary-Rent Pressure Map — 5 income brackets, area segment mapping, migration prediction (flight risk by bracket) | `intelligence_cache` key `affordability_latest` has complete bracket×area structure; PROD-08 wraps it with flight-risk classification |
| QUAL-01 | Out-of-sample validation — split data into training/test sets, validate Granger results on held-out data | New Python module `analyze_validation.py`; new DB table `validation_results`; pipeline integration between Granger and composite steps |
| QUAL-03 | Conditional forward-fill — fill gaps up to 1 period only; leave NULL for extended outages | `normalize.py` already has `ffill(limit=1)`; per-source normalizers use `resample("ME")` without forward-fill; verify and patch the ~11 per-source modules that may propagate None values differently |
</phase_requirements>

---

## Summary

Phase 11 is the thinnest phase in the v1.3 roadmap. All statistical computation happened in Phase 10; Phase 11 reads those results and formats them for Telegram consumption. The core infrastructure (intelligence_cache, composite_scores, anomaly_flags, granger_results, normalized_monthly, IntelligenceCache class, digest.ts formatting patterns) is fully deployed and verified. The eight intelligence products are TypeScript modules that run SQL queries against these tables and format the results as Telegram-friendly strings.

The non-trivial work is in two areas: (1) QUAL-01 requires a new Python module `analyze_validation.py` and a new `validation_results` table, integrated into `pipeline.ts` as Step 1.5 (between Granger and composite); (2) QUAL-03 requires auditing all per-source normalizers to confirm `ffill(limit=1)` is applied consistently — the base `normalize.py` already does this but the 11 individual normalizers do not all replicate it. Several derived metrics for PROD-02/PROD-03/PROD-07 are not pre-computed in analysis tables and must be derived in the product SQL queries themselves.

Phase 12 will consume these products as tools (TOOL-01 through TOOL-08 call the PROD-01 through PROD-08 formatters). Products must therefore export a clean TypeScript function signature, not just produce Telegram strings.

**Primary recommendation:** Build each product as a single TypeScript file in `src/products/` that exports a typed async function `query{ProductName}(db, params) => FormattedResult`. The formatter takes the structured result and returns a Telegram string. Keep SQL inline (parameterized) — no ORM layer needed for 8 simple queries.

---

## Standard Stack

### Core (already installed — no new installs needed)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| better-sqlite3 | ≥9.x | Parameterized SQL queries reading analysis tables | Already used throughout; synchronous, fast for read-only product queries |
| Python 3.13 stdlib (`sqlite3`, `json`, `sys`) | stdlib | `analyze_validation.py` bridge module | Same pattern as all 6 existing analysis modules |
| statsmodels | ≥0.14 | Out-of-sample Granger re-test on held-out data (QUAL-01) | Already in analytics-venv; `grangercausalitytests` used in `analyze_granger.py` |
| pandas | ≥2.2 | 70/30 train/test splitting, `ffill(limit=1)` in normalizers | Already in analytics-venv and all normalizers |

### Supporting
| Library | Purpose | When to Use |
|---------|---------|-------------|
| Node.js built-in `Date` | Freshness footer computation, next-25th TTL | No library needed |
| Python `hashlib` | params_hash for validation_results cache key | Same pattern as analyze_affordability.py |

### No New Installations Needed
All required libraries are already in `/opt/lobsec/analytics-venv/` and `node_modules`. No `pip install` or `pnpm add` needed.

---

## Architecture Patterns

### Recommended Project Structure

```
packages/uae-re/src/
├── analytics/           # Phase 10 — computation (no changes)
│   ├── bridge.ts
│   ├── digest.ts
│   ├── pipeline.ts      # ADD validation step (Step 1.5)
│   └── types.ts         # ADD "analyze_validation" to PythonScriptName
├── products/            # Phase 11 — NEW directory
│   ├── prod01-area-signal.ts
│   ├── prod02-distress.ts
│   ├── prod03-rental.ts
│   ├── prod04-supply.ts
│   ├── prod05-expat-funnel.ts
│   ├── prod06-macro-health.ts
│   ├── prod07-arbitrage.ts
│   ├── prod08-salary-rent.ts
│   └── format.ts        # shared Telegram format helpers (truncate, header, footer)
├── db/
│   └── schema.ts        # ADD validation_results table
└── tools/               # Phase 12 (not touched in Phase 11)

packages/uae-re/python/uae_re/
├── analyze_validation.py   # NEW: QUAL-01 out-of-sample validation
└── normalize_*.py          # PATCH: confirm ffill(limit=1) (QUAL-03)
```

### Pattern 1: Product Module Structure

Each product module follows this exact shape — verified from digest.ts and cache/manager.ts patterns:

```typescript
// Source: pattern from packages/uae-re/src/analytics/digest.ts
import type Database from "better-sqlite3";

export interface AreaSignalResult {
  area: string;
  score: number;
  zone: string;
  componentCount: number;
  totalComponents: number;
  components: Array<{ source: string; metric: string; weight: number; zscore: number }>;
  computedAt: string;
  // For Phase 12 tool consumption:
  formattedText: string;
}

export function queryAreaSignal(
  db: Database.Database,
  area: string,
  // property_type optional — if omitted, returns area aggregate
): AreaSignalResult | null {
  // 1. Validate area against area_names (SEC-06)
  const areaRow = db.prepare(
    "SELECT canonical_name FROM area_names WHERE canonical_name = ?"
  ).get(area) as { canonical_name: string } | undefined;
  if (!areaRow) return null;

  // 2. Query composite_scores
  const row = db.prepare(
    "SELECT score, zone, component_count, total_components, components_json, computed_at " +
    "FROM composite_scores WHERE area = ? ORDER BY computed_at DESC LIMIT 1"
  ).get(area) as CompositeRow | undefined;
  if (!row) return null;

  // 3. Parse components_json, build result, format text
  const result: AreaSignalResult = { ... };
  result.formattedText = formatAreaSignal(result);
  return result;
}

function formatAreaSignal(result: AreaSignalResult): string {
  const lines: string[] = [
    `📊 AREA SIGNAL — ${result.area.toUpperCase()}`,
    `Score: ${result.score.toFixed(2)} (${zoneLabel(result.zone)})`,
    `Coverage: ${result.componentCount}/${result.totalComponents} components`,
    // ...
    `Data as of: ${result.computedAt.slice(0, 10)} | Next update: ${nextUpdateDate()}`,
  ];
  return truncate4K(lines.join("\n"));
}
```

**Rule:** Every product module exports exactly one query function + its result interface. No shared fetch utilities. Format functions are private to each module.

### Pattern 2: Shared Format Helpers (format.ts)

Keep shared only: the 4K truncation function, the data freshness footer computation, and the zone-to-label mapping. Everything else stays private to each product.

```typescript
// packages/uae-re/src/products/format.ts
export function truncate4K(text: string): string {
  if (text.length <= 4000) return text;
  return text.slice(0, 3990) + "\n[truncated]";
}

export function freshnessFooter(lastDate: string): string {
  // Reuse getNextAnalysisDate() from pipeline.ts
  const nextRun = getNextAnalysisDate();
  return `Data as of: ${lastDate} | Next update: ${nextRun.toISOString().slice(0, 10)}`;
}

export function stalenessWarning(sourceDate: string, expectedFreqDays: number): string | null {
  const daysSince = (Date.now() - new Date(sourceDate).getTime()) / 86400000;
  if (daysSince > expectedFreqDays * 2) {
    return `⚠️ STALE: ${Math.floor(daysSince)}d since last update`;
  }
  return null;
}
```

### Pattern 3: Out-of-Sample Validation Module (QUAL-01)

New Python module `analyze_validation.py` follows the exact same bridge pattern as `analyze_granger.py`:

```python
# packages/uae-re/python/uae_re/analyze_validation.py
"""
Out-of-sample validation module (QUAL-01).

Bridge pattern: JSON stdin {db_path} → compute → JSON stdout {validated, skipped, downweighted}
- Reads granger_results for significant signals
- Splits normalized_monthly series 70/30 (train/test)
- Re-runs Granger on training set, checks significance on test set
- Writes results to validation_results table
- Composite reads validation_results to apply 0.5x downweight on failures

Output: {"validated": int, "skipped": int, "downweighted": int}
"""
import sys, json, sqlite3
from statsmodels.tsa.stattools import grangercausalitytests

TRAIN_RATIO = 0.70
MIN_TOTAL_OBS = 12  # skip validation if fewer than 12 months total

def main():
    config = json.load(sys.stdin)
    db = sqlite3.connect(config["db_path"])
    # ... fetch significant signals, split, re-test, write validation_results
    json.dump({"validated": v, "skipped": s, "downweighted": d}, sys.stdout)
```

The pipeline step runs **after** `analyze_granger` and **before** `analyze_composite`:

```typescript
// packages/uae-re/src/analytics/pipeline.ts — modified step sequence
// Step 2: Granger (requires stationarity success)
await runStep("granger", "analyze_granger", stationarityFailed);

// Step 2.5: Validation (QUAL-01) — after Granger, before composite
await runStep("validation", "analyze_validation", grangerFailed);

// Step 3: Composite (requires granger success)
await runStep("composite", "analyze_composite", grangerFailed);
```

### Pattern 4: Conditional Forward-Fill (QUAL-03)

The base `normalize.py` already has `ffill(limit=1)` (verified at line 38). The 11 per-source normalizers (`normalize_dld.py`, `normalize_ejari.py`, etc.) use `resample("ME")` without applying forward-fill. They produce `None`/`NaN` values naturally where data is absent — which is the correct behavior for QUAL-03. The change is: confirm each per-source normalizer does NOT silently carry forward stale values past 1 period. If any normalizer has unbounded `ffill()` calls (no `limit=`), patch it to `ffill(limit=1)`.

**Verified state:**
- `normalize.py` (base): `ffill(limit=1)` — already correct
- `normalize_dld.py`, `normalize_ejari.py`, `normalize_permits.py`: use `resample("ME")` → `.mean()` aggregation, no `ffill()` call — already correct (NaN where no data)
- `normalize_trends.py`: `resample("MS")` without `ffill()` — already correct
- No normalizer was found with unbounded `ffill()` in source inspection

**QUAL-03 action:** Audit the remaining 7 per-source normalizers for `ffill()` calls during Wave 1. If any has unbounded forward-fill, add `limit=1`. No retroactive migration step needed.

### Anti-Patterns to Avoid
- **Shared data-fetch layer:** Locked decision — each product queries independently. Don't build a `fetchProductData()` helper that all 8 products call.
- **Re-computing Granger/composite:** Products read pre-computed values from analysis tables. Never call `runPython()` inside a product module.
- **City-wide distress threshold:** PROD-02 threshold applies at area level only. City-wide aggregate hides hyperlocal signals.
- **Proactive distress alerts in Phase 11:** Alert behavior is query-only in Phase 11. Proactive Telegram push is Phase 12 (AUTO-02, deferred to v1.4 actually).
- **Hardcoded area names in SQL:** Always validate area parameter against `area_names` table first (SEC-06).

---

## Derived Metrics Not Yet In Analysis Tables

Several PROD metrics require computation at query time (not pre-stored). These need SQL derivation or Python bridge calls:

### PROD-02: Listing-to-Transaction Ratio
Not in any analysis table. Derivable at query time:
```sql
-- listing_count from bayut/normalized_monthly vs trans_count from dld/normalized_monthly
SELECT
  b.value / NULLIF(d.value, 0) AS listing_to_txn_ratio
FROM normalized_monthly b
JOIN normalized_monthly d ON b.measurement_date = d.measurement_date
WHERE b.source = 'bayut' AND b.metric_name = 'listing_count'
  AND d.source = 'dld' AND d.metric_name = 'trans_count'
ORDER BY b.measurement_date DESC LIMIT 1
```

### PROD-02: Permit Withdrawal Rate
Depends on whether `normalize_permits.py` tracks withdrawn permits. The normalizer classifies permits as residential/commercial but may not track withdrawals directly. If not available: use `NULL` with note "insufficient data" rather than inventing a proxy.

### PROD-03: Gross Yield
Requires combining ejari rent with DLD/bayut sale prices:
```
gross_yield = (annual_rent / sale_price) × 100
annual_rent = avg_rent_per_sqft × typical_sqft × 12
sale_price = avg_asking_price from bayut or meter_sale_price from dld
```

### PROD-03: Vacancy Proxy
No direct vacancy data. Proxy: `listing_count / (new_contracts + listing_count)`. If listing count is high relative to contracts signed, vacancy is elevated.

### PROD-03: Pipeline Pressure
Ratio of permits in-progress to recent completions: `residential_count from permits / avg new_connections from dewa`. Approximates supply-demand balance.

### PROD-07: Off-Plan vs Ready Segmentation
The DLD `procedure_name_en` field distinguishes off-plan from ready. The current `normalize_dld.py` does not segment by this field. PROD-07 either: (a) queries `raw_sources` file path and re-reads the CSV — fragile; or (b) extends `normalize_dld.py` to also produce `offplan_avg_price` and `ready_avg_price` metrics. Option (b) is better but requires a normalization change. Check whether `normalize_dld.py` currently stores `procedure_name_en` before committing to an approach.

### PROD-06: Traffic Light Logic

Signal groups and their sources:
| Group | Sources | Green Condition | Red Condition |
|-------|---------|----------------|---------------|
| Employment | jobs.total_postings, mohre.new_permits_total | z-score > 0.3 | z-score < -0.3 |
| Housing | ejari.new_contracts, bayut.listing_count | z-score > 0.3 | z-score < -0.3 |
| Spending | licenses.new_licenses, rta.new_registrations | z-score > 0.3 | z-score < -0.3 |
| Mobility | dxb.passenger_arrivals, metro.ridership | z-score > 0.3 | z-score < -0.3 |
| Sentiment | sentiment.bearish_ratio (inverted), trends.expat_interest | z-score > 0.3 | z-score < -0.3 |
| Population | gdrfa.visa_issuances, demographics.population_total | z-score > 0.3 | z-score < -0.3 |

Traffic light = avg z-score of available signals in group:
- Green: avg z-score >= 0.3
- Red: avg z-score <= -0.3
- Amber: otherwise

---

## New Database Table: validation_results

```sql
-- packages/uae-re/src/db/schema.ts — add to initSchema()
CREATE TABLE IF NOT EXISTS validation_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  signal_source TEXT NOT NULL,
  signal_metric TEXT NOT NULL,
  target TEXT NOT NULL,
  train_obs INTEGER NOT NULL,           -- observation count in training set
  test_obs INTEGER NOT NULL,            -- observation count in test set
  train_significant INTEGER NOT NULL,   -- 1 if significant in training set
  test_significant INTEGER NOT NULL,    -- 1 if significant in test set
  validated INTEGER NOT NULL,           -- 1 if consistent (both significant OR both not)
  downweight_factor REAL NOT NULL DEFAULT 1.0,  -- 0.5 on validation failure, 1.0 on pass
  tested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_validation_signal
  ON validation_results(signal_source, signal_metric, target, tested_at);
```

The composite module reads this table to apply downweighting:
```python
# In analyze_composite.py — extend fetch_significant_signals()
def fetch_significant_signals_with_downweight(db):
    """Fetch signals with validation downweighting applied."""
    rows = db.execute(
        "SELECT g.signal_source, g.signal_metric, g.target, "
        "       g.weight * COALESCE(v.downweight_factor, 1.0) AS effective_weight, "
        "       g.best_lag "
        "FROM granger_results g "
        "LEFT JOIN ("
        "  SELECT signal_source, signal_metric, target, downweight_factor "
        "  FROM validation_results "
        "  WHERE tested_at = (SELECT MAX(tested_at) FROM validation_results v2 "
        "                     WHERE v2.signal_source = validation_results.signal_source)"
        ") v ON g.signal_source = v.signal_source AND g.signal_metric = v.signal_metric "
        "WHERE g.significant = 1 AND g.tested_at = ..."
    ).fetchall()
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SQL area validation | Custom area lookup class | `db.prepare("SELECT canonical_name FROM area_names WHERE canonical_name = ?").get(area)` | One-liner; area_names table already seeded |
| 4K truncation | Custom chunker | `truncate4K()` helper in format.ts | Already in digest.ts (line 261-268); copy pattern |
| Cache TTL | Custom date math | `getNextAnalysisDate()` from pipeline.ts | Already exported; re-use directly |
| Granger re-test | New stats library | `grangercausalitytests` from statsmodels | Already in analyze_granger.py; same function |
| Traffic light thresholds | ML classifier | Simple z-score threshold (±0.3) | Consistent with composite zone thresholds |
| Distress score | Custom scoring framework | Weighted z-score average, same as composite pattern | analyze_composite.py already implements this pattern |
| Forward-fill limit | Custom resample logic | `df.ffill(limit=1)` in pandas | Base normalize.py already does this |
| Telegram send | Custom HTTP | Existing `sendTelegramMessage()` in pipeline.ts | Already implemented; products don't send — tools do |

**Key insight:** Phase 11 is about reading, not computing. The temptation is to add computation inside product modules. Resist it — all math is in Phase 10 analysis tables.

---

## Common Pitfalls

### Pitfall 1: PROD-07 Requires DLD Segmentation Not Yet Computed
**What goes wrong:** Off-plan vs ready arbitrage requires knowing which DLD transactions are off-plan. The current `normalize_dld.py` aggregates all transactions without `procedure_name_en` segmentation. PROD-07 cannot produce meaningful output without this field.
**Why it happens:** Phase 7 normalized DLD for general price/volume metrics, not off-plan/ready segmentation.
**How to avoid:** During Wave 1 (research validation), check the raw DLD CSV and `normalize_dld.py` output to confirm whether `procedure_name_en` data is already available in `normalized_monthly`. If not, PROD-07 needs to extend the DLD normalizer to add `offplan_avg_price` and `ready_avg_price` metrics — small but required normalization change.
**Warning signs:** PROD-07 returns "insufficient data" for all queries — the segmentation metric is absent.

### Pitfall 2: expat_funnel_latest Cache Key May Not Exist
**What goes wrong:** PROD-02 and PROD-05 read from `intelligence_cache` key `expat_funnel_latest`. If the pipeline hasn't run successfully with expat funnel data, this key doesn't exist. Product must handle NULL gracefully.
**Why it happens:** Pipeline was deployed March 2026 with sparse data — many analysis steps skip with "insufficient data" gracefully.
**How to avoid:** All product queries must have NULL fallback paths. When cache is absent: return "insufficient data — pipeline not yet run" rather than throwing. Use `?? "No data"` patterns in TypeScript.
**Warning signs:** Product throws on `.get()` returning `undefined` from cache query.

### Pitfall 3: Validation Step Order in Pipeline
**What goes wrong:** If `analyze_validation` runs AFTER `analyze_composite`, the composite module uses non-downweighted weights. The downweighting effect won't appear until the next monthly run.
**Why it happens:** Easy to add the validation step at the wrong position in pipeline.ts.
**How to avoid:** Insert validation as Step 2.5 — after `analyze_granger` (which populates `granger_results`) and before `analyze_composite` (which reads `granger_results`). The pipeline `skip` flag for validation should be `grangerFailed` (skip if Granger failed, same gate as composite).
**Warning signs:** `validation_results` table has entries but composite scores are unchanged from before — composite is reading old granger weights without downweighting.

### Pitfall 4: PROD-03 Gross Yield Requires Both Rent and Price Data
**What goes wrong:** Gross yield needs both ejari rent AND sale price data in the same area. With sparse Tier A collection, one or both may be absent for many areas.
**Why it happens:** Ejari and DLD/Bayut collection may not have succeeded for all 20 areas.
**How to avoid:** Return metric as `null` with "insufficient data" text when either component is missing. Don't compute yields from city-wide averages applied to specific areas — that produces misleading precision.
**Warning signs:** PROD-03 shows yield = 4.2% for every area despite no area-level rent data.

### Pitfall 5: 70/30 Split Direction Matters
**What goes wrong:** If the 70/30 split takes the LAST 30% as test data (correct for time series — no look-ahead), but code accidentally takes a random 30% or the FIRST 30%, validation results will be biased.
**Why it happens:** Confusing cross-validation with time-series validation. Random splits introduce look-ahead bias.
**How to avoid:** Always split chronologically: first 70% of observations by date = train, last 30% = test. Use `series[:train_n]` and `series[train_n:]` where `train_n = int(len(series) * 0.7)`.
**Warning signs:** Validation shows much higher significance on test than train — likely look-ahead bias from non-chronological split.

### Pitfall 6: Distress Score Exceeds 1.0 Without Normalization
**What goes wrong:** The 17-signal distress score is a weighted average of z-scores. Z-scores can exceed ±3. If the threshold is 0.6 but z-scores are routinely ±2, threshold calibration is off.
**Why it happens:** The 0.6 threshold is calibrated against the composite's tanh-scaled [-1,+1] score, not raw z-scores.
**How to avoid:** Apply `tanh(weighted_avg_z / 2)` scaling to the distress score the same way composite does, so the 0.6 threshold maps consistently. Alternatively, normalize by capping z-scores at ±3 before averaging.
**Warning signs:** Every area shows distress score > 0.6, or no area ever exceeds 0.5.

### Pitfall 7: PythonScriptName Missing "analyze_validation"
**What goes wrong:** `pipeline.ts` calls `runPython("analyze_validation", ...)` but if `"analyze_validation"` is not in the `PythonScriptName` union type in `types.ts`, TypeScript will emit a compile error.
**Why it happens:** The union type must be manually extended for each new Python module.
**How to avoid:** Add `"analyze_validation"` to the `PythonScriptName` union in `packages/uae-re/src/analytics/types.ts` as part of the same wave that creates the Python module.
**Warning signs:** TypeScript compile error: `Argument of type '"analyze_validation"' is not assignable to parameter of type 'PythonScriptName'`.

---

## Code Examples

Verified patterns from existing production codebase:

### Cache Read Pattern (for PROD-05 and PROD-08)
```typescript
// Source: packages/uae-re/src/analytics/digest.ts lines 160-177
const cacheRow = db.prepare(
  "SELECT result_json FROM intelligence_cache WHERE cache_key = ?"
).get("expat_funnel_latest") as { result_json: string } | undefined;

if (cacheRow) {
  try {
    const parsed = JSON.parse(cacheRow.result_json) as ExpatFunnelResult;
    // use parsed.stages, parsed.digest_text
  } catch {
    return "Cache data parse error";
  }
}
```

### Composite Score Query (for PROD-01)
```typescript
// Source: pattern from packages/uae-re/src/analytics/digest.ts lines 91-103
const row = db.prepare(
  "SELECT score, zone, component_count, total_components, components_json, computed_at " +
  "FROM composite_scores WHERE area = ? ORDER BY computed_at DESC LIMIT 1"
).get(area) as CompositeRow | undefined;
```

### Area Validation (SEC-06)
```typescript
// Source: pattern established in analyze_composite.py + STATE.md
const valid = db.prepare(
  "SELECT canonical_name FROM area_names WHERE canonical_name = ?"
).get(area) as { canonical_name: string } | undefined;
if (!valid) return { error: `Unknown area: ${area}` };
```

### Granger Results Query (for distress weighting)
```typescript
const signals = db.prepare(
  "SELECT signal_source, signal_metric, pvalue, weight " +
  "FROM granger_results WHERE significant = 1 " +
  "ORDER BY tested_at DESC LIMIT 50"
).all() as GrangerRow[];
```

### Normalized Monthly Time-Series Fetch (for trend indicators)
```typescript
// Last 2 values for trend indicator (vs last month)
const rows = db.prepare(
  "SELECT value, measurement_date FROM normalized_monthly " +
  "WHERE source = ? AND metric_name = ? AND value IS NOT NULL " +
  "ORDER BY measurement_date DESC LIMIT 2"
).all(source, metric) as { value: number; measurement_date: string }[];

const current = rows[0]?.value ?? null;
const previous = rows[1]?.value ?? null;
const trend = (current !== null && previous !== null)
  ? (current > previous ? "up" : current < previous ? "down" : "flat")
  : "unknown";
const trendArrow = trend === "up" ? "^" : trend === "down" ? "v" : "-";
```

### 70/30 Chronological Split (analyze_validation.py)
```python
# Source: standard time-series validation practice
def chronological_split(series: list[float], train_ratio: float = 0.70):
    """Split series chronologically — NO random shuffling."""
    n = len(series)
    train_n = int(n * train_ratio)
    return series[:train_n], series[train_n:]  # train, test
```

### Telegram Header Template
```typescript
// Consistent with locked decision: "header line with emoji + product name"
function productHeader(emoji: string, name: string, scope: string): string {
  return `${emoji} ${name}\n${scope}`;
}
// Usage: productHeader("📊", "AREA SIGNAL", "Downtown Dubai · Apartment")
```

---

## Pipeline Integration (QUAL-01)

The current pipeline sequence in `pipeline.ts` (6 steps):
```
stationarity → granger → composite → anomalies → affordability → expat_funnel
```

Phase 11 adds Step 2.5:
```
stationarity → granger → [validation] → composite → anomalies → affordability → expat_funnel
```

Changes to `pipeline.ts`:
1. Add `runStep("validation", "analyze_validation", grangerFailed)` after granger step
2. Set skip condition: `grangerFailed` (same gate as composite)
3. `analyze_composite.py` must be modified to JOIN `validation_results` for downweighting

Changes to `analyze_composite.py`:
- Extend `fetch_significant_signals()` to apply `downweight_factor` from `validation_results`
- If no `validation_results` for a signal (e.g. first run), default `downweight_factor = 1.0`
- LEFT JOIN handles this correctly

---

## QUAL-03 Forward-Fill Audit

**Finding:** Only `normalize.py` (the base utility module used by the TS normalization orchestrator's "generic" path) has `ffill(limit=1)`. The 11 per-source normalizers that write directly to `normalized_monthly` use pandas `resample("ME").agg(...)` which produces `NaN` for missing months — correct behavior for QUAL-03.

**Files to audit during Wave 1:**
```
normalize_dld.py        — resample("ME") only, no ffill → CORRECT
normalize_ejari.py      — resample("ME") only, no ffill → CORRECT
normalize_permits.py    — resample("ME") only, no ffill → CORRECT
normalize_trends.py     — resample("MS") only, no ffill → CORRECT
normalize_adrec.py      — inspect during impl
normalize_bayut.py      — inspect during impl
normalize_propertyfinder.py — inspect during impl
normalize_dewa.py       — inspect during impl
normalize_mohre.py      — inspect during impl
normalize_dxb.py        — inspect during impl
normalize_gdrfa.py      — inspect during impl
normalize_khda.py       — inspect during impl
normalize_rta.py        — inspect during impl
normalize_remittances.py — inspect during impl
normalize_jobs.py       — inspect during impl
normalize_salary.py     — inspect during impl
```

If any uses unbounded `ffill()` without `limit=1`, add `limit=1`. No migration needed.

---

## Open Questions

1. **Does normalize_dld.py produce `procedure_name_en`-segmented metrics?**
   - What we know: `normalize_dld.py` filters to "Sales" transactions and aggregates `meter_sale_price`, `actual_worth`, `trans_count`. The DLD CSV includes `procedure_name_en` field.
   - What's unclear: Whether off-plan vs ready was ever added as a segmentation dimension.
   - Recommendation: Read `normalize_dld.py` fully during Wave 1. If `procedure_name_en` is absent, extend the normalizer to produce `offplan_avg_price` and `ready_avg_price` metrics. This is a normalization change but is required for PROD-07.

2. **Does the DLD CSV include `procedure_name_en` values for off-plan transactions?**
   - What we know: Dubai Pulse DLD data includes transaction type metadata. Off-plan transactions typically appear with procedure types like "Sell" under "Off-Plan" category.
   - What's unclear: The exact values of `procedure_name_en` that distinguish off-plan from ready.
   - Recommendation: Query raw DLD CSV during Wave 1 to inspect `procedure_name_en` distribution. If Dubai Pulse WAF is blocking downloads (known issue from STATE.md), use any cached CSV from previous collection attempts.

3. **How does `analyze_composite.py` currently access validation_results?**
   - What we know: `analyze_composite.py` does not yet read `validation_results` (the table doesn't exist until Phase 11).
   - What's unclear: Nothing — the change is clear. But there's a risk of breaking the existing composite if the LEFT JOIN is poorly written.
   - Recommendation: Use `LEFT JOIN` with `COALESCE(downweight_factor, 1.0)` so composite behavior is unchanged when no validation results exist (first run after Phase 11 deploy).

4. **Does the monthly digest in pipeline.ts need updating for distress alerts?**
   - What we know: CONTEXT.md says "Distress included in monthly digest if any area crosses threshold." The current `generateDigest()` in digest.ts does not include distress output.
   - What's unclear: Whether this belongs in Phase 11 (digest update) or Phase 12 (TOOL-02).
   - Recommendation: Add distress check to `generateDigest()` in Phase 11 since it's part of the monthly pipeline behavior, not a tool invocation. One additional SQL query against `composite_scores` / distress logic.

---

## State of the Art

| Old Approach | Phase 11 Approach | Impact |
|--------------|-------------------|--------|
| Monthly digest (digest.ts): city-wide only | 8 per-area products: area-specific on demand | Per-area intelligence instead of city aggregate |
| No out-of-sample validation | QUAL-01: 70/30 split, 0.5x downweight on failure | Composite weights validated against held-out data |
| Forward-fill behavior undocumented | QUAL-03: explicit limit=1, NULL for extended gaps | Prevents stale data propagation into analysis |
| No distress alerting | PROD-02: 17-signal score, area-level threshold | Risk management product for hyperlocal distress |

---

## Sources

### Primary (HIGH confidence)
- `/root/lobsec/packages/uae-re/src/analytics/digest.ts` — formatting patterns, truncation logic, Telegram helper
- `/root/lobsec/packages/uae-re/src/cache/manager.ts` — cache read/write pattern, params hash
- `/root/lobsec/packages/uae-re/src/cache/types.ts` — CacheEntry interface
- `/root/lobsec/packages/uae-re/src/analytics/pipeline.ts` — step sequence, runStep() pattern, getNextAnalysisDate()
- `/root/lobsec/packages/uae-re/src/db/schema.ts` — all 10 tables (composite_scores, anomaly_flags, granger_results, intelligence_cache, normalized_monthly confirmed)
- `/root/lobsec/packages/uae-re/src/analytics/types.ts` — PythonScriptName union (must add "analyze_validation")
- `/root/lobsec/packages/uae-re/python/uae_re/analyze_composite.py` — signal weighting, zone classification, parameterized SQL pattern
- `/root/lobsec/packages/uae-re/python/uae_re/analyze_affordability.py` — cache write pattern, next_25th_datetime(), INCOME_BRACKETS
- `/root/lobsec/packages/uae-re/python/uae_re/analyze_expat_funnel.py` — digest_text format, stage z-scores, cache key `expat_funnel_latest`
- `/root/lobsec/packages/uae-re/python/uae_re/analyze_anomalies.py` — EWMA anomaly_flags structure
- `/root/lobsec/packages/uae-re/python/uae_re/normalize.py` — `ffill(limit=1)` confirmed at line 38
- `/root/lobsec/packages/uae-re/src/index.ts` — plugin registration pattern, tool registration shape
- `/root/lobsec/.planning/phases/11-intelligence-products/11-CONTEXT.md` — all locked decisions

### Secondary (MEDIUM confidence)
- `/root/lobsec/.planning/REQUIREMENTS.md` — PROD-01..08, QUAL-01, QUAL-03 definitions and acceptance criteria
- `/root/lobsec/.planning/STATE.md` — architecture decisions, production environment, known issues
- `/root/lobsec/.planning/phases/10-statistical-analysis/10-04-SUMMARY.md` — what Phase 10 actually built and verified

### Tertiary (LOW confidence)
- Traffic light threshold (±0.3 z-score for green/red): aligned with composite zone thresholds but not validated against UAE RE signal distributions. Adjust after first pipeline run with real data.
- Distress signal weighting for market signals without Granger data: equal weight assumption is reasonable but unverified.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in production, no new dependencies
- Architecture: HIGH — product module pattern directly derived from verified digest.ts and cache/manager.ts code
- SQL queries: HIGH for PROD-01/05/08 (read pre-computed tables); MEDIUM for PROD-02/03/07 (require derived metrics)
- QUAL-01 validation: HIGH — same Granger code path, standard chronological split, clear table schema
- QUAL-03 forward-fill: HIGH — base normalize.py confirmed correct; per-source normalizers confirmed no unbounded ffill in sampled files
- Derived metrics (PROD-07 off-plan/ready): MEDIUM — depends on DLD CSV structure not yet confirmed for this metric

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (30 days — stable stack; only risk is DLD CSV field availability for PROD-07)
