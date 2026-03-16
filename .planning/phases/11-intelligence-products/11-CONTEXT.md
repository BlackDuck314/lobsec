# Phase 11: Intelligence Products - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Build 8 intelligence products (PROD-01 through PROD-08) as thin query+format wrappers over Phase 10's analysis tables. Each product reads from composite_scores, granger_results, anomaly_flags, intelligence_cache, and normalized_monthly — no re-computation. Plus out-of-sample validation (QUAL-01) integrated into the pipeline and conditional forward-fill (QUAL-03) applied going forward.

Requirements: PROD-01, PROD-02, PROD-03, PROD-04, PROD-05, PROD-06, PROD-07, PROD-08, QUAL-01, QUAL-03

</domain>

<decisions>
## Implementation Decisions

### Product Architecture
- All 8 products are thin wrappers: SQL queries + formatting. No re-computation of analysis
- Each product queries independently — no shared data-fetch utilities between products
- No cross-references between products in Telegram output. Each product is self-contained
- Product modules live in `src/products/` directory (new). Separation: analytics/ = computation, products/ = presentation, tools/ = plugin commands (Phase 12)
- Single area per query. No multi-area comparison in one response. Phase 12 tool can support ranked "all areas" list

### Distress Detection (PROD-02)
- 8 market signals: DLD price YoY decline, listing DOM increase, price reduction count, permit withdrawal rate, DEWA disconnection surge, F&B closure rate, mortgage rate increase, listing-to-transaction ratio
- 9 lifecycle signals: expat funnel stages 2-10 (Job Search through Exit), mapped from existing funnel z-scores
- Weighting: Granger-derived (1/p-value) where available, equal weight for signals without Granger data. Consistent with composite index approach
- Alert threshold: >=0.6 at area-level only. City-wide average hides hyperlocal distress. No city-wide threshold
- Alert behavior: query-only, no proactive push. Distress included in monthly digest if any area crosses threshold. On-demand via Telegram tool in Phase 12

### Telegram Response Formatting
- Consistent template across all 8 products: header line with emoji + product name, area/scope line, key metrics block, trend indicator (vs last month), data freshness footer
- Verbosity: summary + top 3-5 contributing signals with direction arrows. ~500 chars per area. Quick to scan, actionable
- Data freshness footer: "Data as of: YYYY-MM-DD | Next update: YYYY-MM-DD". Warns if any source is stale (>2x overdue)
- Hard 4K char limit (Telegram) with [truncated] suffix — consistent with existing digest.ts convention

### Out-of-Sample Validation (QUAL-01)
- 70/30 train/test split. Minimum 12 months total data required (so ~8 train, 4 test)
- Skip validation for signals with <12 months. Report which signals validated vs skipped
- On validation failure (significant on train, not on test): downweight signal by 0.5x in composite. Don't remove entirely — limited test data may cause premature drops
- Validation runs as part of the monthly pipeline (after Granger, before composite). Results stored in a validation_results table. Composite reads validation status to apply downweighting
- Validation results persist — enables tracking confidence evolution over time

### Conditional Forward-Fill (QUAL-03)
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

</decisions>

<specifics>
## Specific Ideas

- The expat lifecycle funnel (PROD-05) already has a Telegram-friendly text format with bars and arrows from Phase 10's analyze_expat_funnel.py — reuse that directly
- Named zones on composite (Strong Sell/Neutral/Strong Buy) are immediately actionable — preserve in PROD-01 output
- Distress detection is the "risk management" product — should feel urgent when threshold crossed. Use warning emoji/language
- Affordability model (PROD-08) already computes 5 income brackets in Phase 10 — PROD-08 wraps it with area-specific rent data

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `composite_scores` table: per-area + city-wide scores with zone classification — PROD-01 reads directly
- `anomaly_flags` table: EWMA anomalies for 4 signals — PROD-02 and PROD-06 read from here
- `granger_results` table: significant signals with p-values and lags — PROD-01, PROD-02 weighting
- `intelligence_cache` table: TTL-based cache with params hash key — products store formatted results here
- `analyze_expat_funnel.py`: already produces Telegram-friendly digest_text — PROD-05 can reuse
- `analyze_affordability.py`: 5 income brackets already computed — PROD-08 wraps this
- `digest.ts` (286 lines): monthly digest formatter — template patterns reusable for product formatting
- `CacheEntry` interface in `cache/types.ts`: product, paramsHash, resultJson, expiresAt

### Established Patterns
- Products should use `intelligence_cache` with TTL = time until next 25th (same as analysis pipeline)
- All SQL must use parameterized queries (SEC-06 from Phase 10)
- No raw data values in logs (SEC-07 from Phase 10)
- Python modules follow bridge pattern: JSON stdin → compute → JSON stdout
- TypeScript orchestration calls Python via `runPython()` bridge

### Integration Points
- `pipeline.ts`: validation step needs to be added after Granger, before composite
- `intelligence_cache`: products write formatted results here, Phase 12 tools read from here
- `normalized_monthly`: forward-fill change affects all normalizer Python modules
- `PythonScriptName` union type: may need new entries for validation module
- Existing analysis pipeline (25th monthly timer): validation step integrates here

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 11-intelligence-products*
*Context gathered: 2026-03-16*
