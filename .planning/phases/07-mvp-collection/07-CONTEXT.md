# Phase 7: MVP Data Collection (Tier A + DEWA) - Context

**Gathered:** 2026-03-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Build 5 concrete data collectors (DLD sales, Ejari rentals, building permits, Bayut listings, PropertyFinder listings, DEWA connections) and the normalization pipeline that transforms raw collected data into monthly time-series in the `normalized_monthly` SQLite table. Includes gap detection, schema validation, volume validation, and area name mapping.

DARI Abu Dhabi (COLL-04) is **deferred** — UAE Pass auth complexity is not worth the MVP risk. Phase 7 ships with 5 sources (+1 PropertyFinder addition), not 6.

Requirements: COLL-01, COLL-02, COLL-03, COLL-05, COLL-15, NORM-01, NORM-02, NORM-03, NORM-04, NORM-05
Deferred: COLL-04 (DARI)

</domain>

<decisions>
## Implementation Decisions

### DARI Deferral
- COLL-04 (DARI Abu Dhabi) is deferred entirely — UAE Pass auth via Playwright is the single highest-complexity item in Phase 7
- Parked indefinitely (not just moved to Phase 9) — user doesn't have UAE Pass account confirmed
- Phase 7 validates the pipeline end-to-end with simpler sources first

### Source Access Strategy
- **Dubai Pulse** (DLD, Ejari, permits): Researcher to determine exact access method (direct CSV download vs API registration). Don't lock approach now
- **Bayut**: Direct Playwright scraping — no Apify cloud dependency. Free but potentially fragile
- **PropertyFinder**: Added as second listings source — scrape simultaneously with Bayut for cross-validation
- **DEWA**: Press release scraping — fragile by nature, researcher to evaluate feasibility
- **No multi-source fallbacks**: Each collector targets one source. If blocked/unavailable, fail gracefully with Telegram alert — don't build cascading fallback logic in MVP

### Listings Collection (Bayut + PropertyFinder)
- Two separate collectors: `bayut-listings` and `propertyfinder-listings` registered independently in CollectorRegistry
- Each can fail independently without affecting the other
- Geographic scope: **all Dubai areas** — comprehensive coverage, not limited to top investment areas
- Core listing metrics per area: active listing count, median asking price, median days on market (DOM), price reduction count

### Normalization Pipeline Architecture
- **Two-step pipeline**: Collectors write raw files only → separate normalization step reads raw files, resamples to monthly, inserts to `normalized_monthly`
- **Auto-trigger**: Normalization runs automatically after collection completes (not a separate manual step)
- **One Python call per source**: Each source has its own Python normalization module (e.g., `normalize_dld.py`, `normalize_bayut.py`). Isolated, source-specific logic
- **Upsert semantics**: Normalization DELETEs existing rows for source+measurement_date range, then INSERTs new. Idempotent — re-running normalization always reflects latest raw data
- **Gap detection** (NORM-03): Runs during normalization, not as a separate health check. After normalizing, check the time series for gaps exceeding 2x expected frequency
- **Schema validation** (NORM-04): **Hard error** — if raw data fails column/type/range validation, collection is marked as failed, no raw file saved, Telegram alert with mismatch details
- **Volume validation** (NORM-05): Skipped for first N runs (4 successful collections needed to build baseline). Gradually builds rolling average

### Metric Granularity
- **DLD sales** (COLL-01): Aggregated by (area, property_type). Extended metrics: transaction volume (count), median price (AED), median price per sqft, total value (AED), 25th/75th percentile price, YoY change, MoM change
- **Ejari rentals** (COLL-02): Same (area, property_type) granularity as DLD sales with rental-specific derived metrics: renewal_rate, avg_rent_per_sqft, rent_YoY_change
- **Building permits** (COLL-03): Classified residential vs commercial, track permit withdrawal/expiry
- **Bayut/PropertyFinder listings** (COLL-05): Core metrics per area: active listing count, median asking price, median DOM, price reduction count
- **DEWA** (COLL-15): Per-area breakdown required — researcher must validate whether DEWA publishes area-level data. If not available, revisit granularity decision

### Area Name Mapping
- Build a canonical area name mapping table in Phase 7 (not deferred to Phase 12)
- **Static seed list**: Ship with a curated list of ~100 Dubai areas with canonical names and known aliases (JVC, JBR, DIFC, etc.)
- Normalization uses the mapping to standardize area names across all sources
- Extend the list as new areas appear in collected data
- QUAL-04 (Phase 12) adds fuzzy matching for Telegram queries — Phase 7 builds the underlying mapping data

### Claude's Discretion
- Exact Playwright scraping patterns for Bayut, PropertyFinder, and DEWA
- Raw file format per source (CSV, JSON, or HTML snapshots)
- Python normalization module internal structure
- Area seed list compilation (which ~100 areas to include)
- Volume validation threshold (how many runs = "first N")
- Timeout settings per collector type

</decisions>

<specifics>
## Specific Ideas

- Reuse existing Playwright from Examy QA (already installed at system level) for Bayut/PropertyFinder/DEWA scraping
- The playbook at `.planning/uae-re-playbook.md` has detailed source URLs, field mappings, and collection strategies for all 28 sources — use Phase 7 sources as primary reference
- DLD and Ejari come from the same Dubai Pulse CSV dataset — COLL-01 and COLL-02 can share the same download step, then filter by `trans_group_en` (Sale vs Rent)
- PropertyFinder was user's addition — not in original requirements. Register as a new collector source alongside Bayut for cross-validation of listing data

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `SourceCollector` base class (`packages/uae-re/src/collectors/base.ts`): Extend with concrete collectors for each source — implement `collect()` method
- `CollectorRegistry` (`packages/uae-re/src/collectors/registry.ts`): Register all 5+ collectors, `runAll()` or `runByFrequency()` for orchestration
- `runPython()` bridge (`packages/uae-re/src/analytics/bridge.ts`): Call per-source normalization Python modules
- `insertRawSource()`, `insertNormalized()`, `queryNormalized()` (`packages/uae-re/src/db/queries.ts`): Existing queries for raw source metadata and normalized data
- `insertCollectionLog()`, `getLatestCollection()` (`packages/uae-re/src/db/queries.ts`): Audit logging for collection runs
- `CircuitBreaker` + `retryWithBackoff` (`@lobsec/shared`): Already wired into SourceCollector base class
- Playwright (system-level): Already installed for Examy QA — reuse for web scraping collectors

### Established Patterns
- Collector pattern: Extend `SourceCollector`, implement `collect()`, return `{filePath, rowCount}`, base handles retry/circuit breaker/logging
- Python bridge: `runPython('normalize_dld', inputData)` → Python module reads stdin JSON, outputs stdout JSON
- Plugin registration: `api.registerTool()` with JSON Schema parameters (for future Phase 12 tools)
- Raw file storage: `/opt/lobsec/data/raw/{source-name}/{date-based-filename}`

### Integration Points
- SQLite database: `/opt/lobsec/data/uae-re.db` — new `area_names` table for canonical mapping
- Raw data directory: `/opt/lobsec/data/raw/` — new subdirectories per source
- Python package: `packages/uae-re/python/uae_re/` — new normalization modules
- CollectorRegistry: Register 5+ concrete collectors at plugin startup
- Normalization auto-trigger: Wire into registry's `runAll()` completion callback

</code_context>

<deferred>
## Deferred Ideas

- **DARI Abu Dhabi** (COLL-04) — UAE Pass auth is too complex for MVP. Parked indefinitely until account access and auth strategy are resolved
- **Embedding/vectorization of collected data** — Not needed for structured time-series data. SQL queries via plugin tools (Phase 12) are the correct access pattern. Revisit only if unstructured text search is needed later

</deferred>

---

*Phase: 07-mvp-collection*
*Context gathered: 2026-03-11*
