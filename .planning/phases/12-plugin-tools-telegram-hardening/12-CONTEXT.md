# Phase 12: Plugin Tools, Telegram Interface & Production Hardening - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Register 13 plugin tools in the lobsec-uae-re OpenClaw plugin (TOOL-01..13), callable via Telegram. Add area name fuzzy matching (QUAL-04), staleness warnings in responses (QUAL-02), collection health dashboard (QUAL-05). Harden production: nftables egress whitelist for all 28 source domains (SEC-03), credential redaction for new API key patterns (SEC-04), audit logging for collection runs (SEC-05). End-to-end integration verification.

Requirements: TOOL-01, TOOL-02, TOOL-03, TOOL-04, TOOL-05, TOOL-06, TOOL-07, TOOL-08, TOOL-09, TOOL-10, TOOL-11, TOOL-12, TOOL-13, QUAL-02, QUAL-04, QUAL-05, SEC-03, SEC-04, SEC-05

</domain>

<decisions>
## Implementation Decisions

### Tool Registration
- All 13 tools registered in lobsec-uae-re plugin (extend existing `register()` alongside `uae_collection_status`). Single plugin, single DB connection, single deploy
- Do NOT create a separate plugin. Matches how lobsec-tools bundles 8 tools in one plugin
- Tools use synchronous `api.registerTool()` with JSON Schema parameters (same pattern as lobsec-tools adapter)

### Product Tool Wiring (TOOL-01..08)
- Cache-first: check `intelligence_cache` for fresh result → return cached if valid TTL → call product query function on miss
- Each tool is a thin wrapper: resolve area → check cache → call product query → return formatted text
- TOOL-02 (distress) supports both modes: `uae_distress()` with no area → top 5 distressed areas ranked by score; `uae_distress('JVC')` → detailed breakdown for specific area

### Area Name Normalization (QUAL-04)
- Shared module: `src/tools/area-normalizer.ts` with `resolveArea(input)` → `{ canonical, confidence, alternatives }`
- Every tool calls this first. Single place to add aliases
- Canonical area list from DB: `SELECT DISTINCT area FROM normalized_monthly`. Grows automatically as data arrives
- Alias table for known abbreviations: JVC→Jumeirah Village Circle, JBR→Jumeirah Beach Residence, DIFC→Dubai International Financial Centre, DIP→Dubai Investment Park, JLT→Jumeirah Lake Towers, etc.
- Fuzzy fallback: Levenshtein distance with threshold (max 2 edits). Shows "Did you mean?" if distance 1-2, rejects if >2
- Ambiguous matches (e.g. "Jumeirah" matches multiple): list all matches, ask user to clarify. No auto-pick
- Inline correction for single fuzzy match: "Showing results for [corrected]. Did you mean [corrected]?"

### Staleness Warnings (QUAL-02)
- All product tool responses include data freshness footer (already built in format.ts `freshnessFooter()`)
- When any source feeding a product is >2x overdue, include explicit staleness warning in response

### Operational Tools
- TOOL-09 (raw data): Returns raw CSV-formatted data for any source within date range
- TOOL-10 (collection status): Extend existing `uae_collection_status` with staleness flags, next scheduled run, row counts — already partially built
- TOOL-11 (trigger collection): No auth restriction — any user can trigger. Loopback-only proxy limits exposure. Triggers collection for one source or all sources
- TOOL-12 (Granger test): Live computation via Python bridge — runs actual Granger causality on demand for custom signal+target pairs
- TOOL-13 (correlation): Live computation via Python bridge — runs cross-correlation for custom signal+target+max_lag

### Security Hardening
- SEC-03 nftables: Whitelist all 28 source domains upfront (including Tier B not yet active). No future firewall changes needed
- SEC-04 credential redaction: Extend existing redactor with new patterns (Reddit PRAW tokens, Google Maps API keys, Apify tokens, Dubai Pulse credentials)
- SEC-05 audit logging: All collection runs logged to existing audit.jsonl (source, timestamp, row count, success/failure)

### Claude's Discretion
- Exact alias table entries beyond the ones listed above
- Levenshtein vs Jaro-Winkler for fuzzy distance
- Specific nftables rule syntax and domain list
- New credential regex patterns for SEC-04
- TOOL-09 output format details (CSV columns, date filtering)
- How to detect "next scheduled run" for TOOL-10

</decisions>

<specifics>
## Specific Ideas

- TOOL-02 top-N mode is the "risk scanner" — user asks "what's distressed?" without knowing which area to check
- Area normalizer should handle Arabic transliterations eventually but English-only for now
- Collection trigger (TOOL-11) is useful for debugging — "run DLD collector now" to test after credential updates

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `lobsec-tools/dist/openclaw-adapter.js`: Complete tool registration pattern with JSON Schema helpers, `textResult()`, `getEnv()`, `Type.Object/String/Number/Optional`
- `lobsec-uae-re/dist/index.js`: Already has `register(api)` with DB init, collector registry, and 1 registered tool (`uae_collection_status`)
- `src/products/prod01..08.ts`: Each exports a query function returning formatted text — tools wrap these
- `src/products/format.ts`: `truncate4K()`, `freshnessFooter()`, `stalenessWarning()`, `trendArrow()`, `zoneLabel()`
- `intelligence_cache` table: TTL-based cache with params hash key — product tools check this first
- `CacheEntry` interface in `cache/types.ts`: product, paramsHash, resultJson, expiresAt

### Established Patterns
- Synchronous `api.registerTool()` — OpenClaw ignores async return values
- `group:plugins` in sandbox allow list auto-allows all plugin tools
- Python bridge: `runPython()` for analytical computation (Granger, correlation)
- Parameterized SQL for all user inputs (SEC-06)
- No raw data in logs (SEC-07)

### Integration Points
- `lobsec-uae-re/dist/index.js` `register()`: Add 12 more `api.registerTool()` calls
- `openclaw.json` `tools.sandbox.tools.allow`: May need tool names if `group:plugins` expansion fails
- `/etc/nftables.conf`: Add egress rules for 28 source domains
- `lobsec-security` plugin: Extend credential redactor regex array
- Existing `CollectorRegistry`: `triggerCollection(source)` method needed for TOOL-11

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 12-plugin-tools-telegram-hardening*
*Context gathered: 2026-03-16*
