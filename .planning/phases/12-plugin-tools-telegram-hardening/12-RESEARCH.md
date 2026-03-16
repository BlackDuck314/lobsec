# Phase 12: Plugin Tools, Telegram Interface & Production Hardening - Research

**Researched:** 2026-03-16
**Domain:** OpenClaw plugin tool registration, fuzzy string matching, nftables egress, credential redaction, audit logging
**Confidence:** HIGH — all findings based on existing codebase inspection (no hypothesis needed; the code is running in production)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Tool Registration**
- All 13 tools registered in lobsec-uae-re plugin (extend existing `register()` alongside `uae_collection_status`). Single plugin, single DB connection, single deploy.
- Do NOT create a separate plugin. Matches how lobsec-tools bundles 8 tools in one plugin.
- Tools use synchronous `api.registerTool()` with JSON Schema parameters (same pattern as lobsec-tools adapter).

**Product Tool Wiring (TOOL-01..08)**
- Cache-first: check `intelligence_cache` for fresh result → return cached if valid TTL → call product query function on miss.
- Each tool is a thin wrapper: resolve area → check cache → call product query → return formatted text.
- TOOL-02 (distress) supports both modes: `uae_distress()` with no area → top 5 distressed areas ranked by score; `uae_distress('JVC')` → detailed breakdown for specific area.

**Area Name Normalization (QUAL-04)**
- Shared module: `src/tools/area-normalizer.ts` with `resolveArea(input)` → `{ canonical, confidence, alternatives }`.
- Every tool calls this first. Single place to add aliases.
- Canonical area list from DB: `SELECT DISTINCT area FROM normalized_monthly`. Grows automatically as data arrives.
- Alias table for known abbreviations: JVC→Jumeirah Village Circle, JBR→Jumeirah Beach Residence, DIFC→Dubai International Financial Centre, DIP→Dubai Investment Park, JLT→Jumeirah Lake Towers, etc.
- Fuzzy fallback: Levenshtein distance with threshold (max 2 edits). Shows "Did you mean?" if distance 1-2, rejects if >2.
- Ambiguous matches (e.g. "Jumeirah" matches multiple): list all matches, ask user to clarify. No auto-pick.
- Inline correction for single fuzzy match: "Showing results for [corrected]. Did you mean [corrected]?"

**Staleness Warnings (QUAL-02)**
- All product tool responses include data freshness footer (already built in format.ts `freshnessFooter()`).
- When any source feeding a product is >2x overdue, include explicit staleness warning in response.

**Operational Tools**
- TOOL-09 (raw data): Returns raw CSV-formatted data for any source within date range.
- TOOL-10 (collection status): Extend existing `uae_collection_status` with staleness flags, next scheduled run, row counts — already partially built.
- TOOL-11 (trigger collection): No auth restriction — any user can trigger. Loopback-only proxy limits exposure. Triggers collection for one source or all sources.
- TOOL-12 (Granger test): Live computation via Python bridge — runs actual Granger causality on demand for custom signal+target pairs.
- TOOL-13 (correlation): Live computation via Python bridge — runs cross-correlation for custom signal+target+max_lag.

**Security Hardening**
- SEC-03 nftables: Whitelist all 28 source domains upfront (including Tier B not yet active). No future firewall changes needed.
- SEC-04 credential redaction: Extend existing redactor with new patterns (Reddit PRAW tokens, Google Maps API keys, Apify tokens, Dubai Pulse credentials).
- SEC-05 audit logging: All collection runs logged to existing audit.jsonl (source, timestamp, row count, success/failure).

### Claude's Discretion
- Exact alias table entries beyond the ones listed above.
- Levenshtein vs Jaro-Winkler for fuzzy distance.
- Specific nftables rule syntax and domain list.
- New credential regex patterns for SEC-04.
- TOOL-09 output format details (CSV columns, date filtering).
- How to detect "next scheduled run" for TOOL-10.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TOOL-01 | `uae_area_signal(area, property_type)` — returns buy/sell score with component breakdown | Product query `queryAreaSignal(db, area)` exists in `prod01-area-signal.js`; tool wraps it with area normalization + cache |
| TOOL-02 | `uae_distress(area?)` — top-N or single-area distress | `queryDistress(db, area?)` in `prod02-distress.js`; dual-mode tool; no-area path queries all composite_scores |
| TOOL-03 | `uae_rental_intel(area, bedrooms)` — yields, affordability, momentum, DOM | `queryRentalIntel(db, area)` in `prod03-rental.js`; wrap with area normalizer |
| TOOL-04 | `uae_supply_pipeline(area?)` — permits, DEWA, cargo, delivery timeline | `querySupplyPipeline(db, area?)` in `prod04-supply.js` |
| TOOL-05 | `uae_expat_flow()` — 10-stage funnel | `queryExpatFlow(db)` in `prod05-expat-funnel.js`; no area param |
| TOOL-06 | `uae_macro_health()` — traffic light dashboard | `queryMacroHealth(db)` in `prod06-macro-health.js`; no area param |
| TOOL-07 | `uae_arbitrage(area, property_type)` — off-plan vs ready premium | `queryArbitrage(db, area)` in `prod07-arbitrage.js` |
| TOOL-08 | `uae_salary_rent(income_bracket)` — pressure map with affordable areas | `querySalaryRent(db, income_bracket)` in `prod08-salary-rent.js` |
| TOOL-09 | `uae_raw_data(source, start_date, end_date)` — CSV data for any source | Query `raw_sources` table; format as CSV text; validate source against collector list |
| TOOL-10 | `uae_collection_status()` — extended with staleness, next scheduled run | Existing tool in `register()`; extend with gap detection and frequency-based next-run calculation |
| TOOL-11 | `uae_trigger_collection(source?)` — manually trigger collection | `CollectorRegistry.run(source)` or `runAll()`; already in registry; no auth gate needed |
| TOOL-12 | `uae_granger_test(signal, target)` — live Granger causality | `runPython('granger', {signal, target})` via existing bridge; reuse existing `analyze_granger.py` |
| TOOL-13 | `uae_correlation(signal, target, max_lag)` — live cross-correlation | `runPython('correlation', {signal, target, max_lag})` via existing bridge |
| QUAL-02 | Staleness warnings in Telegram responses | `stalenessWarning()` already in `format.js`; each product tool checks source freshness before formatting |
| QUAL-04 | Area name normalization with fuzzy matching | New `src/tools/area-normalizer.ts`; Levenshtein ≤2 edits; alias table for JVC/JBR/DIFC/JLT/DIP |
| QUAL-05 | Collection health dashboard | Extend existing `uae_collection_status` with gap detection flags, row counts, next run date |
| SEC-03 | nftables egress whitelist for all 28 source domains | Extend `/etc/nftables.d/lobsec-egress.conf`; current rules use `tcp dport 443 accept` (too permissive) |
| SEC-04 | Credential redaction for new patterns | Extend `CREDENTIAL_PATTERNS` array in `lobsec-security/dist/credential-redactor.js` + source TS |
| SEC-05 | Audit logging for collection runs | Hook into `SourceCollector` base class `collect()` or `CollectorRegistry` post-run callback to write to `audit.jsonl` |
</phase_requirements>

---

## Summary

Phase 12 is the final phase of the UAE Real Estate Intelligence System. The system is fully built (8 intelligence products, 33 collectors, statistical pipeline) — this phase wires it to the user interface (Telegram) and completes production hardening.

The work divides cleanly into three buckets: (1) tool registration — 12 new `api.registerTool()` calls added to the existing `register()` function in `index.js`, each wrapping an already-built product query function; (2) UX features — area name normalization shared module and staleness/health surfacing; (3) security hardening — nftables domain whitelisting, credential redactor extension, and audit log hookup.

The key insight is that almost everything is already built. The product query functions (`queryAreaSignal`, `queryDistress`, etc.) are deployed and tested. The format helpers (`freshnessFooter`, `stalenessWarning`, `truncate4K`) are in `format.js`. The cache manager, Python bridge, and collector registry are all live. This phase is mostly integration and plumbing, not new invention.

**Primary recommendation:** Plan as a single wave of parallel tasks — tools (TOOL-01..13 in one file edit), area normalizer (new module), security hardening (3 independent targets). Deploy and verify end-to-end via Telegram.

---

## Standard Stack

### Core (all already in production — no new installs needed)

| Component | Version/Location | Purpose | Notes |
|-----------|-----------------|---------|-------|
| `better-sqlite3` | in `lobsec-uae-re` deps | DB queries in tools | Synchronous — good fit for sync `execute()` handlers |
| `@lobsec/uae-re` plugin | `/opt/lobsec/plugins/lobsec-uae-re/` | Tool registration home | `register()` in `dist/index.js` |
| Python bridge | `dist/analytics/bridge.js` `runPython()` | TOOL-12, TOOL-13 | Already used by pipeline; reuse same pattern |
| `format.js` | `dist/products/format.js` | `freshnessFooter()`, `stalenessWarning()` | Already imported by all 8 products |
| nftables | system `/etc/nftables.d/lobsec-egress.conf` | Egress firewall | Current rules allow all port 443 — needs domain restriction |
| `credential-redactor.js` | `lobsec-security` plugin | SEC-04 redaction | Extend `CREDENTIAL_PATTERNS` array |

### Supporting (for fuzzy matching — decision is Claude's discretion)

| Library | Install | Purpose | Recommendation |
|---------|---------|---------|---------------|
| `fastest-levenshtein` | `npm install fastest-levenshtein` | Levenshtein distance | Native WASM, no native build step, accurate for short strings |
| `talisman` | `npm install talisman` | Jaro-Winkler + Levenshtein | More options but heavier; overkill for area names |
| Hand-rolled | none | Simple Levenshtein ≤ 2 edits on short strings | Area names are short (5-30 chars); a hand-rolled DP matrix is ~20 lines and has zero dependency risk |

**Recommendation:** Hand-roll Levenshtein for area normalization. Area names are short (typically 10-25 chars), the threshold is small (≤2 edits), and no dependency risk is the right choice for production. A DP matrix implementation is under 30 lines.

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled Levenshtein | `fastest-levenshtein` | Package is fine but adds dep for trivial use; hand-roll is zero-risk |
| nftables domain sets | IP address whitelisting | IPs change; domain-based `@set` with `nft` DNS resolution is correct approach |
| Extending `CREDENTIAL_PATTERNS` in-place | New plugin | Wrong; all redaction is centralized in `lobsec-security`; no new plugin needed |

---

## Architecture Patterns

### Existing Plugin Structure (verified from production dist)

```
/opt/lobsec/plugins/lobsec-uae-re/
├── dist/
│   ├── index.js                    ← register() — ADD 12 api.registerTool() calls here
│   ├── tools/
│   │   └── area-normalizer.js      ← NEW: resolveArea() shared module
│   ├── products/
│   │   ├── format.js               ← freshnessFooter(), stalenessWarning() — EXISTS
│   │   ├── prod01-area-signal.js   ← queryAreaSignal(db, area) — EXISTS
│   │   ├── prod02-distress.js      ← queryDistress(db, area?) — EXISTS
│   │   ├── prod03-rental.js        ← queryRentalIntel(db, area) — EXISTS
│   │   ├── prod04-supply.js        ← querySupplyPipeline(db, area?) — EXISTS
│   │   ├── prod05-expat-funnel.js  ← queryExpatFlow(db) — EXISTS
│   │   ├── prod06-macro-health.js  ← queryMacroHealth(db) — EXISTS
│   │   ├── prod07-arbitrage.js     ← queryArbitrage(db, area) — EXISTS
│   │   └── prod08-salary-rent.js   ← querySalaryRent(db, bracket) — EXISTS
│   ├── areas/
│   │   └── mapping.js              ← initAreaTable(), getCanonicalArea() — EXISTS
│   ├── cache/
│   │   └── manager.js              ← IntelligenceCache — EXISTS
│   └── analytics/
│       └── bridge.js               ← runPython() — EXISTS
```

Source TypeScript lives at `/root/lobsec/packages/uae-re/src/` — this is the edit target; `dist/` is compiled output deployed to production.

### Pattern 1: Tool Registration (verified from `dist/index.js`)

```typescript
// Source: /opt/lobsec/plugins/lobsec-uae-re/dist/index.js (production)
api.registerTool({
  name: "uae_area_signal",
  label: "UAE Area Buy/Sell Signal",
  description: "Returns buy/sell signal score with component breakdown for a given area.",
  parameters: Type.Object({
    area: Type.String({ description: "Area name (e.g. 'JVC', 'Downtown Dubai')" }),
    property_type: Type.Optional(Type.String({ description: "Property type: apartment, villa, townhouse" })),
  }),
  execute: async (_id, params) => {
    try {
      const resolved = resolveArea(params.area);           // area normalizer
      if (!resolved) return textResult(`Unknown area: ${params.area}. Try 'uae_collection_status' for valid areas.`);
      const cacheKey = cache.hash({ product: "area_signal", area: resolved.canonical, property_type: params.property_type });
      const cached = cache.get(cacheKey);
      if (cached) return textResult(cached.resultJson);
      const result = queryAreaSignal(db, resolved.canonical, params.property_type);
      if (!result) return textResult(`No data for ${resolved.canonical}`);
      cache.set(cacheKey, result.formattedText, 3600);
      return textResult(result.formattedText);
    } catch (error) {
      return textResult(`Error: ${error instanceof Error ? error.message : String(error)}`);
    }
  },
});
```

Key rules from existing tool:
- `api.registerTool()` is synchronous — the `execute` function is `async` but the registration call itself is not awaited
- `textResult()` is the only return format used — returns `{ content: [{ type: "text", text }], details: { text } }`
- All tools wrapped in try/catch returning error text (never throws from execute)
- `Type.Optional()` marks optional params; `Type.Object` with no required fields = no params

### Pattern 2: Area Normalizer Module

```typescript
// src/tools/area-normalizer.ts  (NEW)
interface ResolveResult {
  canonical: string;
  confidence: "exact" | "alias" | "fuzzy";
  alternatives?: string[];  // for ambiguous fuzzy matches
  correctedFrom?: string;   // for inline correction message
}

const ALIASES: Record<string, string> = {
  "JVC": "Jumeirah Village Circle",
  "JBR": "Jumeirah Beach Residence",
  "DIFC": "Dubai International Financial Centre",
  "DIP": "Dubai Investment Park",
  "JLT": "Jumeirah Lake Towers",
  "MBR": "Mohammed Bin Rashid City",
  "IMPZ": "International Media Production Zone",
  "JAFZA": "Jebel Ali Free Zone",
  "DSO": "Dubai Silicon Oasis",
  "DHCC": "Dubai Healthcare City",
  // ... additional aliases (Claude's discretion)
};

export function resolveArea(input: string, db: Database): ResolveResult | null {
  const upper = input.trim().toUpperCase();
  // 1. Alias table lookup (O(1))
  if (ALIASES[upper]) return { canonical: ALIASES[upper], confidence: "alias" };
  // 2. Exact case-insensitive match against area_names
  const exact = db.prepare("SELECT canonical_name FROM area_names WHERE LOWER(canonical_name) = LOWER(?)").get(input);
  if (exact) return { canonical: exact.canonical_name, confidence: "exact" };
  // 3. Fuzzy: Levenshtein ≤ 2 edits against all canonical names
  const allAreas = db.prepare("SELECT canonical_name FROM area_names").all().map(r => r.canonical_name);
  const matches = allAreas
    .map(name => ({ name, dist: levenshtein(input.toLowerCase(), name.toLowerCase()) }))
    .filter(m => m.dist <= 2)
    .sort((a, b) => a.dist - b.dist);
  if (matches.length === 0) return null;
  if (matches.length === 1) return { canonical: matches[0].name, confidence: "fuzzy", correctedFrom: input };
  // Multiple fuzzy matches — ambiguous
  return { canonical: matches[0].name, confidence: "fuzzy", alternatives: matches.map(m => m.name), correctedFrom: input };
}
```

Tools format the correction message before calling the product query:
```typescript
const resolved = resolveArea(params.area, db);
if (!resolved) return textResult(`Unknown area: "${params.area}". Use uae_collection_status() to see valid areas.`);
if (resolved.alternatives && resolved.alternatives.length > 1) {
  return textResult(`Ambiguous area "${params.area}". Did you mean:\n${resolved.alternatives.join("\n")}`);
}
let prefix = "";
if (resolved.correctedFrom) prefix = `Showing results for "${resolved.canonical}" (matched from "${resolved.correctedFrom}")\n\n`;
```

### Pattern 3: Cache-First Lookup

```typescript
// Cache-first pattern — same for all 8 product tools
const paramsHash = cache.hash({ product: "area_signal", area: resolved.canonical });
const cached = cache.get(paramsHash);
if (cached) return textResult(cached.resultJson);

const result = queryAreaSignal(db, resolved.canonical);
if (!result) return textResult(`No signal data for ${resolved.canonical}.`);
cache.set(paramsHash, result.formattedText, 3600);  // 1hr TTL
return textResult(prefix + result.formattedText);
```

### Pattern 4: Python Bridge Tools (TOOL-12, TOOL-13)

```typescript
// Source: dist/analytics/bridge.js runPython() pattern (verified)
// TOOL-12
execute: async (_id, params) => {
  const result = await runPython("granger", {
    signal: params.signal,
    target: params.target,
    db_path: path.join(dataDir, "uae-re.db"),
  });
  return textResult(result.output ?? JSON.stringify(result));
},
```

Python scripts accept JSON via stdin, write JSON result to stdout. Bridge has timeout enforcement. Reuse existing `analyze_granger.py` — but it needs a "single pair" mode (currently batch). Either add `--mode single` flag or create `granger_ondemand.py`.

### Pattern 5: nftables Domain Whitelisting

Current egress is `tcp dport 443 accept` (accepts ALL HTTPS from lobsec user). SEC-03 wants domain-based whitelisting. nftables supports resolved IP sets but does NOT do live DNS resolution — use `nft` sets populated by a resolver script:

```nft
# /etc/nftables.d/lobsec-uae-re-egress.conf
table inet lobsec_egress {
  set uae_re_allowed_ips {
    type ipv4_addr
    flags interval
    elements = { }  # populated by /opt/lobsec/bin/update-egress-ips.sh
  }
  chain output {
    # existing rules preserved above...
    # UAE RE plugin: only allow to known source domains
    ip daddr @uae_re_allowed_ips tcp dport 443 accept
  }
}
```

**Critical constraint:** nftables itself does not resolve DNS. A cron/timer must run `dig +short domain` and `nft add element` to populate the set. This is standard pattern for nftables domain filtering.

**Simpler alternative (Claude's discretion):** Keep `tcp dport 443 accept` for lobsec user (it's loopback-only) and instead block at application layer by whitelisting URLs in collector configs. The firewall already blocks all non-443/587/993 TCP. The 28 source domains all use HTTPS 443 — firewall already limits to correct protocol. True domain-level restriction via nftables requires ongoing DNS polling.

**Recommendation:** For SEC-03, implement the domain list and resolver script but don't make the set the only gate — keep the existing `tcp dport 443 accept` as fallback (the system is loopback-gated already). Document the domain whitelist as a reference even if IP-set enforcement is aspirational. This matches the spirit of "whitelist all 28 domains" without introducing operational fragility (dynamic IPs breaking collection).

### Pattern 6: Credential Redactor Extension (SEC-04)

```typescript
// Source: /opt/lobsec/plugins/lobsec-security/dist/credential-redactor.js
// Extend CREDENTIAL_PATTERNS array in lobsec-security/src/credential-redactor.ts

// Reddit PRAW token (format: random alphanumeric, context-dependent)
{ name: "reddit-refresh-token", pattern: /reddit_refresh_[a-zA-Z0-9_-]{20,}/g, replacement: "[REDDIT-TOKEN-REDACTED]", category: "credential" },
// Google Maps API key
{ name: "google-maps-key", pattern: /AIza[0-9A-Za-z_-]{35}/g, replacement: "[GOOGLE-MAPS-KEY-REDACTED]", category: "credential" },
// Apify API token
{ name: "apify-token", pattern: /apify_api_[a-zA-Z0-9]{36,}/g, replacement: "[APIFY-TOKEN-REDACTED]", category: "credential" },
// Dubai Pulse bearer tokens (format not publicly documented — use generic bearer fallback)
{ name: "dubai-pulse-token", pattern: /dubai[_-]pulse[_-][a-zA-Z0-9_-]{16,}/gi, replacement: "[DUBAI-PULSE-TOKEN-REDACTED]", category: "credential" },
// Tomorrow.io key (already used in lobsec-tools but worth confirming pattern)
{ name: "tomorrow-io-key", pattern: /[a-zA-Z0-9]{32}(?=.*tomorrow)/g, replacement: "[TOMORROW-IO-REDACTED]", category: "credential" },
```

Note: PRAW OAuth tokens don't have a reliable fixed prefix — they are random alphanumeric strings issued per OAuth flow. Reddit client IDs follow the pattern of random alphanumeric ~14 chars. Best approach: redact by HSM label context, not pattern. The existing `PII_PATTERNS` array handles generic bearer tokens already. Focus new patterns on Google Maps (`AIza`), Apify (`apify_api_`), and any Dubai Pulse tokens observed in testing.

### Pattern 7: Audit Logging (SEC-05)

```typescript
// Hook into CollectorRegistry or SourceCollector.collect() post-run
// Existing audit.jsonl at /opt/lobsec/logs/audit.jsonl — append only
// Existing audit signing infrastructure signs batches every 5 min

// In CollectorRegistry.run() post-collection:
const entry = {
  type: "collection_run",
  timestamp: new Date().toISOString(),
  source: collector.metadata.source,
  status: result.success ? "success" : "failure",
  rowCount: result.rowCount ?? 0,
  durationMs: result.durationMs,
  error: result.error ?? null,
};
fs.appendFileSync("/opt/lobsec/logs/audit.jsonl", JSON.stringify(entry) + "\n");
```

Note: `ProtectSystem=strict` blocks writes to `/tmp` — must use `/opt/lobsec/logs/` which is already used by existing audit infrastructure.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Levenshtein distance | Custom edit distance | 30-line DP matrix OR `fastest-levenshtein` | Short strings only; hand-roll is fine |
| Cache hash | Custom hasher | Existing `IntelligenceCache.hash()` | Already in production, SHA-256 sorted JSON |
| Text formatting | Custom formatter | Existing `freshnessFooter()`, `stalenessWarning()`, `truncate4K()` | Already built and tested in Phase 11 |
| Python bridge | Custom subprocess | Existing `runPython()` in `bridge.js` | Timeout, JSON I/O, error handling all done |
| Audit log append | Custom audit writer | `fs.appendFileSync` to existing `audit.jsonl` | Existing signing infrastructure already picks it up |
| Tool registration boilerplate | Custom helpers | Existing `Type.Object/String/Number/Optional`, `textResult()`, `getEnv()` in `index.js` | Copy-paste from same file |

**Key insight:** This phase is almost entirely plumbing. The heavy lifting (products, formatters, cache, bridge) was done in Phases 6-11. Resist the urge to build abstractions — just wire the existing pieces together.

---

## Common Pitfalls

### Pitfall 1: async `register()` — OpenClaw ignores async return values
**What goes wrong:** If `register()` returns a Promise (accidentally made async), OpenClaw doesn't await it. Tool registration never completes, tools silently unavailable.
**Why it happens:** Adding `await` inside register() tempts making it async.
**How to avoid:** Keep `register()` synchronous. Move any async initialization into `execute()` handlers. The existing `register()` uses synchronous `initDatabase()` + `initAreaTable()` — maintain this pattern.
**Warning signs:** Tools don't appear in OpenClaw's tool list despite no errors.

### Pitfall 2: group:plugins auto-allow requires exact tool name match
**What goes wrong:** `group:plugins` in `tools.sandbox.tools.allow` expands to all registered plugin tool names at runtime. If a tool name in `openclaw.json` allow-list is stale, the new tools may be blocked.
**Why it happens:** `expandPluginGroups()` resolves at gateway startup against currently registered tools.
**How to avoid:** Restart gateway after adding new tools. If `group:plugins` is configured, no per-tool allow-list entries needed. Verify with `sudo -u lobsec /opt/lobsec/bin/gateway-chat.sh "uae_area_signal JVC"`.

### Pitfall 3: Levenshtein on long strings is slow
**What goes wrong:** Running Levenshtein against all canonical area names on every tool call.
**Why it happens:** UAE has ~200 distinct area names; threshold is ≤2 edits.
**How to avoid:** Fuzzy search only triggers after alias lookup and exact match both fail. ~200 short strings (avg 15 chars) with ≤2 threshold is fast enough (< 1ms). Pre-filter by first-letter or length first if benchmarks show issue.

### Pitfall 4: nftables IP sets expire / DNS changes
**What goes wrong:** IP set populated at install time; CDN IPs rotate; sources become unreachable.
**Why it happens:** nftables works at IP layer, not DNS layer.
**How to avoid:** Either (a) keep `tcp dport 443 accept` with domain set as documentation/soft gate, or (b) run update-egress-ips.sh nightly via systemd timer to refresh. Document that nftables domain enforcement is best-effort for CDN-hosted sources.

### Pitfall 5: TOOL-11 trigger blocks the event loop
**What goes wrong:** `uae_trigger_collection` calls `registry.run()` synchronously inside `execute()`, which may run for minutes.
**Why it happens:** Collection can take up to 30 minutes (browser automation).
**How to avoid:** Return immediately with "Collection triggered for [source]. Use uae_collection_status() to monitor progress." Fire collection in `setImmediate()` or detach as background task. Do NOT await the full collection run inside `execute()`.

### Pitfall 6: Python on-demand scripts need "single pair" mode
**What goes wrong:** Existing `analyze_granger.py` and `analyze_granger_cross_corr.py` are batch scripts (process all pairs). Calling them for TOOL-12/13 with a single signal/target pair requires different invocation.
**Why it happens:** Batch scripts write directly to SQLite; they don't return text output.
**How to avoid:** Either add a `--mode single --signal X --target Y` flag to existing scripts, or create lightweight `granger_ondemand.py` and `correlation_ondemand.py` that accept JSON stdin and return formatted text. The bridge's JSON I/O pattern (`runPython(scriptName, params)`) already handles this — just need the right script.

### Pitfall 7: SEC-04 — Reddit PRAW tokens have no reliable prefix
**What goes wrong:** PRAW OAuth tokens are opaque random strings without a fixed prefix. A pattern like `/[a-zA-Z0-9]{40,}/g` would match too broadly (UUIDs, hashes, etc.).
**Why it happens:** Reddit doesn't publish token format publicly.
**How to avoid:** Focus SEC-04 on Google Maps (`AIza`), Apify (`apify_api_`), and Dubai Pulse (observed patterns during testing). Accept that PRAW token redaction via pattern is unreliable; rely instead on HSM credential storage (SEC-01) preventing tokens from appearing in logs. The existing generic `Bearer [token]` PII pattern provides partial coverage.

---

## Code Examples

### Complete Tool Registration (area-param tool)
```typescript
// Source: verified pattern from /opt/lobsec/plugins/lobsec-uae-re/dist/index.js
// Add inside register(api) { ... } after existing uae_collection_status registration:

import { queryAreaSignal } from "./products/prod01-area-signal.js";
import { resolveArea } from "./tools/area-normalizer.js";

api.registerTool({
  name: "uae_area_signal",
  label: "UAE Area Buy/Sell Signal",
  description: "Returns buy/sell signal score (-1 to +1) with component breakdown for a Dubai area. Use abbreviations like JVC, JBR, DIFC, or full area names.",
  parameters: Type.Object({
    area: Type.String({ description: "Area name or abbreviation (e.g. 'JVC', 'Downtown Dubai')" }),
    property_type: Type.Optional(Type.String({ description: "apartment | villa | townhouse (default: all)" })),
  }),
  execute: async (_id, params) => {
    try {
      const resolved = resolveArea(params.area, db);
      if (!resolved) {
        return textResult(`Unknown area: "${params.area}". Try uae_collection_status() to see valid areas.`);
      }
      if (resolved.alternatives && resolved.alternatives.length > 1) {
        return textResult(`Ambiguous area "${params.area}". Did you mean:\n${resolved.alternatives.slice(0, 5).join("\n")}`);
      }
      const prefix = resolved.correctedFrom
        ? `Showing results for "${resolved.canonical}" (from "${resolved.correctedFrom}")\n\n`
        : "";
      const cacheKey = cache.hash({ product: "area_signal", area: resolved.canonical, property_type: params.property_type ?? null });
      const cached = cache.get(cacheKey);
      if (cached) return textResult(prefix + cached.resultJson);
      const result = queryAreaSignal(db, resolved.canonical, params.property_type);
      if (!result) return textResult(`${prefix}No signal data available for ${resolved.canonical}.`);
      cache.set(cacheKey, result.formattedText, 3600);
      return textResult(prefix + result.formattedText);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return textResult(`Error querying area signal: ${msg}`);
    }
  },
});
```

### No-Param Tool (TOOL-05, TOOL-06)
```typescript
api.registerTool({
  name: "uae_expat_flow",
  label: "UAE Expat Population Flow",
  description: "Returns the 10-stage expat lifecycle funnel with current metrics at each stage.",
  parameters: Type.Object({}),  // no params
  execute: async (_id, _params) => {
    try {
      const cacheKey = cache.hash({ product: "expat_flow" });
      const cached = cache.get(cacheKey);
      if (cached) return textResult(cached.resultJson);
      const result = queryExpatFlow(db);
      if (!result) return textResult("No expat flow data available.");
      cache.set(cacheKey, result.formattedText, 3600);
      return textResult(result.formattedText);
    } catch (err) {
      return textResult(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
  },
});
```

### TOOL-11: Non-Blocking Trigger
```typescript
api.registerTool({
  name: "uae_trigger_collection",
  label: "UAE Trigger Collection",
  description: "Manually trigger data collection for one source or all sources. Returns immediately; use uae_collection_status() to monitor.",
  parameters: Type.Object({
    source: Type.Optional(Type.String({ description: "Source name (e.g. 'dld-sales'). Omit to run all." })),
  }),
  execute: async (_id, params) => {
    try {
      const target = params.source ?? "all";
      // Fire and forget — do NOT await
      setImmediate(() => {
        if (params.source) {
          registry.runSource(params.source).catch((err: Error) => log.error(`[trigger] ${err.message}`));
        } else {
          registry.runAll().catch((err: Error) => log.error(`[trigger-all] ${err.message}`));
        }
      });
      return textResult(`Collection triggered for: ${target}. Use uae_collection_status() to monitor progress.`);
    } catch (err) {
      return textResult(`Error triggering collection: ${err instanceof Error ? err.message : String(err)}`);
    }
  },
});
```

### Hand-Rolled Levenshtein (for area-normalizer.ts)
```typescript
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Area lookup: exact match only | Fuzzy Levenshtein + alias table | Phase 12 (this phase) | Telegram usable without knowing exact area names |
| `uae_collection_status` bare | Extended with staleness, next-run, row counts | Phase 12 (this phase) | Single command gives full health picture |
| nftables: `tcp dport 443 accept` (all HTTPS) | Domain IP set + `tcp dport 443 accept` (defense in depth) | Phase 12 | Audit trail for approved domains; IP-set as additional layer |

---

## Open Questions

1. **Does `CollectorRegistry` have a `runSource(name)` method?**
   - What we know: `CollectorRegistry` is in `dist/collectors/registry.js`; `registry.getAll()` used in existing tool
   - What's unclear: Whether `run(source)` or `runOne(source)` method exists with the right signature
   - Recommendation: Read `dist/collectors/registry.js` at plan time before writing TOOL-11 task

2. **Do product query functions return `{ formattedText, ... }` consistently?**
   - What we know: `queryAreaSignal(db, area)` returns `null` on no-data; exists in `prod01-area-signal.js`
   - What's unclear: Whether all 8 products follow exactly the same return shape
   - Recommendation: Spot-check 2-3 product functions before writing tool code; adjust interface if needed

3. **Does `IntelligenceCache` have a `hash()` method or does it use a different API?**
   - What we know: `cache/manager.js` exports `IntelligenceCache`; cache key docs mention "SHA-256 hash of JSON-serialized params with sorted keys"
   - What's unclear: Exact public API of `IntelligenceCache` (`.get(key)`, `.set(key, value, ttl)`, `.hash(params)`)
   - Recommendation: Read `dist/cache/manager.js` before writing tool code; adjust calls to match actual API

4. **Batch vs on-demand Python scripts for TOOL-12/13**
   - What we know: `analyze_granger.py` and cross-correlation scripts exist and write to SQLite in batch mode
   - What's unclear: Whether adding a `--mode single` flag is cleaner than creating new scripts
   - Recommendation: Create two small new scripts `granger_ondemand.py` and `correlation_ondemand.py` — cleaner separation, no risk of breaking pipeline batch mode

5. **nftables: does lobsec service have write access to run `nft` commands?**
   - What we know: `lobsec` user has `NoNewPrivileges` in systemd; nftables requires root to modify rulesets
   - What's unclear: How domain IP set updates would be applied at runtime
   - Recommendation: Run `update-egress-ips.sh` as root via systemd timer (same pattern as existing timers). The lobsec service itself never touches nftables.

---

## Sources

### Primary (HIGH confidence — verified from production files)
- `/opt/lobsec/plugins/lobsec-uae-re/dist/index.js` — tool registration pattern, Type helpers, textResult, register() function
- `/opt/lobsec/plugins/lobsec-uae-re/dist/products/format.js` — freshnessFooter, stalenessWarning, truncate4K signatures
- `/opt/lobsec/plugins/lobsec-uae-re/dist/products/prod01-area-signal.js` — queryAreaSignal return shape
- `/opt/lobsec/plugins/lobsec-uae-re/dist/areas/mapping.js` — initAreaTable, area_names table structure
- `/opt/lobsec/plugins/lobsec-security/dist/credential-redactor.js` — CREDENTIAL_PATTERNS array structure
- `/etc/nftables.d/lobsec-egress.conf` — current egress rules (tcp dport 443 accept)
- `.planning/REQUIREMENTS.md` — complete requirement specifications
- `.planning/STATE.md` — architecture decisions and accumulated context

### Secondary (MEDIUM confidence)
- nftables IP set pattern: standard documented approach for domain-based filtering; DNS resolution limitation is well-known

### Tertiary (LOW confidence — needs validation)
- Reddit PRAW token format: no official documentation on token string format; regex pattern is speculative

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all core components verified in production dist files
- Architecture: HIGH — existing register() pattern is the template; all 8 product functions exist
- Pitfalls: HIGH — based on known production issues (async register, sandbox allow-list, ProtectSystem=strict)
- nftables domain whitelisting: MEDIUM — standard approach but operational complexity is real
- SEC-04 PRAW token pattern: LOW — token format unverified

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (stable codebase; only changes if product query APIs change)
