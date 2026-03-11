# Phase 6: Foundation & Infrastructure - Context

**Gathered:** 2026-03-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver the foundational infrastructure for the UAE Real Estate Intelligence System: SQLite database with WAL mode, Python 3.13 analytics environment, collector framework with scheduling and concurrency control, TypeScript-to-Python subprocess bridge, intelligence cache layer, and the `@lobsec/uae-re` OpenClaw plugin package. This phase builds plumbing — no actual data sources are collected yet (that's Phase 7+).

Requirements: INFRA-01, INFRA-02, INFRA-03, INFRA-04, INFRA-05, INFRA-06, INFRA-07, SEC-01, SEC-02, SCHED-01

</domain>

<decisions>
## Implementation Decisions

### Package Layout
- New `@lobsec/uae-re` monorepo package at `packages/uae-re/` — separate from existing `@lobsec/tools`
- Two separate OpenClaw plugins: `lobsec-tools` stays as-is, `lobsec-uae-re` registers independently. Independent deployment — updating UAE RE doesn't risk breaking existing tools
- Collector framework (SourceCollector base, registry, scheduling) lives inside `@lobsec/uae-re` — it's UAE-RE-specific, extract to shared later only if another use case appears
- Python subprocess bridge (`runPython()`) lives inside `@lobsec/uae-re` — only this package needs Python
- Internal structure: subdirectories by concern — `src/collectors/`, `src/analytics/`, `src/tools/`, `src/db/`
- Deployed plugin at `/opt/lobsec/plugins/lobsec-uae-re/` includes Python scripts alongside compiled JS in a `python/` subdirectory. One location to update
- Standard tsconfig extending `tsconfig.base.json` — same strict mode, ESM, NodeNext module resolution as the rest of the monorepo

### Data File Organization
- Raw collected data (CSVs, PDFs, JSON) stored as files on disk at `/opt/lobsec/data/raw/` alongside the SQLite database. SQLite holds normalized monthly data only
- Raw files organized by source name: `raw/dld-sales/2026-W11.csv`, `raw/bayut-listings/2026-03.json`. Simple, predictable, easy to find latest download per source
- Simple create-if-not-exists for SQLite schema — no formal migration system. Single schema creation script run at startup. Add columns with ALTER TABLE if needed later
- Raw file retention: unlimited — keep everything. Disk is cheap, data is priceless. fscrypt covers encryption at rest

### Python Code Structure
- Modular Python package: `packages/uae-re/python/uae_re/` with `__init__.py`, `normalize.py`, `stationarity.py`, `granger.py`, etc. Each module is importable and testable. `runPython()` calls specific entry points
- Dependencies pinned in `requirements.txt` with exact versions (e.g., `pandas==2.2.3`) in `packages/uae-re/python/`. Simple, reproducible, no extra tooling
- Both pytest (Python unit tests for analytics logic) and Vitest (TypeScript bridge/integration tests). Catches bugs at both layers
- Deploy script creates/updates venv automatically — checks if venv exists, runs `pip install -r requirements.txt`. Zero manual steps for updates

### Collector Error Behavior
- Retry 3x with backoff on failure, then log to audit + send Telegram alert. Source marked STALE. Other collectors continue unaffected
- Fully independent collectors — one failure doesn't block the other 27. Concurrency limiter (max 3) only governs simultaneous execution
- Summary logging per run: one audit entry per collector run with source name, status (ok/fail), row count, duration. Detailed errors only on failure
- Escalating severity: first failure cycle = WARN via Telegram. If still failing after next scheduled run = CRITICAL alert. Gives time to act before compounding

### Claude's Discretion
- Exact SQLite table schemas (column names, types, indices)
- CollectorRegistry internal scheduling implementation
- Python subprocess bridge error serialization format
- Intelligence cache TTL tuning and eviction strategy
- Deploy script structure and systemd unit file details
- better-sqlite3 vs other SQLite Node.js bindings (better-sqlite3 is the project decision)

</decisions>

<specifics>
## Specific Ideas

- Follow existing plugin adapter pattern from `packages/tools/src/openclaw-adapter.ts` — same `AgentTool` interface, JSON Schema parameters, `textResult()` helper
- Reuse existing `CircuitBreaker` and `retryWithBackoff` from `@lobsec/shared/src/resilience.ts` for collector retry logic
- Reuse existing `FscryptManager` from `@lobsec/shared/src/encryption.ts` for encrypting `/opt/lobsec/data/`
- HSM credential storage follows same pattern as existing credentials — `pkcs11-tool --write-object` then `chown lobsec:lobsec` the token dir
- The playbook at `.planning/uae-re-playbook.md` has detailed source URLs, field mappings, and agent instructions for all 28 sources

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `CircuitBreaker` + `retryWithBackoff` (packages/shared/src/resilience.ts): Collector retry and failure handling
- `FscryptManager` (packages/shared/src/encryption.ts): Encrypt /opt/lobsec/data/ as 5th fscrypt directory
- `Logger` (packages/shared/src/logger.ts): Structured JSONL logging with redaction and trace IDs
- `AuditSigner` (packages/shared/src/audit-signer.ts): Audit log entries for collection runs
- OpenClaw adapter pattern (packages/tools/src/openclaw-adapter.ts): Plugin registration with AgentTool interface, JSON Schema params, textResult() helper
- Type helpers from packages/tools/src/openclaw-adapter.ts: OPTIONAL_MARKER, Type.Object/String/Number/Optional

### Established Patterns
- Monorepo packages: pnpm workspace, `@lobsec/` scope, tsconfig extending base, co-located tests (.test.ts)
- Plugin registration: synchronous `register(api: PluginApi)`, `api.registerTool()` with JSON Schema parameters
- Credentials from env vars: `getEnv()` helper, HSM extracts at service startup, injected via ExecStart bash wrapper
- Import pattern: all packages import from `@lobsec/shared`, siblings never import each other

### Integration Points
- OpenClaw plugin loader: `/opt/lobsec/plugins/lobsec-uae-re/` registered in `.openclaw/config.json` plugins array
- HSM: new API keys stored as data objects in SoftHSM2 token "lobsec"
- fscrypt: `/opt/lobsec/data/` needs new encryption policy (AES-256-XTS, policy_version 2)
- systemd: new `lobsec-uae-collector.service` with controlled concurrency
- Sandbox tools allow list: new UAE RE plugin tools need adding to `tools.sandbox.tools.allow`
- nftables: egress rules need new source domains whitelisted (Dubai Pulse, DARI, etc. — Phase 12)

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 06-foundation-infrastructure*
*Context gathered: 2026-03-11*
