# Plan 07-04 Summary: DEWA Collector + Final Integration

**Executed:** 2026-03-11
**Status:** Complete (deployment blocker resolved by orchestrator)
**Wave:** 3 of 3
**Requirements:** COLL-15

## Objective

Implement DEWA connections collector, wire all 7 collectors into the plugin registry, update CLI to auto-trigger normalization, deploy to production, and verify end-to-end integration.

## Completed

### Task 1: Build DEWA Collector and Wire All Collectors ✅

**DEWA Connections Collector (COLL-15):**
- **File**: `packages/uae-re/src/collectors/dewa-connections.ts`
- Scrapes DEWA press releases from `https://www.dewa.gov.ae/en/about-us/media-publications/latest-news`
- Primary strategy: Parse press releases for connection/disconnection announcements
- Fallback strategy: Check publications page if press releases yield no data
- Extracts numeric data via regex patterns: "X new connections", "Y disconnections"
- Supports both area-level and emirate-level granularity (graceful degradation)
- Saves JSON output to `/opt/lobsec/data/raw/dewa-connections/`
- Metadata: `{source: "dewa-connections", frequency: "monthly", priority: 4, timeout: 180_000}`

**Python Normalization:**
- **File**: `packages/uae-re/python/uae_re/normalize_dewa.py`
- Aggregates connection/disconnection counts by area or emirate
- Produces metrics:
  - `{area}|dewa_new_connections`
  - `{area}|dewa_disconnections`
  - `{area}|dewa_net_change`
- Falls back to emirate-level (`dubai|dewa_*`) if area data unavailable
- **Schema**: `packages/uae-re/python/uae_re/schemas/dewa_schema.py` - lenient validation for semi-structured press release data

**Registry Integration:**
- Updated `packages/uae-re/src/index.ts`:
  - All 7 collectors registered in plugin `register()` function
  - `initAreaTable()` called on startup to seed ~150 area names
  - Plugin logs "registered 7 collectors + 1 tool"
- 7 collectors now registered:
  1. DLD sales (weekly, priority 1)
  2. Ejari rentals (weekly, priority 1)
  3. Building permits (monthly, priority 2)
  4. ADREC Abu Dhabi (weekly, priority 2)
  5. Bayut listings (weekly, priority 3)
  6. PropertyFinder listings (weekly, priority 3)
  7. DEWA connections (monthly, priority 4)

**CLI Auto-Normalization:**
- Updated `packages/uae-re/src/cli.ts`:
  - `runAll()`, `runFrequency()`, and `runOne()` now auto-trigger normalization after each successful collection
  - Logs normalization results (record count, date range, gap warnings, volume warnings) to stderr
  - Normalization failures logged but don't block remaining collections
  - Exit code 1 if any collection or normalization fails
  - All 7 collectors registered in CLI commands

**TypeScript Compilation:**
- All code compiles without errors
- Verified with `npx tsc --noEmit -p packages/uae-re/tsconfig.json`

**Commit:**
- Commit 4d539b2: "feat(07-04): build DEWA collector and wire all 7 collectors"

### Task 2: Deploy to Production ✅ (resolved by orchestrator)

**Original blocker:** `SQLITE_CANTOPEN` on WAL pragma during plugin load.

**Root cause:** Agent set `UAE_RE_DATA_DIR=/var/lib/lobsec` in `.env`, but `/var/lib/lobsec` was not in systemd `ReadWritePaths`. Under `ProtectSystem=strict`, the directory was read-only — SQLite could open the DB but couldn't create WAL journal files.

**Fix applied (orchestrator):**
1. Changed `.env` to `UAE_RE_DATA_DIR=/opt/lobsec/data` (fscrypt-encrypted, already in ReadWritePaths)
2. Added `/opt/lobsec/data` to `ReadWritePaths` in `lobsec.service` as well (defense in depth)
3. Restarted service — plugin loads, 7 collectors + 1 tool registered

**Service status after fix:**
- Gateway running: ✅
- lobsec security: ✅ 9 hooks
- lobsec-tools: ✅ 9 tools
- lobsec-uae-re: ✅ 7 collectors + 1 tool
- SQLite WAL mode: ✅ active
- Area names seeded: ✅ 150+ areas

### Task 3: Checkpoint - Human Verification ⏸️ PENDING

Deployment successful. Awaiting human verification of end-to-end collection.

## Decisions

| Decision | Rationale |
|----------|-----------|
| DEWA press release primary strategy | Press releases most likely to contain timely connection/disconnection announcements |
| Graceful area-level degradation | DEWA may only publish emirate-level aggregates; collector handles both |
| Lenient DEWA schema | Press release data is semi-structured; validate basic structure only |
| All 7 collectors in single registration | Simplifies plugin initialization, all collectors available immediately |
| Auto-normalization in CLI | Ensures collection + normalization always run together, prevents data staleness |
| WAL mode for performance | Optimizes read concurrency, critical for multi-collector setup |

## Files Modified

- `packages/uae-re/src/collectors/dewa-connections.ts` (new)
- `packages/uae-re/python/uae_re/normalize_dewa.py` (new)
- `packages/uae-re/python/uae_re/schemas/dewa_schema.py` (new)
- `packages/uae-re/src/index.ts` (updated - register all 7 collectors)
- `packages/uae-re/src/cli.ts` (updated - auto-normalization wiring)
- `packages/uae-re/src/db/connection.ts` (updated - debug logging for troubleshooting)

## Metrics

- **Lines of code**: +762 lines
- **Collectors**: 7 registered (100% of MVP requirement)
- **Normalization modules**: 7 complete
- **Schema validators**: 7 complete
- **Test coverage**: Not executed (deployment blocked)
- **Compilation**: ✅ 0 TypeScript errors
- **Deployment**: ❌ Runtime error during plugin load

## Verification Status

| Verification Step | Status | Notes |
|-------------------|--------|-------|
| TypeScript compiles | ✅ PASS | No errors |
| Plugin builds | ✅ PASS | dist/ generated successfully |
| Plugin deploys | ✅ PASS | Files copied to production |
| Plugin loads | ✅ PASS | Fixed: ReadWritePaths + data dir path |
| Area names seeded | ✅ PASS | 150+ areas seeded on startup |
| CLI check-deps passes | ✅ PASS | When run directly |
| DLD collection works | ⏸️ PENDING | Awaiting human verification |
| Normalization works | ⏸️ PENDING | Awaiting human verification |
| Telegram status visible | ⏸️ PENDING | Awaiting human verification |

## Lessons Learned

- **systemd ReadWritePaths**: All data directories written by the service need explicit ReadWritePaths entries under `ProtectSystem=strict`
- `.env` overrides must match systemd's writable paths — agent defaulted to `/var/lib/lobsec` which was outside the allowed set
- Debug logging in connection.ts was invaluable for pinpointing exactly where the failure occurred
- Test deployment early to catch integration issues before code completion
