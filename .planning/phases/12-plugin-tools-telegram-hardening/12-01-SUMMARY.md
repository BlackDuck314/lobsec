---
phase: 12-plugin-tools-telegram-hardening
plan: "01"
subsystem: uae-re-plugin
tags: [tools, telegram, area-normalization, products]
dependency_graph:
  requires: [11-04]
  provides: [uae_area_signal, uae_distress, uae_rental_intel, uae_supply_pipeline, uae_expat_flow, uae_macro_health, uae_arbitrage, uae_salary_rent]
  affects: [lobsec-uae-re plugin, Telegram bot tool surface]
tech_stack:
  added: []
  patterns: [cache-first pattern with 1hr TTL, area resolution pipeline, Levenshtein fuzzy matching]
key_files:
  created:
    - packages/uae-re/src/tools/area-normalizer.ts
  modified:
    - packages/uae-re/src/index.ts
decisions:
  - "Hand-rolled Levenshtein over npm library: 20-line DP matrix sufficient, no dep weight"
  - "resolveAreaOrError helper centralises ambiguity/unknown error messaging across 6 area tools"
  - "Top-5 distress mode queries composite_scores directly (approximation sufficient for list view)"
  - "cache.get/set called with same cacheKey object — consistent with IntelligenceCache.hashParams deterministic SHA-256 approach"
metrics:
  duration: "~12 minutes"
  completed: "2026-03-16"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 1
---

# Phase 12 Plan 01: Area Normalizer + 8 Product Tools Summary

All 8 intelligence product query functions wired to Telegram via OpenClaw plugin tools, with shared area name normalization (alias lookup, exact match, Levenshtein fuzzy matching).

## What Was Built

### Task 1: area-normalizer.ts (QUAL-04)

New module at `packages/uae-re/src/tools/area-normalizer.ts`:

- **ResolveResult interface**: canonical name + confidence (exact/alias/fuzzy) + optional alternatives[] and correctedFrom string
- **ALIASES constant**: 30 entries covering JVC, JBR, DIFC, DIP, JLT, MBR, IMPZ, JAFZA, DSO, DHCC, DWC, DIC, DMC, KV, SZR, DAMAC, JVT, JI, JGE, JH, DFC, DCC, BUR, DEIRA, KARAMA, QR and variants
- **levenshtein()**: Standard DP matrix (~20 lines), no external dependencies
- **resolveArea()**: 4-step pipeline — alias table -> normalized_monthly exact match -> area_names table (getCanonicalArea) -> Levenshtein fuzzy (threshold <= 2). Returns null only if completely unrecognized.

### Task 2: 8 Product Tools in index.ts (TOOL-01..08)

Top-level imports added for all 8 product functions and resolveArea.

**resolveAreaOrError()** helper: wraps resolveArea(), returns error string for unknown areas or ambiguous multi-match, returns prefix string for fuzzy corrections.

Tools registered:

| Tool | Name | Area Param | Cache Key |
|------|------|------------|-----------|
| TOOL-01 | uae_area_signal | required | area + property_type |
| TOOL-02 | uae_distress | optional (top-5 mode) | area or distress_topN |
| TOOL-03 | uae_rental_intel | required | area |
| TOOL-04 | uae_supply_pipeline | optional (city-wide) | area or "all" |
| TOOL-05 | uae_expat_flow | none | {} |
| TOOL-06 | uae_macro_health | none | {} |
| TOOL-07 | uae_arbitrage | required | area + property_type |
| TOOL-08 | uae_salary_rent | none (income_bracket) | bracket |

All tools: 1-hour cache TTL (3600000ms), async execute with try/catch, textResult() returns.

## Verification

- `npx tsc --noEmit -p packages/uae-re/tsconfig.json`: 0 errors
- 9 `api.registerTool()` calls confirmed (8 new + 1 existing uae_collection_status)
- area-normalizer.ts: 207 lines, 0 external dependencies
- index.ts: +368 lines, all cache-first pattern

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check: PASSED

Files exist:
- packages/uae-re/src/tools/area-normalizer.ts: FOUND
- packages/uae-re/src/index.ts: FOUND (modified)

Commits:
- 5f3d150: feat(12-01): add area-normalizer with alias table and Levenshtein fuzzy matching
- 4f18256: feat(12-01): register 8 product tools in plugin index (TOOL-01..08)
