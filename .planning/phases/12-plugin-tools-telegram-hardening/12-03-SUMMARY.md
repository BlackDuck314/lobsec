---
phase: 12-plugin-tools-telegram-hardening
plan: "03"
subsystem: security
tags: [credential-redaction, nftables, egress-firewall, audit-logging, uae-re]
dependency_graph:
  requires: []
  provides: [SEC-03, SEC-04, SEC-05]
  affects:
    - packages/plugin/src/credential-redactor.ts
    - packages/uae-re/src/collectors/base.ts
    - /etc/nftables.d/lobsec-egress.conf
    - /opt/lobsec/bin/update-egress-ips.sh
tech_stack:
  added: []
  patterns:
    - Credential pattern extension (prefix-based + context-based)
    - fs.appendFileSync audit trail (non-fatal, catch swallowed)
    - nftables comment-based domain documentation
key_files:
  created:
    - /opt/lobsec/bin/update-egress-ips.sh
  modified:
    - packages/plugin/src/credential-redactor.ts
    - packages/uae-re/src/collectors/base.ts
    - /etc/nftables.d/lobsec-egress.conf
decisions:
  - "CREDENTIAL_PATTERNS uses reliable prefixes (AIza, apify_api_) plus context-based patterns (client_id/client_secret assignments) for Reddit — avoids overly broad hash-matching patterns"
  - "nftables keeps tcp dport 443 accept as functional gate — IP sets would break on CDN rotation; domain comments serve as audit documentation"
  - "Audit entries written synchronously (appendFileSync) with catch-swallowed — audit failure must never crash collection"
  - "fs default import used (esModuleInterop: true in tsconfig.base.json) — matches existing codebase pattern"
metrics:
  duration: "~20 minutes"
  completed: "2026-03-16"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 4
  files_created: 1
---

# Phase 12 Plan 03: Security Hardening Summary

Extended credential redactor with UAE RE API key patterns, documented 28 egress domains in nftables with DNS resolver script, and integrated per-run audit logging into the collector framework.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend credential redactor with UAE RE API key patterns (SEC-04) | f17d16f | packages/plugin/src/credential-redactor.ts |
| 2 | nftables domain whitelist, resolver script, collector audit logging (SEC-03, SEC-05) | c389c2e | base.ts, /etc/nftables.d/lobsec-egress.conf, /opt/lobsec/bin/update-egress-ips.sh |

## What Was Built

### Task 1: Credential Redactor Extension (SEC-04)

Added 4 new patterns to `CREDENTIAL_PATTERNS` in `packages/plugin/src/credential-redactor.ts`:

- `google-maps-key`: `/AIza[0-9A-Za-z_-]{35}/g` — well-known Google Maps API key prefix
- `apify-token`: `/apify_api_[a-zA-Z0-9]{20,}/g` — Apify web scraping token prefix
- `reddit-client-id`: context-based match on `client_id=` / `REDDIT_CLIENT_ID=` assignments
- `reddit-client-secret`: context-based match on `client_secret=` / `REDDIT_CLIENT_SECRET=` assignments

Reddit PRAW OAuth refresh tokens have no fixed prefix and were not added (overly broad patterns risk false positives on UUIDs/hashes). The existing `bearer-token` pattern provides partial coverage.

### Task 2A: nftables Domain Whitelist (SEC-03)

Updated `/etc/nftables.d/lobsec-egress.conf` to document all 28 UAE RE source domains plus 3 infrastructure domains (Anthropic, Telegram, Perplexity) in a comment block above `tcp dport 443 accept`. The functional gate remains unchanged — IP-set enforcement deferred pending separate lobsec-proxy user (known issue).

Created `/opt/lobsec/bin/update-egress-ips.sh`:
- Resolves all 36 domains via `dig +short A`
- Deduplicates and writes to `/opt/lobsec/logs/egress-ips-latest.txt`
- Shell syntax validated with `bash -n`
- Made executable (`chmod +x`)

### Task 2B: Collector Audit Logging (SEC-05)

Added `import fs from "node:fs"` and audit log appends in both branches of `SourceCollector.run()`:

```typescript
const auditEntry = {
  type: "collection_run",
  timestamp: new Date().toISOString(),
  source: this.metadata.source,
  status: "success" | "failure",
  rowCount: number,
  durationMs: number,
  error: string | null,
};
fs.appendFileSync("/opt/lobsec/logs/audit.jsonl", JSON.stringify(auditEntry) + "\n");
```

The existing `lobsec-audit-sign.timer` (runs every 5 minutes) will sign these new entries automatically.

## Deviations from Plan

### Out-of-scope pre-existing errors (not fixed, per scope boundary rules)

`packages/plugin/src/index.ts` has 2 pre-existing TypeScript errors (lines 660, 744) that existed before this plan. Not introduced by changes here. Not fixed per deviation scope boundary rule.

## Verification Results

1. `npx tsc --noEmit packages/plugin/src/credential-redactor.ts` — PASS (clean)
2. `npx tsc -p packages/uae-re/tsconfig.json --noEmit` — no errors in base.ts
3. CREDENTIAL_PATTERNS has 4 new entries confirmed
4. `/opt/lobsec/bin/update-egress-ips.sh` exists and passes `bash -n`
5. nftables config documents all 28 source domains in comments
6. base.ts run() appends JSON audit entries with all required fields

## Self-Check: PASSED

- packages/plugin/src/credential-redactor.ts — modified, committed f17d16f
- packages/uae-re/src/collectors/base.ts — modified, committed c389c2e
- /etc/nftables.d/lobsec-egress.conf — updated (outside repo, system file)
- /opt/lobsec/bin/update-egress-ips.sh — created (outside repo, system file)
