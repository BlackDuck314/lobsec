---
gsd_state_version: 1.0
milestone: v1.7
milestone_name: System Health & Reliability
status: complete
last_updated: "2026-04-22T08:00:00Z"
progress:
  total_phases: 4
  completed_phases: 4
  total_plans: 3
  completed_plans: 2
---

# Project State

## Current Position

Phase: Phase 30 (Integration & Verification) — COMPLETE
Status: v1.7 milestone complete. All phases done (27 partial — Jetson deferred, BGE-M3 blocked).
Last activity: 2026-04-22 — Phase 30 verification passed.

### v1.7 Phase Status
| Phase | Name | Requirements | Status |
|-------|------|--------------|--------|
| 27 | Core Infrastructure Repair | REPAIR-01 through REPAIR-05 | Partial (Jetson deferred, BGE-M3 blocked) |
| 28 | System Housekeeping | HOUSE-01 through HOUSE-05 | **Complete** |
| 29 | Data Pipeline Restoration | PIPE-01 through PIPE-04 | **Complete** |
| 30 | Integration & Verification | VERIF-01 through VERIF-03 | **Complete** |

### Phase 27 Plan Status (carried)
| Plan | Scope | Status | Notes |
|------|-------|--------|-------|
| 27-01 | Portullama + memory search | **Partial** | Chat works (qwen3.5:27b). Embeddings broken (BGE-M3 crash on remote). Memory plugin not configured. |
| 27-02 | Jetson CF-Access | **Deferred** | Jetson is down. Skip for now — revisit when device is back online. |
| 27-03 | Weekly digest + TLS lifecycle | **Complete** | All 3 timer services fixed, digest tested, TLS PartOf= verified. |

### Phase 28 Results
| Req | Scope | Status | Notes |
|-----|-------|--------|-------|
| HOUSE-01 | Session bloat | **Done** | Trimmed 2.7MB → 210KB (92% reduction) |
| HOUSE-02 | Disk cleanup | **Done** | Freed ~6GB (83% → 68%) |
| HOUSE-03 | ConfigMonitor drift | **Done** | Fixed hash-only drift check + stub shim → symlink |
| HOUSE-04 | Timer audit | **Done** | 5 broken collectors disabled (reddit-sentiment, news-sentiment, propertyfinder, jebel-ali-port, fcsa-demographics) |
| HOUSE-05 | Deploy files committed | **Done** | 11 files committed (feat(27-28)) |

### Fixes Applied (2026-04-22)
- **Proxy egress firewall**: Added `EnvironmentFile=/opt/lobsec/proxy/.env` to lobsec-proxy.service
- **Portullama model updated**: `qwen2.5:32b` → `qwen3.5:27b` in openclaw.json
- **Sovereign routing restored**: qwen3.5:27b responds through proxy
- **Weekly digest fixed**: Added `EnvironmentFile=/opt/lobsec/.openclaw/.env` to timer services
- **TLS lifecycle verified**: PartOf= correctly auto-restarts proxy with gateway
- **Feynman tool deployed**: feynman_research registered as 10th plugin tool
- **ConfigMonitor fixed**: drift check uses hash comparison only (not validation violations)
- **Collectors cleaned**: 5 broken sources disabled (missing API keys, dead endpoints)
- **Session trimmed**: 2.7MB → 210KB (92% reduction)
- **Disk freed**: ~6GB recovered (npm cache, Playwright, old binaries, journals)

### Capabilities Audit Update (2026-04-22)
**Working:** Gateway, Proxy, Telegram, HSM, LUKS, nftables, audit signing, TLS, Anthropic API, Gmail IMAP, Weather API, Perplexity, Radicale, GitHub PAT, 10 plugin tools, Portullama chat (qwen3.5:27b), Weekly digest, Monthly report, Alerts timers, Feynman research, TLS lifecycle, ConfigMonitor
**Down:** Jetson (cloudflared tunnel down), Memory Search (BGE-M3 crashes on Portullama + memory plugin not configured)
**Blocked:** Jetson needs cloudflared restart on remote device
**Resolved:** Session bloat, root disk usage, ConfigMonitor drift, broken collectors

### Phase 29 Results
| Req | Scope | Status | Notes |
|-----|-------|--------|-------|
| PIPE-01 | Scraper service | **Done** | Running stable (3+ weeks), 18 missions enabled, health OK |
| PIPE-02 | Sentiment collectors | **Done** | 5 broken sources disabled in registry (HOUSE-04), remaining produce data |
| PIPE-03 | Collection cycle | **Done** | Exit code fix: partial success = exit 0. Daily tested OK (google-trends → normalized_monthly) |
| PIPE-04 | Feynman research | **Done** | Deployed earlier as feynman_research tool |

### Phase 30 Results
| Req | Scope | Status | Notes |
|-----|-------|--------|-------|
| VERIF-01 | Telegram → LLM → Tool | **Pass** | Gateway running, 23 tools registered, Telegram flowing, tool invocations confirmed |
| VERIF-02 | Backend connectivity | **Pass** | Anthropic: 200 OK (1.8s), Portullama: 200 OK (9.1s), Jetson: deferred |
| VERIF-03 | Timers produce output | **Pass** | 13 timers active, collection exit code fixed (partial success = exit 0) |

## Resume Instructions

1. v1.7 milestone complete. Deferred items:
   - **Jetson**: Down, revisit when device is back online
   - **BGE-M3**: Broken on Portullama, revisit when admin fixes it
2. Next milestone (v1.8) can be planned when ready.

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-21)

**Core value:** No credential or sensitive data ever reaches an LLM provider
**Current focus:** v1.7 System Health — restore all broken capabilities from audit

## Architecture Decisions

- All previous decisions from v1.6 still apply
- PartOf=lobsec.service added to proxy service (TLS cert lifecycle fix)
- Sandbox image rebuilt with Python 3.11 (lobsec-sandbox:hardened v0.2.0)
- Feynman integrated as feynman_research tool (synchronous, idle detection, 8 workflows)
- Portullama model updated: qwen3.5:27b replaces qwen2.5:32b
- Proxy egress firewall uses EnvironmentFile for extra hosts
- Timer services now source /opt/lobsec/.openclaw/.env for credentials
- ConfigMonitor drift check: hash-only comparison (ignores validation-only violations)
- 5 broken collectors disabled in registry (re-enable when APIs/scrapers are fixed)

## Production Environment
- Server: Ubuntu 25.04 (VMware), <HOSTNAME> (<HOST_IP>)
- OpenClaw v2026.2.24, Node.js 22, sandbox mode "all" (hardened v0.2.0 with Python)
- Both plugins active: 9 security hooks + 10 general tools + 13 UAE RE tools
- Default model: Claude Haiku 4.5 via proxy (TLS 1.3)
- Sovereign model: Qwen 3.5 27B via Portullama (restored 2026-04-22)
- Services: lobsec, lobsec-proxy, lobsec-radicale, lobsec-scraper
- Timers: weekly-digest (Mon 04:00 UTC), monthly-report (26th 03:00 UTC), alerts (daily 20:00 UTC)
- Telegram: @<BOT_HANDLE> connected and responding
- LUKS2 encrypted volume at /opt/lobsec (15G, 5.5G used)
- nftables per-UID egress active (lobsec=<GATEWAY_UID>, lobsec-proxy=<PROXY_UID>)
- Feynman v0.2.40 at /opt/lobsec/.local/bin/feynman (default model: claude-haiku-4-5-20251001)
- Root disk: 68% (down from 83%)

## Known Issues (carried)
- Jetson cloudflared tunnel down (user must restart on remote device)
- BGE-M3 embedding model crashes on Portullama (remote server issue)
- Memory search disabled (needs BGE-M3 fix + memory-core plugin config)
- mTLS is server-TLS only (OpenClaw doesn't present client certs)
- message_sending hook never fires (OpenClaw limitation)

## Session Continuity

Last session: 2026-04-22
Stopped at: Phase 28 complete. Phase 29 next.
Resume file: N/A
Next: v1.7 complete. Plan v1.8 when ready.
