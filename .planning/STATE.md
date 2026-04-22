---
gsd_state_version: 1.0
milestone: v1.7
milestone_name: System Health & Reliability
status: executing
last_updated: "2026-04-22T06:35:00Z"
progress:
  total_phases: 4
  completed_phases: 0
  total_plans: 3
  completed_plans: 2
---

# Project State

## Current Position

Phase: Phase 27 (Core Infrastructure Repair) — EXECUTING (2/3 plans complete)
Status: 27-01 mostly done (Portullama chat works, embeddings broken on remote). 27-02 blocked on user. 27-03 complete.
Last activity: 2026-04-22 — Phase 27 execution in progress.

### v1.7 Phase Status
| Phase | Name | Requirements | Status |
|-------|------|--------------|--------|
| 27 | Core Infrastructure Repair | REPAIR-01 through REPAIR-05 | Executing (2/3 plans done) |
| 28 | System Housekeeping | HOUSE-01 through HOUSE-05 | Not started |
| 29 | Data Pipeline Restoration | PIPE-01 through PIPE-04 | PIPE-04 done early (Feynman) |
| 30 | Integration & Verification | VERIF-01 through VERIF-03 | Not started |

### Phase 27 Plan Status
| Plan | Scope | Status | Notes |
|------|-------|--------|-------|
| 27-01 | Portullama + memory search | **Partial** | Chat works (qwen3.5:27b). Embeddings broken (BGE-M3 crash on remote). Memory plugin not configured. |
| 27-02 | Jetson CF-Access | **Blocked** | CF-Access creds valid but cloudflared tunnel is down on Jetson (error 1033). User must restart. |
| 27-03 | Weekly digest + TLS lifecycle | **Complete** | All 3 timer services fixed, digest tested, TLS PartOf= verified. |

### Fixes Applied (2026-04-22)
- **Proxy egress firewall**: Added `EnvironmentFile=/opt/lobsec/proxy/.env` to lobsec-proxy.service — loads `LOBSEC_EGRESS_EXTRA_HOSTS`
- **Portullama model updated**: `qwen2.5:32b` → `qwen3.5:27b` in openclaw.json (old model removed from server)
- **Sovereign routing restored**: qwen3.5:27b responds through proxy (confirmed with chat test)
- **Weekly digest fixed**: Added `EnvironmentFile=/opt/lobsec/.openclaw/.env` to digest, monthly-report, alerts services
- **Digest test passed**: Telegram message sent successfully
- **TLS lifecycle verified**: PartOf= correctly auto-restarts proxy with gateway
- **Log ownership fixed**: digest.log and alerts.log chown'd to lobsec
- **Feynman tool deployed** (2026-04-21): feynman_research registered as 10th plugin tool, synchronous with idle detection

### Capabilities Audit Update (2026-04-22)
**Working:** Gateway, Proxy, Telegram, HSM, LUKS, nftables, audit signing, TLS, Anthropic API, Gmail IMAP, Weather API, Perplexity, Radicale, GitHub PAT, 10 plugin tools, Portullama chat (qwen3.5:27b), Weekly digest, Monthly report, Alerts timers, Feynman research, TLS lifecycle
**Down:** Jetson (cloudflared tunnel down), Memory Search (BGE-M3 crashes on Portullama + memory plugin not configured)
**Blocked:** Jetson needs cloudflared restart on remote device
**Issues:** Session bloat (2.7MB), root disk 81%, ConfigMonitor drift, BGE-M3 model broken on Portullama

## Resume Instructions

1. Phase 27 mostly complete. Two items need user action:
   - **Jetson**: SSH into Jetson, restart cloudflared. Then verify from here.
   - **BGE-M3**: Portullama admin needs to fix/reinstall bge-m3:latest (llama runner crash)
2. Once Jetson is restored, verify all 3 backends through proxy.
3. Memory search also needs memory-core plugin configuration (separate from embeddings).
4. Phase 28 (System Housekeeping) is next after Phase 27 closes.

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

## Production Environment
- Server: Ubuntu 25.04 (VMware), <HOSTNAME> (<HOST_IP>)
- OpenClaw v2026.2.24, Node.js 22, sandbox mode "all" (hardened v0.2.0 with Python)
- Both plugins active: 9 security hooks + 10 general tools + 13 UAE RE tools
- Default model: Claude Haiku 4.5 via proxy (TLS 1.3)
- Sovereign model: Qwen 3.5 27B via Portullama (restored 2026-04-22)
- Services: lobsec, lobsec-proxy, lobsec-radicale, lobsec-scraper
- Timers: weekly-digest (Mon 04:00 UTC), monthly-report (26th 03:00 UTC), alerts (daily 20:00 UTC)
- Telegram: @lobsec_bot connected and responding
- LUKS2 encrypted volume at /opt/lobsec (15G, 5.5G used)
- nftables per-UID egress active (lobsec=995, lobsec-proxy=993)
- Feynman v0.2.40 at /opt/lobsec/.local/bin/feynman (default model: claude-haiku-4-5-20251001)

## Known Issues (carried)
- Jetson cloudflared tunnel down (user must restart on remote device)
- BGE-M3 embedding model crashes on Portullama (remote server issue)
- Memory search disabled (needs BGE-M3 fix + memory-core plugin config)
- Session file 2.7MB (1140+ messages)
- Root disk 81% full
- ConfigMonitor drift warning
- mTLS is server-TLS only (OpenClaw doesn't present client certs)
- message_sending hook never fires (OpenClaw limitation)

## Session Continuity

Last session: 2026-04-22
Stopped at: Phase 27 executing — 2/3 plans done, 27-02 blocked on user.
Resume file: N/A
Next: Close Phase 27 (user fixes Jetson + BGE-M3), then Phase 28 (System Housekeeping).
