# Project State

## Current Position

Phase: Phase 1 COMPLETE, Phase 2 NOT STARTED
Plan: v1.1 Tool Reliability
Status: Phase 1 done, need to build GitHub plugin tool and deploy
Last activity: 2026-03-04 — Skills cleanup, PAT stored, extraction script updated

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-04)

**Core value:** No credential or sensitive data ever reaches an LLM provider
**Current focus:** v1.1 Tool Reliability — fix tool discovery

## Phase 1 Completed

- [x] SKILL-01: Removed 47 non-functional skills from `/opt/lobsec/.openclaw/sandboxes/agent-main-f331f052/skills/`
- [x] SKILL-02: Kept only: coding-agent, summarize, session-logs, skill-creator
- [x] SKILL-03: Synced AGENTS.md (added web_search, web_fetch to workspace copy)
- [x] GH-01: GitHub PAT stored in HSM (label: `github-pat`, user: Centaur0101, repo scope)
- [x] GH-02: gh CLI already installed (v2.46.0) — gh auth NOT configured (PAT missing `read:org` scope, but REST API works fine)
- [x] HSM extraction script updated: `/opt/lobsec/bin/hsm-extract-credentials.sh` now extracts `github-pat` into `GITHUB_PAT` and `GITHUB_USER=Centaur0101` env vars

## Phase 2 Remaining

- [ ] GH-03: Create `github` plugin tool in `packages/tools/src/github.ts`
  - Use GitHub REST API via `fetch()` (not gh CLI)
  - PAT from `process.env.GITHUB_PAT`
  - Operations: list_repos, list_issues, create_issue, list_prs, view_pr, search_code
  - Register in `packages/tools/src/openclaw-adapter.ts`
- [ ] GH-04: gh CLI auth skipped (PAT only has repo scope, not read:org). Plugin tool uses REST API directly.
- [ ] GH-05: Update TOOLS.md (workspace + sandbox) with GitHub tool instructions
- [ ] VERIFY-01: Build (`pnpm build`), deploy plugin to `/opt/lobsec/plugins/lobsec-tools/`, restart services
- [ ] VERIFY-02: Test all tools via Telegram

## Key Details for Resumption

### GitHub Plugin Tool Design
- File: `packages/tools/src/github.ts`
- Pattern: Follow email.ts / weather.ts pattern (export functions, register in openclaw-adapter.ts)
- Auth: `Authorization: Bearer ${process.env.GITHUB_PAT}` header
- Base URL: `https://api.github.com`
- User: Centaur0101 (ID: 240006892)
- Register as multiple tools or one tool with action parameter (recommend: one `github` tool with `action` param like "list_repos", "list_issues", etc.)

### Files to Modify
1. NEW: `packages/tools/src/github.ts` — GitHub REST API wrapper
2. NEW: `packages/tools/src/github.test.ts` — Tests
3. EDIT: `packages/tools/src/openclaw-adapter.ts` — Register github tool(s)
4. EDIT: `packages/tools/src/index.ts` — Export github functions
5. EDIT: `/opt/lobsec/.openclaw/workspace/TOOLS.md` — Add github docs
6. EDIT: `/opt/lobsec/.openclaw/sandboxes/agent-main-f331f052/TOOLS.md` — Same

### Deploy Steps
1. `cd /root/lobsec && pnpm build`
2. `cp -r packages/tools/dist/* /opt/lobsec/plugins/lobsec-tools/dist/`
3. `cp packages/tools/openclaw.plugin.json /opt/lobsec/plugins/lobsec-tools/`
4. `chown -R lobsec:lobsec /opt/lobsec/plugins/lobsec-tools/`
5. `systemctl restart lobsec` (extraction script will pull new GITHUB_PAT from HSM)
6. Check logs: `journalctl -u lobsec -n 20` — should show "registered 8 tools"
7. Test via Telegram

### Production Changes Already Made (need service restart to take effect)
- Skills directory cleaned (47 skills removed)
- AGENTS.md synced
- HSM extraction script updated with GITHUB_PAT
- GitHub PAT stored in HSM

## Accumulated Context

### From pre-GSD development (Feb-Mar 2026)
- 9 security layers implemented and deployed
- 765 tests passing, 0 type errors
- All services running in production
- Bot integrations (weather, email, calendar, contacts, web search) deployed
- Security verifier and health monitoring active

### Root Cause of Tool Issues (discovered 2026-03-04)
- 51 community skills in sandbox competed with 7 working plugin tools
- Skills designed for macOS desktop (curl, himalaya, gh) — don't work on headless Linux server
- Bot would try skill instructions (e.g., `curl wttr.in`) instead of calling plugin tool (`weather`)
- Fix: Remove 47 broken skills, keep 4 useful ones
