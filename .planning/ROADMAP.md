# Roadmap: lobsec v1.1 — Tool Reliability

## Phase 1: Cleanup & Credentials

**Goal:** Remove skill conflicts and store GitHub PAT securely.

**Requirements:** SKILL-01, SKILL-02, SKILL-03, GH-01, GH-02

**Success Criteria:**
1. Only 4 skills remain in sandbox (coding-agent, summarize, session-logs, skill-creator)
2. GitHub PAT stored in HSM
3. gh CLI installed and working
4. AGENTS.md identical in workspace and sandbox

## Phase 2: GitHub Tool & Deploy

**Goal:** Build GitHub plugin tool, deploy everything, verify all tools work.

**Requirements:** GH-03, GH-04, GH-05, VERIFY-01, VERIFY-02

**Success Criteria:**
1. github plugin tool registers on startup
2. TOOLS.md updated with GitHub usage instructions
3. All 8 plugin tools work when called via Telegram
4. No conflicting skills interfere with tool calls

---
*Roadmap created: 2026-03-04*
*Phases: 2 | Requirements: 10 | Coverage: 100%*
