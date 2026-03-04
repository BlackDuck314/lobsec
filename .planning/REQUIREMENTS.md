# Requirements: lobsec

**Defined:** 2026-03-04
**Core Value:** No credential or sensitive data ever reaches an LLM provider

## v1.1 Requirements

### Skills Cleanup

- [ ] **SKILL-01**: Remove all non-functional skills from sandbox (47 of 51)
- [ ] **SKILL-02**: Keep only coding-agent, summarize, session-logs, skill-creator
- [ ] **SKILL-03**: Sync AGENTS.md between workspace and sandbox

### GitHub Integration

- [ ] **GH-01**: Store GitHub PAT securely in HSM (label: github-pat)
- [ ] **GH-02**: Install gh CLI on the host system
- [ ] **GH-03**: Create github plugin tool (issues, PRs, repos via REST API)
- [ ] **GH-04**: Configure gh CLI auth for lobsec user
- [ ] **GH-05**: Add GitHub tool to TOOLS.md with usage instructions

### Tool Verification

- [ ] **VERIFY-01**: All 8 plugin tools register on startup (7 existing + github)
- [ ] **VERIFY-02**: Each tool works when called via Telegram

## Out of Scope

| Feature | Reason |
|---------|--------|
| gh CLI inside Docker sandbox | Plugin tools run in gateway process, not sandbox |
| Rewrite existing plugin tools | They work, just need skill conflicts removed |
| New integrations beyond GitHub | Separate milestone |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SKILL-01 | Phase 1 | Pending |
| SKILL-02 | Phase 1 | Pending |
| SKILL-03 | Phase 1 | Pending |
| GH-01 | Phase 1 | Pending |
| GH-02 | Phase 1 | Pending |
| GH-03 | Phase 2 | Pending |
| GH-04 | Phase 2 | Pending |
| GH-05 | Phase 2 | Pending |
| VERIFY-01 | Phase 2 | Pending |
| VERIFY-02 | Phase 2 | Pending |

**Coverage:**
- v1.1 requirements: 10 total
- Mapped to phases: 10
- Unmapped: 0

---
*Requirements defined: 2026-03-04*
