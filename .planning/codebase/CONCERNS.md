# Technical Debt & Concerns Registry

**Generated**: 2026-03-03
**Scope**: Full codebase review (packages/plugin, packages/proxy, packages/shared, packages/cli)
**Status**: Production deployed (Feb 25, 2026) with known gaps

---

## CRITICAL ISSUES (Must address before next phase)

### C1: Proxy baseUrl Injection Not Wired
**Severity**: HIGH
**Component**: packages/proxy/src/llm-router.ts
**Status**: Incomplete

OpenClaw providers still call inference backends **directly**, bypassing the proxy entirely. The routing logic exists in `llm-router.ts` but it's never injected into OpenClaw's provider configuration.

**Impact**:
- Cloud API keys and sovereign credentials flow directly from OpenClaw, not through proxy
- Budget enforcement and credential redaction happen AFTER the request, not BEFORE
- Defeats core goal (G2: PII never leaves the local machine)

**Required Fix**:
1. Wire `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` replacement with proxy URL in OpenClaw config
2. All outbound LLM calls → `http://127.0.0.1:18790`
3. Proxy handles actual credential injection + routing decision
4. Add integration test: verify direct calls are blocked at proxy

**Effort**: 1-2 days (config wiring + e2e test)

---

### C2: mTLS Enforcement Not Active
**Severity**: HIGH
**Component**: packages/shared/src/cert-manager.ts
**Status**: Partially implemented

Certificates exist at `/opt/lobsec/run/certs/` (P-256/ECDSA, auto-renewable) but services still use unencrypted HTTP:
- Gateway: `http://127.0.0.1:18789` (ws://)
- Proxy: `http://127.0.0.1:18790` (plain HTTP)

**Code Status**:
- `cert-manager.ts`: Mock implementation only (no actual X.509 cert generation)
- `generateInternalCA()`, `issueCertificate()`: Signatures exist but return mock data
- No TLS server configuration in OpenClaw wrapper

**Impact**:
- Inter-component traffic unencrypted (even though all loopback-only)
- Malicious local process can MITM requests
- Violates defense-in-depth principle

**Required Fix**:
1. Implement real X.509 cert generation (use `node-forge` or shell out to `openssl`)
2. Wire mTLS into gateway WebSocket server
3. Wire client certs into proxy HTTP client
4. Add cert rotation every 12h with zero-downtime reload
5. Add integration test: verify invalid certs rejected

**Effort**: 2-3 days (crypto + server integration)

---

### C3: Sandbox Image Not Used in OpenClaw
**Severity**: MEDIUM
**Component**: Deployment infra
**Status**: Built but unused

Docker image `lobsec-sandbox:hardened` (74.8MB, hardened rootless, seccomp whitelist) was built and pushed, but OpenClaw still uses `openclaw-sandbox:bookworm-slim`.

**Code Status**:
- Image exists: `/root/lobsec/deploy/docker/Dockerfile.sandbox`
- Hardened features: NoNewPrivileges, ProtectSystem=strict, seccomp whitelist
- **Not applied**: OpenClaw config still hardcoded to stock image

**Impact**:
- Tool breakout risk from default seccomp policy
- No ProtectSystem/ProtectHome in OpenClaw containers
- Capabilities not minimized

**Required Fix**:
1. Update OpenClaw plugin to set `sandboxImage: "lobsec-sandbox:hardened"`
2. Verify seccomp profile loaded: `docker inspect --format '{{.HostConfig.SecurityOpt}}'`
3. Add test: deny syscall (e.g., `ptrace`) should fail

**Effort**: 4-6 hours (config + validation)

---

## HIGH-PRIORITY GAPS (Next sprint)

### H1: Monitoring & Alerting Not Deployed
**Severity**: HIGH
**Component**: packages/shared/src/monitor.ts
**Status**: Fully implemented but inactive

`SystemMonitor` class exists with full alert/metric infrastructure but is never instantiated or connected to systemd services.

**Code**:
- `monitor.ts`: ~200 LOC, supports alerts (critical/high/medium/low/info), webhooks
- `MonitorConfig`: Slack/Discord/email-ready interfaces
- **Gap**: No instantiation in CLI startup, no webhook endpoint

**Missing**:
- Alert lifecycle (create → acknowledge → resolve)
- Webhook delivery mechanism
- Persistence layer for alerts
- Dashboard/API endpoint

**Risk**:
- Silent failures (HSM unavailable, cert expiry in 3h)
- No early warning for security events (config drift, blocked egress)
- Operational blind spot

**Required Fix**:
1. Instantiate `SystemMonitor` in orchestrator startup
2. Implement `sendAlert()` webhook delivery with retry
3. Add `/api/alerts` REST endpoint (or Telegram notification)
4. Persist alerts to SQLite (7-day rotation)
5. Add tests for alert categories: config-drift, cert-expiry, hsm-error

**Effort**: 2-3 days

---

### H2: Backup Automation Not Deployed
**Severity**: MEDIUM
**Component**: packages/shared/src/backup.ts
**Status**: Class exists but never runs

`BackupManager` class (with HSM token snapshot, encrypted tar, integrity hash) is defined but never scheduled.

**Code**:
- `backup.ts`: ~180 LOC
- Methods: `backup()`, `verify()`, `restore()`
- **Gap**: Not called by orchestrator or cron

**Current State**:
- HSM data: `/opt/lobsec/hsm/` (fscrypt encrypted)
- Offline backups: Manual only
- Restore procedure: Untested

**Risk**:
- HSM token corruption → no recovery path
- fscrypt keys lost → data permanently inaccessible
- Compliance: no backup attestation

**Required Fix**:
1. Schedule `BackupManager.backup()` on systemd timer (daily 2 AM)
2. Store encrypted backup: `/opt/lobsec/backups/daily-YYYY-MM-DD.tar.gz`
3. Rotate: keep 14 days
4. Test restore in staging annually
5. Add smoke test: verify backup integrity

**Effort**: 1-2 days

---

### H3: LUKS Full-Disk Encryption Deferred
**Severity**: MEDIUM
**Component**: Deployment (physical security)
**Status**: Deferred to maintenance window

Memory mentions "LUKS full-disk: Deferred to maintenance window (requires re-encrypt or fresh install)".

**Current**: fscrypt on 4 directories only (hsm, config, logs, .openclaw) — leaves `/etc`, system binaries, logs unencrypted.

**Gap**:
- Attacker with offline server access reads unencrypted `/etc/systemd/system/lobsec.service`
- Secrets in memory leakable (fscrypt only encrypts at rest)

**Risk**: Physical compromise → credential exposure

**Required Fix** (maintenance window):
1. Plan: 8-hour maintenance window
2. Backup all data to external drive
3. Re-encrypt with LUKS (AES-256-XTS, PBKDF2)
4. Restore from backup
5. Test HSM PIN recovery from cold boot

**Effort**: 8-10 hours downtime

---

## MEDIUM-PRIORITY ISSUES (This quarter)

### M1: Token Estimation Logic Is Rough
**Severity**: MEDIUM
**Component**: packages/proxy/src/llm-router.ts, lines 144-165
**Status**: Hard-coded assumption

Token estimation uses **4 characters per token** (line 158) as fixed ratio, but:
- Anthropic Claude: ~1 token per 3.5 characters
- OpenAI: ~1 token per 4 characters
- Ollama qwen2.5: ~1 token per 3 characters
- Multilingual: varies significantly

**Code**:
```typescript
return Math.ceil(charCount / 4); // Hard-coded 4 chars/token
```

**Impact**:
- Budget enforcement off by 25-40% for Claude
- Telemetry misleading
- Cost estimates inaccurate

**Required Fix**:
1. Use provider-specific ratios
2. Detect language (Accept-Language header) for multilingual adjustment
3. Add unit tests for Anthropic, OpenAI, Ollama

**Effort**: 4-6 hours

---

### M2: No Rate Limiting on Proxy
**Severity**: MEDIUM
**Component**: packages/proxy
**Status**: Missing entirely

`llm-router.ts` validates token and routes, but:
- No per-client rate limit
- No global rate limit
- No request queuing
- No concurrent request cap

**Risk**:
- Runaway loop floods LLM backend
- OOM from request backlog
- No protection against accidental DoS (broken tool loop)

**Required Fix**:
1. Add token bucket or sliding window rate limit
2. Config: `maxRequestsPerSecond`, `maxConcurrent`, `maxQueuedMs`
3. Return 429 Too Many Requests when limit hit
4. Log rate limit violations to audit
5. Add load test: verify concurrent cap enforced

**Effort**: 1-2 days

---

### M3: Config Validation Too Permissive
**Severity**: MEDIUM
**Component**: packages/shared/src/config.ts, packages/cli/src/commands/start.ts
**Status**: Incomplete validation

`validateHardenedConfig()` checks structure but not semantics:
- Allows provider list without valid routing
- No check: cert expiry date is in future
- No check: HSM token accessible
- No check: nftables rules won't create deadlock

**Impact**:
- Silent failures at runtime (cert expired → TLS breaks)
- Config that looks valid but isn't (HSM offline)
- No pre-flight validation before start

**Required Fix**:
1. Add semantic validators: cert dates, HSM connectivity, firewall rule syntax
2. Add pre-flight checks to `start` command
3. Return detailed errors (which cert is expired, which HSM key missing)
4. Add integration test: reject config with expired cert

**Effort**: 1-2 days

---

### M4: Audit Log Signatures Not Verified on Read
**Severity**: MEDIUM
**Component**: packages/shared/src/audit-signer.ts
**Status**: Sign-only implementation

Audit log entries are signed in batches (every 5 min) but:
- No verifier function implemented
- No log integrity check command
- No audit trail proof-of-work validation

**Impact**:
- Can't prove audit hasn't been tampered (no forensic integrity check)
- Compliance gap: logs not cryptographically verified

**Required Fix**:
1. Implement `verifyAuditBatch()` function
2. Add CLI command: `lobsec audit verify` (hash chain validation)
3. Detect tampering (signature mismatch, hash break)
4. Return detailed report of integrity violations
5. Add test: inject tampered entry, detect it

**Effort**: 1-2 days

---

### M5: HSM Module Path Hard-Coded in Some Paths
**Severity**: LOW-MEDIUM
**Component**: packages/shared/src/hsm-client.ts
**Status**: Partially parameterized

`LOBSEC_PKCS11_MODULE` env var is used, but:
- SoftHSM2 config path: `/opt/lobsec/boot/softhsm2.conf` (hard-coded)
- PIN file: `/opt/lobsec/boot/pin.env` (hard-coded)
- Token name: `"lobsec"` (hard-coded in configs)

**Impact**:
- Portability: can't move lobsec to different path
- Multi-instance: can't run two on same host (token collision)

**Required Fix**:
1. Make HSM config path parameterized via env var or config
2. Add support for multiple token instances
3. Update docs: "Path portability" section

**Effort**: 4-6 hours

---

## LOW-PRIORITY CONCERNS (Future quarters)

### L1: No Health Check Endpoint
**Severity**: LOW
**Component**: Gateway, Proxy
**Status**: Missing

Services lack `/health` or `/metrics` endpoint for:
- Load balancers (external health checks)
- Kubernetes (liveness/readiness probes)
- Monitoring systems (Prometheus scrape)

**Current**: Only systemd status check (not exportable)

**Required Fix**:
1. Add HTTP health check endpoint (fast, no dep checks)
2. Add HTTP metrics endpoint (Prometheus format)
3. Expose: cert expiry, HSM status, request counters, error rates

**Effort**: 1-2 days

---

### L2: Error Messages Leak Context
**Severity**: LOW
**Component**: Across proxy, plugin, CLI
**Status**: Minor issues

Some error responses contain hints about internal structure:
- `"API key not found for provider anthropic"` reveals provider list
- HSM key names in error logs
- File paths in stack traces

**Impact**: Minor information disclosure (not a blocker)

**Required Fix**:
1. Audit error messages for internal detail leakage
2. Log full details, return generic "unauthorized" to client
3. Add test: verify error responses don't expose internals

**Effort**: 4-6 hours

---

### L3: No OpenClaw Version Pinning Verification
**Severity**: LOW
**Component**: CLI orchestrator
**Status**: Trust assumption

Docs require OpenClaw v2026.2.24 but code doesn't verify version at startup.

**Risk**:
- User runs with wrong version → incompatible plugin
- No clear error message (silent failure or weird errors)

**Required Fix**:
1. Query OpenClaw version endpoint at startup
2. Reject if mismatch (hard error)
3. Update docs: supported versions

**Effort**: 2-3 hours

---

### L4: Test Coverage Gaps
**Severity**: LOW
**Component**: Integration tests
**Status**: 680 unit tests, limited e2e

Unit test coverage is strong, but:
- No e2e test: credential flow through all layers
- No chaos test: what if HSM goes offline mid-request
- No performance test: proxy latency under load
- No compliance test: audit trail completeness

**Required Fix**:
1. Add e2e test suite (uses real HSM, OpenClaw mock)
2. Add chaos scenarios: HSM failure, cert expiry, proxy timeout
3. Add load test: measure p99 latency at various concurrencies
4. Add compliance test: audit trail has no gaps

**Effort**: 3-5 days

---

### L5: Deployment Scripts Are Bash, Not Declarative
**Severity**: LOW
**Component**: deploy/ directory
**Status**: Works but manual

Deployment uses shell scripts (security-audit.sh, etc.) instead of:
- Terraform (IaC, repeatable)
- Ansible playbooks (idempotent)
- systemd templates (standard)

**Impact**:
- Hard to reason about final state
- Drift not detected automatically
- Backup/restore not tested

**Required Fix** (long-term):
1. Convert to Terraform for infra
2. Convert service setup to Ansible playbooks
3. Add drift detection job (systemd timer)

**Effort**: 5-7 days

---

## FRAGILE AREAS (Watch list)

### F1: Mock TLS Certificate Generation
**File**: packages/shared/src/cert-manager.ts
**Status**: Placeholder implementation

The `CertManager` class uses HSM for keys but generates mock X.509 certificates. Real X.509 generation requires:
- Proper ASN.1 DER encoding
- Signature over certificate body
- Proper serial number management
- SANs encoding

**Current Mock** doesn't produce valid certificates (would fail strict TLS validation).

**Risk**: When real TLS is wired, certificate generation will fail.

**Recommendation**: Pre-implement X.509 generation before M2 (mTLS enforcement).

---

### F2: Provider Detection Based on Request Path
**File**: packages/proxy/src/llm-router.ts, lines 116-140
**Status**: Works but fragile

Provider detection uses path pattern matching:
```typescript
if (req.path.includes("/v1/messages")) return PROVIDERS.find((p) => p.name === "anthropic");
```

**Risk**:
- Path collisions (hypothetical, but brittle)
- Requires X-LLM-Provider hint header as fallback (not always set)
- No request validation (could be garbage between delimiters)

**Recommendation**: Add unit test for each provider's distinct routes, document expected patterns.

---

### F3: fscrypt Key Rotation Not Implemented
**Component**: Deployment infra
**Status**: Encryption at rest, no key rotation

fscrypt data is encrypted with `/opt/lobsec/boot/fscrypt-key.bin`, but:
- No key rotation procedure
- Key lives for entire deployment lifecycle
- Loss of key = total data loss

**Risk**: Long-key-lifetime exposure

**Recommendation**: Plan annual key rotation (requires re-encrypt of all encrypted dirs).

---

### F4: Ollama Backend Assumes Fixed IP
**File**: packages/proxy/src/llm-router.ts, line 76
**Status**: Works in current deployment

```typescript
baseUrl: process.env["OLLAMA_BACKEND_URL"] ?? "http://<remote-gpu-host>:11435",
```

Sovereign backend is hard-coded as `<remote-gpu-host>:11435`. If IP changes:
- Proxy breaks silently
- No alerting on backend unreachable

**Risk**: IP mobility breaks inference

**Recommendation**:
- Use DNS hostname instead of IP
- Add backend health checks
- Alert on backend unreachable (HIGH severity)

---

## DOCUMENTATION GAPS

### D1: No Operator Runbook
- No troubleshooting guide for common failures
- HSM PIN recovery procedure not documented
- fscrypt unlock procedure unclear

### D2: No Architecture Diagram
- Data flow between components not visually clear
- Security layer boundaries not explicit

### D3: Upgrade Path Not Documented
- How to upgrade OpenClaw while preserving config
- fscrypt-key backup/restore procedures

---

## COMPLIANCE & AUDIT GAPS

### CA1: FedRAMP / SOC2 Alignment
Current implementation covers most controls but:
- No formal log retention policy (currently no auto-delete)
- Audit log ingestion into external system not implemented
- Certificate revocation not automated
- No disaster recovery test schedule

### CA2: Secrets Exposure Risk (Low)
- `.env` properly gitignored
- PIN files in unencrypted `/opt/lobsec/boot/` (acceptable for bootstrap)
- No hardcoded secrets found in code review

---

## PERFORMANCE CONCERNS

### P1: Token Estimation CPU Cost
Parsing JSON body for every request to extract model name. For high-frequency deployments:
- Consider pre-computed table (model → token ratio)
- Or cache last seen models

### P2: Audit Log Batching
Signing batches every 5 min is good, but:
- If 60k requests happen in 1 min, all await batch signature
- Consider per-second batching or async signing

---

## SUMMARY TABLE

| Issue | Component | Severity | Status | Est. Effort |
|-------|-----------|----------|--------|-------------|
| **C1** | Proxy baseUrl injection | CRITICAL | Not wired | 1-2d |
| **C2** | mTLS enforcement | HIGH | Mock certs | 2-3d |
| **C3** | Hardened sandbox unused | MEDIUM | Built, not used | 4-6h |
| **H1** | Monitoring not deployed | HIGH | Code exists | 2-3d |
| **H2** | Backup not automated | MEDIUM | Code exists | 1-2d |
| **H3** | LUKS full-disk | MEDIUM | Deferred | 8-10h downtime |
| **M1** | Token estimation | MEDIUM | Hard-coded | 4-6h |
| **M2** | Rate limiting | MEDIUM | Missing | 1-2d |
| **M3** | Config validation | MEDIUM | Incomplete | 1-2d |
| **M4** | Audit verification | MEDIUM | Sign-only | 1-2d |
| **M5** | HSM path hard-coded | LOW-MEDIUM | Partial params | 4-6h |
| **L1** | Health endpoint | LOW | Missing | 1-2d |
| **L2** | Error message leaks | LOW | Minor | 4-6h |
| **L3** | Version pinning | LOW | No check | 2-3h |
| **L4** | Test coverage | LOW | Gaps in e2e | 3-5d |
| **L5** | Declarative IaC | LOW | Shell scripts | 5-7d |

---

## NEXT STEPS (Prioritized)

**IMMEDIATE (This week)**:
1. Wire proxy baseUrl injection (C1) — enables actual security
2. Implement real mTLS cert generation (C2) — enables encryption
3. Activate hardened sandbox (C3) — container hardening

**SOON (Next 2 weeks)**:
4. Deploy monitoring/alerting (H1)
5. Automate backup with restore test (H2)
6. Add rate limiting (M2)

**THIS QUARTER**:
7. Full audit log verification (M4)
8. Comprehensive e2e tests (L4)
9. LUKS setup during maintenance window (H3)

---

**Document Owner**: lobsec security team
**Last Updated**: 2026-03-03
**Next Review**: 2026-03-17
