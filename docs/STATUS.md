# lobsec -- Project Status & Decision Log

> ADR decisions, open questions, project state.
> Updated 2026-02-24.
>
> **Start here instead:** [`docs/DESIGN.md`](DESIGN.md) is the master design document.

---

## What is lobsec?

A security, privacy, and sovereign-inference wrapper around [OpenClaw](https://github.com/openclaw/openclaw) (224K+ stars, TypeScript, MIT). OpenClaw is a personal AI assistant that connects to WhatsApp, Telegram, Discord, Slack, Signal, iMessage, Teams, Matrix, and more.

lobsec does NOT fork OpenClaw. It wraps it via:
1. **Config hardening** -- secure `openclaw.json` with safe defaults
2. **OpenClaw plugin** -- hooks into the message pipeline for runtime enforcement
3. **LLM proxy** -- sovereign inference routing between local/cloud models
4. **OS-level hardening** -- nftables, Docker rootless, Caddy, encrypted storage

---

## Goals

| # | Goal | Status |
|---|------|--------|
| G1 | Zero public attack surface -- SSH/VPN only, no exposed ports | **DEPLOYED** -- loopback only, TLS 1.3 |
| G2 | PII never leaves the local machine | **DEPLOYED** -- sovereign-first routing, proxy credential isolation |
| G3 | JIT credentials -- secrets in encrypted storage, issued per-request | **DEPLOYED** -- HSM + fscrypt + wipe-on-stop |
| G4 | Auditable by design -- every mitigation traceable from requirement to test | **DEPLOYED** -- HSM-signed audit logs, health checks |
| G5 | Deployable on commodity hardware -- Ubuntu 24.04, Jetson Orin | **DEPLOYED** -- Ubuntu 24.04+, 3 inference backends |

---

## What We've Built (design artifacts)

| Document | What it contains |
|----------|-----------------|
| `docs/threat-model/attack-class-taxonomy.md` | 12 attack classes derived from 37 real CVEs |
| `docs/architecture/security-layers.md` | 9 defense-in-depth layers (L1-L9) with cross-reference matrix |
| `docs/threat-model/verification-resolution.md` | 7 verification items resolved against running OpenClaw |
| `docs/architecture/paranoid-isolation.md` | Paranoid-level isolation: 6 containers, 3 networks, HSM/JIT/PAM, total visibility proxy |
| `docs/architecture/encryption.md` | Encryption architecture: LUKS, fscrypt, mTLS, certificate management (3 tiers) |
| `CONTRIBUTING.md` | Development guidelines and pull request process |

---

## Architecture Decision Records (ADRs)

### ADR-1: Wrapper, not fork

**Decision:** lobsec wraps OpenClaw via config + plugin + proxy. We do not modify OpenClaw source.

**Rationale:** OpenClaw has a comprehensive plugin system (25+ hooks) and `baseUrl` override for LLM routing. Plugin covers ~85% of needs. Fork adds massive maintenance burden (tracking upstream CVE patches, merge conflicts). Can always fork later with full knowledge of exactly what needs changing.

**Status:** CONFIRMED. Plugin system verified against source code.

**Trade-offs accepted:**
- No UI integration (CLI commands only for v1)
- No post-error routing control (rely on OpenClaw native failover)
- No deep session isolation changes (sessions are "routing, not security" per upstream)

---

### ADR-2: Credential storage -- HSM (SoftHSM2/YubiHSM2) via PKCS#11 ~~(SUPERSEDED)~~

**Decision:** HSM-backed credential storage as PRIMARY mechanism:
- Development: SoftHSM2 (free, software PKCS#11 token)
- Production: YubiHSM2 (hardware PKCS#11 token, ~$650)
- Same API: `graphene-pk11` npm package abstracts both via PKCS#11
- Fallback: LUKS/SOPS/Age for environments where neither HSM is available

**Rationale:** Paranoid-level security demands HSM. SoftHSM2 is free, available on all platforms, and uses the same PKCS#11 API as YubiHSM2. This means zero code changes when upgrading from dev to prod HSM. The user has consistently requested HSM integration -- it is not optional.

**What this means for JIT credentials:**
- Secrets stored as PKCS#11 objects inside HSM token
- lobsec-cli retrieves secrets via `C_FindObjects` + `C_GetAttributeValue` at startup
- Secrets injected as env vars into OpenClaw container (never on persistent disk)
- `auth-profiles.json` generated to tmpfs (`/run/lobsec/`), symlinked into OpenClaw
- Instant revocation via `C_DestroyObject` on HSM
- HSM-signed audit trail for all credential operations
- Per-deployment rotation + HSM-backed instant destruction on shutdown

**Status:** SUPERSEDED by `docs/architecture/paranoid-isolation.md` Part 3. Previous decision (LUKS/SOPS/Age baseline, HSM optional) replaced.

**Previous decision (archived):** LUKS/SOPS/Age baseline, HSM optional. Rationale was that true HSM is not available on commodity hardware. This was incorrect -- SoftHSM2 is commodity software.

---

### ADR-3: Per-deployment credential rotation + HSM-backed instant revocation ~~(UPDATED)~~

**Decision:** Credentials are rotated per deployment cycle. HSM enables instant credential destruction via `C_DestroyObject`.

**Rationale:** LLM provider API keys (Anthropic, OpenAI) and messaging platform tokens (Telegram bot token, Discord bot token) are long-lived. They don't support per-request issuance. However, HSM adds the ability to instantly destroy the local copy of any credential, which was not possible with file-based storage.

**What we keep:** Encrypted storage (HSM-backed), env injection, log redaction, rotation schedules, instant destruction.
**What we dropped:** Per-request checkout/checkin, approval gateway via WhatsApp (circular dependency), anomaly detection (premature).

**Status:** UPDATED per `docs/architecture/paranoid-isolation.md`.

---

### ADR-4: Drop automatic PII classifier as primary routing mechanism

**Decision:** Automatic RED/AMBER/GREEN content classification is NOT the primary routing mechanism. User-declared session mode (sovereign vs. public) drives routing. Automatic PII detection is a future enhancement, not a shipping feature.

**Rationale:**
- Regex PII detection: ~60-70% recall, high false positives/negatives
- NER models: add latency, still miss context-dependent PII
- The user knows better than any classifier whether their conversation is sensitive
- Building routing on unreliable classification = building on sand

**What replaces it:**
- Per-session mode: user declares `/sovereign` or `/public`
- Per-channel defaults: WhatsApp → sovereign, WebChat → public (configurable)
- Automatic PII detection as advisory/audit layer (L9), not routing decision

**Status:** DECIDED in this session. Needs to be reflected in L8 design update.

---

### ADR-5: Sovereign inference is a first-class feature, not just privacy

**Decision:** Local/sovereign inference routing serves THREE purposes:
1. **Privacy** -- sensitive data never leaves your infrastructure
2. **Economics** -- avoid rate limits and API costs
3. **Availability** -- keeps working when cloud APIs are down or rate-limited

**Infrastructure:**
- Jetson Orin (local LAN): gemma3:1b, llama3.2:3b, qwen2.5-coder:3b
- Remote GPU (privately hosted, via WireGuard): qwen2.5:32b
- Cloud APIs (Anthropic, OpenAI): best quality, expensive, rate-limited

**Routing logic (in lobsec LLM proxy):**
- Sovereign session → local only (Jetson + remote GPU, NEVER cloud)
- Public session → cloud-first with local fallback on rate limit/error
- Budget/rate limit exceeded → automatic fallback to local

**OpenClaw integration:** `before_model_resolve` plugin hook + `baseUrl` per-provider config + OpenClaw native failover.

**Status:** DECIDED in this session. Needs formal design in L8 update.

---

### ADR-6: lobsec is three components

**Decision:** lobsec consists of:

1. **lobsec-cli** -- Config generator + startup manager + security audit runner
   - Generates hardened `openclaw.json`
   - Manages encrypted credential storage
   - Starts OpenClaw with injected env vars
   - Runs `openclaw security audit` and validates
   - Manages nftables rules, Caddy config, Docker setup

2. **lobsec-plugin** -- OpenClaw plugin for runtime security enforcement
   - `before_tool_call` → tool policy gating (L4, L6)
   - `before_model_resolve` → sovereign/public routing (L8)
   - `message_sending` → output validation (L8)
   - `tool_result_persist` + `before_message_write` → secret redaction (L7)
   - `llm_input` + `llm_output` → audit (L9)
   - `registerCommand` → `/sovereign`, `/public` commands

3. **lobsec-proxy** -- LLM privacy/sovereignty proxy
   - HTTP server on localhost
   - Receives all LLM API calls from OpenClaw (via `baseUrl` override)
   - Routes to Jetson / remote GPU / Cloud based on session mode
   - PII tokenization for AMBER data (future)
   - Budget tracking and rate limit detection

**Status:** DEPLOYED. All three components running in production:
- **lobsec-plugin**: 9 security hooks active (tool gate, credential redaction, sovereign routing, config drift, audit)
- **lobsec-proxy**: HTTPS on 127.0.0.1:18790, credential injection for Anthropic, egress firewall
- **lobsec-cli**: Replaced by systemd service units + HSM extraction scripts (no standalone CLI needed)

---

### ADR-7: OpenClaw native security features -- use, don't reimplement

**Decision:** Wherever OpenClaw already has a security feature, lobsec configures it rather than reimplementing.

**OpenClaw already has:**
- Tool deny lists (`tools.deny`)
- Tool execution security modes (`tools.exec.security: "deny" | "allowlist" | "full"`)
- Sandbox modes (`agents[*].sandbox.mode: "off" | "non-main" | "all"`)
- DM pairing policy (`dmPolicy: "pairing"`)
- SSRF policy (`browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`)
- Log redaction (`logging.redactSensitive`)
- Security audit CLI (`openclaw security audit --json --deep --fix`)
- Config audit log (`config-audit.jsonl`)
- mDNS control (`discovery.mdns.mode`)

**lobsec's job:** Enforce the right values, detect drift, add what's missing.

**Status:** CONFIRMED. Full config schema mapped in verification-resolution.md.

---

### ADR-8: `auth-profiles.json` managed via tmpfs

**Decision:** Never store plaintext API keys on persistent disk.

**Mechanism:**
1. lobsec-cli retrieves credentials from HSM via PKCS#11 at startup
2. Writes `auth-profiles.json` to tmpfs (`/run/lobsec/`)
3. Bind-mounts into openclaw-gateway container as read-only
4. OpenClaw reads from mount, sees normal file
5. On shutdown: tmpfs unmounted, secrets gone

**Status:** DECIDED. `auth-profiles.json` schema fully mapped. Updated to reflect HSM-primary (ADR-2 supersede).

---

### ADR-9: Encryption everywhere -- LUKS + fscrypt + mTLS

**Decision:** Triple-layer encryption:
- **At rest (disk):** LUKS2 full-disk encryption (AES-256-XTS, argon2id KDF)
- **At rest (file):** fscrypt per-directory encryption for `.openclaw/` data directories
- **At rest (secrets):** HSM (PKCS#11) for all credentials and signing keys
- **In transit (external):** TLS 1.3 only, via Caddy
- **In transit (internal):** mTLS between all Docker containers on `lobsec-internal`
- **In transit (backends):** TLS + cert pinning to Ollama, WireGuard to remote GPU

**Rationale:** No byte readable by unauthorized party, whether threat is physical disk theft (LUKS), running attacker with filesystem access (fscrypt), network sniffer (mTLS), or compromised container (HSM).

**Status:** DEPLOYED (fscrypt + HSM + mTLS). LUKS deferred.
- fscrypt: 4 directories encrypted (AES-256-XTS, policy_version 2)
- HSM: SoftHSM2 with 8 data objects + RSA-2048 signing key
- mTLS: TLS 1.3 on gateway (wss://) and proxy (https://), self-signed P-256/ECDSA
- LUKS assessment (2026-02-25): Root partition (`/dev/sda3`) is unencrypted LVM → ext4.
  LUKS cannot be retrofitted in-place on a running root partition (requires reinstall or
  offline `cryptsetup reencrypt`). fscrypt already protects all sensitive lobsec data
  (`.openclaw/`, `hsm/`, credentials). LUKS would only add protection against physical
  disk theft — low priority for VPS/cloud. **Decision: defer LUKS to next OS reinstall.**

---

### ADR-10: Certificate management -- three tiers

**Decision:** Three-tier certificate strategy:
- **Self-signed** (default): lobsec-cli generates CA in HSM, issues server cert
- **ACME** (public default): Let's Encrypt via Caddy auto-HTTPS, DNS-01 challenge preferred (no open ports)
- **Custom CA**: User-provided cert + key + chain, optional HSM-stored key

Internal mTLS always uses HSM-backed self-signed CA (not configurable). Supports Let's Encrypt, ZeroSSL, Buypass, and custom ACME CAs. All certificates on tmpfs (RAM only).

**Status:** DESIGNED in `docs/architecture/encryption.md`.

---

## 9 Security Layers -- Summary

| Layer | Name | Primary Attack Classes | Integration |
|-------|------|----------------------|-------------|
| L1 | Network Perimeter | 9 (Discovery), 11 (Defaults) | Config + OS (nftables) |
| L2 | Reverse Proxy Gate | 5 (WebSocket, CVSS 8.8), 8 (XSS) | Caddy + Config |
| L3 | Webhook Authenticator | 3 (Webhook Bypass, 3 vulns) | Startup check + Plugin audit |
| L4 | Gateway Policy Enforcer | 11 (Defaults), 5 (WebSocket), 6 (Sandbox Bypass) | Config + **Plugin** |
| L5 | Egress Firewall | 2 (SSRF, 6 vulns) | Config + OS (nftables) |
| L6 | Execution Sandbox | 1 (Cmd Injection), 4 (Path Traversal), 6 (Bypass) | Config + Docker + **Plugin** |
| L7 | Credential Broker | 7 (Credential Leakage, 4 vulns) | Startup mgmt + **Plugin** |
| L8 | Privacy/Sovereignty Engine | 7 (Info Disclosure), 12 (Prompt Injection) | **Plugin** + **LLM Proxy** |
| L9 | Audit Logger | All 12 classes (detection) | **Plugin** + File + CLI |

---

## Cross-Reference: Layers × Attack Classes

**P** = Primary, **D** = Defense-in-depth

| Attack Class (vulns) | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 | L9 |
|---|---|---|---|---|---|---|---|---|---|
| 1. Command Injection (4) | | | | D | | **P** | | | D |
| 2. SSRF (6) | | | | | **P** | D | | D | D |
| 3. Webhook Auth (3) | | | **P** | | | | | | D |
| 4. Path Traversal (4) | | | | | | **P** | | | D |
| 5. WebSocket Abuse (2) | **P** | **P** | | **P** | | | | | D |
| 6. Sandbox Bypass (4) | | | | D | | **P** | | | D |
| 7. Credential Leakage (4) | | | | | D | | **P** | **P** | D |
| 8. XSS (2) | | D | | | | | | | D |
| 9. Network Discovery (1) | **P** | | | D | | | | | D |
| 10. Supply Chain (1) | | | | | D | **P** | | | D |
| 11. Insecure Defaults (3) | D | D | | **P** | | D | D | | D |
| 12. Prompt Injection (3) | | | D | D | | | | D | D |

---

## Implementation Phases

| Phase | Layers | What | Prereqs |
|-------|--------|------|---------|
| **1** | L1 + L4 + L9 | Perimeter + hardened config + audit logging | **DEPLOYED** |
| **2** | L2 + L3 + L5 | Proxy + webhook auth + egress firewall | **DEPLOYED** |
| **3** | L6 + L7 | Sandbox hardening + credential broker | **DEPLOYED** |
| **4** | L8 | Privacy/sovereignty engine | **DEPLOYED** |

---

## Verified Findings (from running OpenClaw)

| Finding | Impact | Resolved? |
|---------|--------|-----------|
| `config.patch` can override ANY security setting at runtime | CRITICAL -- must block at L2+L4 | Yes |
| `auth-profiles.json` stores API keys in plaintext | HIGH -- L7 tmpfs strategy | Yes |
| `gateway.bind` defaults to `"lan"` | CRITICAL -- L1 sets loopback | Yes |
| `sandbox.mode` defaults to `"off"` | CRITICAL -- L4 sets "all" | Yes |
| `ssrfPolicy.dangerouslyAllowPrivateNetwork` defaults `true` | HIGH -- L5 sets false | Yes |
| OpenClaw has 25+ plugin hooks covering full pipeline | POSITIVE -- enables plugin approach | Yes |
| `baseUrl` override per provider | POSITIVE -- enables LLM proxy (L8) | Yes |
| Sessions are "routing, not security" (per SECURITY.md) | Design constraint -- L4 can't rely on session isolation | Yes |
| Skills are prompt injections by design | Risk -- L10/supply chain must vet | Yes |
| Heartbeat/Cron persistence = compromise survives sessions | Risk -- L4 must monitor | Yes |
| Config supports `${VAR_NAME}` env substitution | POSITIVE -- enables L7 env injection | Yes |
| `openclaw security audit --json --deep --fix` exists | POSITIVE -- L9 can consume | Yes |
| Docker rootless + NVIDIA on Jetson Orin | UNKNOWN -- needs hardware test | No |

---

## Hardware Inventory

| Device | Location | Models | Role |
|--------|----------|--------|------|
| Jetson Orin | Local LAN | gemma3:1b, llama3.2:3b, qwen2.5-coder:3b | Fast local inference, sovereign |
| Remote GPU | Privately hosted (WireGuard) | qwen2.5:32b | Heavy sovereign inference |
| Main host | Local | N/A (runs OpenClaw + lobsec) | Gateway, proxy, config |

---

## Open Design Questions

| # | Question | Blocking? |
|---|----------|-----------|
| Q1 | Sovereign session UX: `/sovereign` command vs per-channel default vs both? | No (implement both) |
| Q2 | Remote GPU: what GPU model? Latency via WireGuard? | No (test when ready) |
| Q3 | Docker rootless + NVIDIA Container Toolkit on Jetson Orin? | Yes for L6+L8 on Jetson |
| Q4 | Do we need complexity-based model selection (simple→gemma, complex→qwen32b)? | No (future enhancement) |
| Q5 | Budget tracking: where does spend data come from? | No (future enhancement) |
| Q6 | ~~How do we handle OpenClaw upstream updates?~~ | **Resolved** (`update-openclaw.sh`: preflight, backup, pull, rollback) |

---

## What's NOT Decided Yet

1. ~~**L8 detailed design**~~ -- **DEPLOYED** (sovereign-first routing via plugin + proxy)
2. ~~**lobsec-plugin internal architecture**~~ -- **DEPLOYED** (9 hooks, tool gate, credential redaction, sovereign routing, config drift, audit)
3. ~~**lobsec-proxy protocol**~~ -- **DEPLOYED** (Anthropic Messages API via x-api-key, credential injection, egress firewall)
4. ~~**Encryption key management**~~ -- **DEPLOYED** (fscrypt + HSM + mTLS)
5. ~~**Monitoring and alerting**~~ -- **DEPLOYED** (health-check.sh every 5 min, 15 checks, structured JSONL logging)
6. ~~**Update strategy**~~ -- **DEPLOYED** (`update-openclaw.sh`: preflight, backup, git pull --ff-only, rebuild, rollback on failure)
7. ~~**Backup and recovery**~~ -- **DEPLOYED** (daily backup at 03:00 UTC, 14-day retention, HSM tokens + config + audit + TLS certs)
