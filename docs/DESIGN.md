# lobsec -- Security Design Document

> **Version:** 0.1 DRAFT
> **Date:** 2026-02-24
> **Authors:** Human + Claude (design session)
> **Status:** Design phase. No code written yet.

---

## 1. What is lobsec?

lobsec is a security, privacy, and sovereign-inference hardening wrapper around [OpenClaw](https://github.com/openclaw/openclaw) -- a 224K-star open-source personal AI assistant that connects to WhatsApp, Telegram, Discord, Slack, Signal, and 15+ other messaging platforms.

OpenClaw is a powerful system with a dangerous default posture: it binds to all network interfaces, runs tools without sandboxing, stores API keys in plaintext, and gives its AI agent unrestricted filesystem access. lobsec treats OpenClaw as an **untrusted component** -- containing it inside a paranoid security perimeter while preserving its functionality.

**lobsec does NOT fork OpenClaw.** It wraps it via configuration hardening, a runtime plugin, an LLM proxy, and OS-level containment. OpenClaw continues to be maintained upstream. lobsec configures, monitors, and constrains it.

---

## 2. Goals

| # | Goal | One-liner |
|---|------|-----------|
| G1 | Zero public attack surface | No open ports. SSH/VPN only. |
| G2 | Data sovereignty | User controls where data goes. Sensitive data never leaves local infrastructure. |
| G3 | Encrypted everything | Every byte at rest encrypted. Every byte in transit encrypted. No exceptions. |
| G4 | JIT credentials with HSM | Secrets live in hardware (or software) HSM. Injected transiently. Destroyed on shutdown. |
| G5 | Total visibility | Every tool call, every LLM request, every egress connection -- logged, auditable, tamper-evident. |
| G6 | Commodity hardware | Runs on Ubuntu 24.04 x86_64 or Jetson Orin. No cloud-specific services required. |

---

## 3. The Problem -- Why OpenClaw Needs Hardening

### 3.1 OpenClaw's Trust Model

OpenClaw is explicitly designed as a **single-user, trusted-operator** system. From its own SECURITY.md: session IDs are routing controls, not authorization boundaries. The operator is trusted. The AI agent is semi-trusted.

This is fine for a personal tool on a laptop. It is not fine for:
- A system connected to 5+ messaging platforms simultaneously
- A system with access to API keys worth thousands of dollars
- A system running on a server reachable from the internet
- A system executing arbitrary commands suggested by an AI

### 3.2 Current Running Instance -- Security Snapshot

Our running OpenClaw instance has these issues **right now**:

| Issue | Severity | Detail |
|-------|----------|--------|
| Gateway on `0.0.0.0:18789` | CRITICAL | WebSocket reachable from all network interfaces |
| Sandbox disabled | CRITICAL | `sandbox.mode: "off"` -- all tool execution on host |
| API keys in plaintext | HIGH | Anthropic key in `auth.json`, `auth-profiles.json` on disk |
| Ollama key in `/proc` | HIGH | Passed as env var on command line, visible to any process |
| Remote Ollama over HTTP | HIGH | `http://<remote-gpu-host>:11435` -- no TLS, API key in URL params |
| `dangerouslyDisableDeviceAuth` | HIGH | Device pairing auth bypassed |
| SSRF policy permissive | HIGH | `dangerouslyAllowPrivateNetwork: true` |
| mDNS advertising service | MEDIUM | Gateway discoverable on LAN |
| Auto-update enabled | MEDIUM | `openclaw update --yes` from npm = remote code execution path |
| Session transcripts unencrypted | MEDIUM | Full conversation history in plaintext JSONL |

### 3.3 Threat Landscape

37 real CVEs analyzed across 12 attack classes. See [`docs/threat-model/attack-class-taxonomy.md`](threat-model/attack-class-taxonomy.md) for full details.

| # | Attack Class | Vuln Count | Worst CVSS | lobsec Mitigation |
|---|-------------|-----------|-----------|-------------------|
| 1 | OS Command Injection | 4 | 8.8 | Sandbox + tool gating |
| 2 | SSRF | 6 | 7.6 | Egress proxy + allowlist |
| 3 | Webhook Auth Bypass | 3 | 8.2 | HSM-backed signature verification |
| 4 | Path Traversal | 4 | 7.5 | Container filesystem isolation |
| 5 | WebSocket/Gateway Abuse | 2 | 8.8 | Reverse proxy + origin validation |
| 6 | Sandbox Bypass | 4 | 8.1 | Independent policy enforcement |
| 7 | Credential Leakage | 4 | 7.5 | HSM + log redaction |
| 8 | XSS | 2 | 6.1 | CSP headers (mostly upstream) |
| 9 | Network Discovery | 1 | 5.3 | mDNS kill + VPN-only |
| 10 | Supply Chain (Skills) | 1 | 9.8 | Allowlist + sandbox + signing |
| 11 | Insecure Defaults | 3 | -- | Hardened config (core mission) |
| 12 | Prompt Injection | 3 | -- | Defense-in-depth (no perfect fix) |

---

## 4. Architecture Overview

### 4.1 The Three Components

lobsec consists of three components that wrap OpenClaw at different layers:

```
                    +-----------+
                    | lobsec-cli|    Orchestrator. The ONLY trusted component.
                    | (host)    |    Generates config, manages HSM, starts containers,
                    +-----+-----+    runs audits, rotates certs/credentials.
                          |
          +---------------+---------------+
          |               |               |
    +-----+-----+  +-----+------+  +-----+------+
    | lobsec-   |  | lobsec-    |  | lobsec-    |
    | plugin    |  | proxy      |  | (config)   |
    | (runtime) |  | (network)  |  | (static)   |
    +-----------+  +------------+  +------------+
    Hooks into      Sits between    Hardened
    OpenClaw's      OpenClaw and    openclaw.json
    25+ plugin      ALL external    with safe
    hooks for       services for    defaults,
    runtime         routing,        deny lists,
    enforcement     filtering,      sandbox=all
                    and audit
```

**lobsec-cli** (host process, not containerized):
- Generates hardened `openclaw.json` from template
- Manages HSM (SoftHSM2/YubiHSM2) via PKCS#11
- Retrieves credentials from HSM, injects into containers
- Issues internal mTLS certificates
- Manages LUKS/fscrypt encrypted storage
- Starts/stops Docker containers
- Runs `openclaw security audit` and validates
- Rotates credentials and certificates on schedule
- The ONLY component with HSM access

**lobsec-plugin** (runs inside OpenClaw's process):
- Hooks into OpenClaw's 25+ plugin lifecycle hooks
- `before_tool_call`: validates commands, paths, enforces deny lists
- `before_model_resolve`: sovereign/public routing decision
- `message_sending`: output validation, credential leak detection
- `tool_result_persist` + `before_message_write`: secret redaction
- `llm_input` + `llm_output`: audit logging
- `registerCommand`: `/sovereign`, `/public` user commands
- Monitors config drift, HEARTBEAT.md changes, cron job creation

**lobsec-proxy** (separate container):
- HTTP server on internal Docker network
- Receives ALL outbound traffic from OpenClaw (via `HTTP_PROXY`/`HTTPS_PROXY` + `baseUrl` override)
- LLM routing: sovereign (Jetson/remote GPU) vs. public (cloud APIs)
- Egress filtering: domain allowlist, RFC1918 denylist, IPv6-mapped block
- Webhook validation: cryptographic signature verification (HSM-backed)
- Holds real API keys in memory (OpenClaw never sees them)
- Full request/response audit logging

### 4.2 Container Architecture

Six isolation domains. OpenClaw is treated as untrusted. No container trusts another.

```
                        INTERNET
                           |
                           X  (no open ports -- SSH/Tailscale only)
                           |
             +-------------+---------------------------+
             |      HOST (Ubuntu 24.04)                |
             |  nftables default-deny                  |
             |  Docker rootless                        |
             |  LUKS full-disk encryption              |
             |  fscrypt per-directory encryption        |
             |                                         |
             |  lobsec-cli (TRUSTED, HSM access)       |
             |                                         |
             |  Docker network: lobsec-internal        |
             |  (--internal, no internet route)        |
             |       |            |           |        |
             |  +----+----+ +----+-----+ +---+------+ |
             |  | caddy   | | openclaw | | lobsec   | |
             |  | (L2)    | | gateway  | | proxy    | |
             |  | TLS     | | UNTRUSTED| | (L5/L8)  | |
             |  +---------+ +----+-----+ +---+------+ |
             |                   |            |        |
             |  Docker network: lobsec-sandbox|        |
             |  (--internal, air-gapped)      |        |
             |       |           |            |        |
             |  +----+----+ +---+------+     |        |
             |  | sandbox  | | sandbox  |     |        |
             |  | exec     | | browser  |     |        |
             |  | (no net) | | (limited)|     |        |
             |  +----------+ +----------+     |        |
             |                                |        |
             |  Docker network: lobsec-egress |        |
             |  (internet access, proxy only) |        |
             |       |                        |        |
             |  +----+-------------------------+       |
             |  | lobsec-proxy → Cloud APIs            |
             |  |              → Jetson Orin (TLS)     |
             |  |              → Remote GPU (WG)        |
             |  +--------------------------------------+
             +------------------------------------------+
```

**Key constraint:** The openclaw-gateway container has NO route to the internet. It can only reach lobsec-proxy on the internal network. Even a complete compromise of OpenClaw cannot exfiltrate data without going through the proxy.

### 4.3 Data Flow

```
User message (WhatsApp/Telegram/Discord/etc.)
  |
  v
[Caddy] TLS termination, rate limiting, origin validation, CSP headers
  |
  v
[lobsec-proxy :8082] Webhook signature verification (HSM-backed HMAC)
  |
  v
[openclaw-gateway] Message received by OpenClaw
  |
  v
[lobsec-plugin: before_model_resolve] → Check session mode (sovereign/public)
  |
  v
[openclaw-gateway] Sends LLM request to baseUrl (lobsec-proxy :8080)
  |
  v
[lobsec-proxy :8080]
  ├─ Sovereign session → Jetson Orin (TLS) or Remote GPU (WireGuard)
  └─ Public session → Cloud API (inject real API key, OpenClaw never had it)
  |
  v
[openclaw-gateway] Receives LLM response, decides tool calls
  |
  v
[lobsec-plugin: before_tool_call] → Validate command, path, deny list
  |
  v
[sandbox-exec container] Tool executes in air-gapped container
  |
  v
[lobsec-plugin: tool_result_persist] → Redact credentials from result
  |
  v
[lobsec-plugin: message_sending] → Scan outbound for leaked secrets/PII
  |
  v
[openclaw-gateway] Sends response back through channel
  |
  v
[lobsec-plugin: llm_output] → Audit log entry (HSM-signed)
  |
  v
[lobsec-proxy :8081] Egress proxy validates outbound destination
  |
  v
User receives response
```

Every arrow in this diagram passes through a lobsec-controlled choke point. Every step is logged.

---

## 5. Security Architecture -- Nine Layers

Defense-in-depth. No single layer is trusted to be sufficient. Each assumes the layers outside it have been bypassed.

```
 Internet
    |
    X  (no open ports)
    |
[L1 Network Perimeter]     nftables default-deny, loopback binding, mDNS off
    |
[L2 Reverse Proxy Gate]    Caddy: TLS 1.3, Origin validation, CSP, rate limits
    |
[L3 Webhook Authenticator] HSM-backed signature verification per channel
    |
[L4 Gateway Policy]        Hardened config (read-only mount), tool deny lists, drift detection
    |
[L5 Egress Firewall]       Outbound allowlist, RFC1918 block, IPv6-mapped block
    |
[L6 Execution Sandbox]     Docker rootless, RO fs, cap_drop ALL, no network, seccomp, AppArmor
    |
[L7 Credential Broker]     HSM storage, JIT injection, log redaction, instant destruction
    |
[L8 Privacy Engine]        Sovereign/public routing, LLM proxy, output validation
    |
[L9 Audit Logger]          HSM-signed hash chain, structured JSON, correlation IDs
```

Full details in [`docs/architecture/security-layers.md`](architecture/security-layers.md).

Cross-reference matrix (P=Primary defense, D=Defense-in-depth):

| Attack Class | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 | L9 |
|---|---|---|---|---|---|---|---|---|---|
| 1. Command Injection | | | | D | | **P** | | | D |
| 2. SSRF | | | | | **P** | D | | D | D |
| 3. Webhook Auth | | | **P** | | | | | | D |
| 4. Path Traversal | | | | | | **P** | | | D |
| 5. WebSocket Abuse | **P** | **P** | | **P** | | | | | D |
| 6. Sandbox Bypass | | | | D | | **P** | | | D |
| 7. Credential Leakage | | | | | D | | **P** | **P** | D |
| 8. XSS | | D | | | | | | | D |
| 9. Network Discovery | **P** | | | D | | | | | D |
| 10. Supply Chain | | | | | D | **P** | | | D |
| 11. Insecure Defaults | D | D | | **P** | | D | D | | D |
| 12. Prompt Injection | | | D | D | | | | D | D |

---

## 6. Encryption Architecture

**Principle:** Every byte at rest is encrypted. Every byte in transit is encrypted.

### 6.1 At Rest

| Layer | What it protects | Mechanism |
|-------|-----------------|-----------|
| **LUKS2** (full-disk) | Everything on disk | AES-256-XTS, argon2id KDF. Protects against physical theft. |
| **fscrypt** (per-directory) | Session transcripts, workspace, logs, agent state | Per-directory AES-256 keys derived from HSM master key. Protects locked directories from running attackers. |
| **HSM** (credentials) | API keys, webhook secrets, signing keys, TLS private keys | PKCS#11 token (SoftHSM2 dev / YubiHSM2 prod). Keys encrypted inside HSM. |

### 6.2 In Transit

| Path | Encryption |
|------|-----------|
| External clients ↔ Caddy | TLS 1.3 (Let's Encrypt / self-signed / custom CA) |
| Caddy ↔ openclaw-gateway | mTLS (internal CA, HSM-backed, 24h certs) |
| openclaw-gateway ↔ lobsec-proxy | mTLS (internal CA) |
| lobsec-proxy ↔ Cloud APIs | TLS 1.3 (public PKI) |
| lobsec-proxy ↔ Jetson Orin | TLS + certificate pinning |
| lobsec-proxy ↔ Remote GPU | WireGuard tunnel |

Zero plaintext network traffic anywhere in the system.

### 6.3 Certificate Management

| Tier | Use Case | Default? |
|------|----------|---------|
| **Self-signed** | Development, local access, SSH tunnel | Default |
| **ACME (Let's Encrypt)** | Production with public domain | Public default |
| **Custom CA** | Enterprise, specific compliance | Manual |

Internal mTLS: always on, always HSM-backed, 24-hour cert lifetime, auto-rotated. Not configurable.

Full details in [`docs/architecture/encryption.md`](architecture/encryption.md).

---

## 7. Credential Management (JIT/PAM + HSM)

### 7.1 The Problem

OpenClaw stores API keys in plaintext JSON files on disk. Anyone with filesystem access can read them. They persist forever. There is no rotation, no revocation, no audit trail.

### 7.2 The Solution

```
+--------+     PKCS#11     +---------+
| lobsec | <=============> |   HSM   |
|  -cli  |                 | SoftHSM2|
+---+----+                 | or      |
    |                      | YubiHSM2|
    | 1. Retrieve key      +---------+
    | 2. Write to tmpfs
    | 3. Inject as env var
    | 4. Clear from memory
    v
+---+----------+     +---------------+
| openclaw-    |     | lobsec-proxy  |
| gateway      |     | (holds real   |
| (NEVER has   |---->|  API keys in  |
|  real keys)  |     |  memory ONLY) |
+--------------+     +-------+-------+
                             |
                             | 5. Inject real key per-request
                             | 6. Forward to upstream
                             v
                     +-------+-------+
                     |  Cloud API    |
                     +---------------+
```

**Key principle:** OpenClaw gateway NEVER holds real API keys. It holds only an internal proxy token. If the gateway is fully compromised and all its memory dumped, no real API keys are exposed.

### 7.3 Where OpenClaw Stores Credentials (three separate places)

OpenClaw scatters credentials across three locations:

| Location | What it stores | Format |
|----------|---------------|--------|
| `~/.openclaw/openclaw.json` | Channel tokens (Telegram `botToken`, Discord `token`, Slack `botToken`/`appToken`/`signingSecret`, etc.), gateway auth, model provider API keys, webhook secrets | JSON5, inline plaintext |
| `~/.openclaw/agents/<id>/agent/auth-profiles.json` | LLM API keys (Anthropic, OpenAI) | JSON, inline plaintext |
| `~/.openclaw/credentials/whatsapp/<id>/creds.json` | WhatsApp session keys (Baileys) | JSON, managed by library |

All plaintext on disk. lobsec replaces all of this.

### 7.4 lobsec Injection Strategies

| Credential Type | OpenClaw Integration Point | lobsec JIT Strategy |
|----------------|---------------------------|-------------------|
| **Telegram bot token** | `channels.telegram.tokenFile` (file path) | HSM → tmpfs file → `tokenFile` path in config |
| **IRC, Line tokens** | `tokenFile` / `passwordFile` / `secretFile` | HSM → tmpfs file → file path in config |
| **Discord, Slack, Teams tokens** | `${VAR_NAME}` env substitution in config | HSM → env var → `${DISCORD_TOKEN}` in config |
| **LLM API keys** | `auth-profiles.json` + `baseUrl` override | lobsec-proxy holds real keys; OpenClaw gets internal proxy token only |
| **Webhook signing secrets** | lobsec-proxy validates before forwarding | HSM performs HMAC directly (key never extracted) |
| **Gateway auth token** | `gateway.auth.token` via env var | HSM → env var at container startup |
| **WhatsApp session** | Baileys `creds.json` (persistent session) | fscrypt-encrypted directory (can't do JIT -- persistent) |
| **Model provider API keys** | `models.providers.*.apiKey` via `${VAR_NAME}` | HSM → env var → config substitution |

### 7.5 Credential Classes (HSM storage)

| Type | HSM Storage | Extractable? | Injection |
|------|-------------|-------------|-----------|
| LLM API keys | Secret key, sensitive | Yes (HTTP header) | lobsec-proxy env at startup |
| Channel bot tokens | Secret key, sensitive | Yes (config injection) | tmpfs file or env var |
| Webhook signing secrets | Secret key | **No** -- HSM does HMAC | HSM crypto directly |
| Audit signing key | RSA-2048 keypair | **Never** | HSM signs internally |
| Internal CA key | EC-P256 | **Never** | HSM signs CSRs internally |
| TLS private keys | EC-P256/RSA | **Never** | HSM or tmpfs cert |
| Gateway auth token | Secret key | Yes | Container env at startup |
| fscrypt master key | AES-256 | Yes (kernel needs it) | Passed to fscrypt at unlock |

30+ sensitive fields identified in OpenClaw's config schema (marked `.register(sensitive)`). Full inventory in [`docs/threat-model/verification-resolution.md`](threat-model/verification-resolution.md).

Full HSM details in [`docs/architecture/paranoid-isolation.md`](architecture/paranoid-isolation.md) Part 3.

---

## 8. Sovereign Inference

### 8.1 Three Purposes

Local/sovereign inference serves privacy, economics, and availability:

| Purpose | Mechanism |
|---------|-----------|
| **Privacy** | Sensitive conversations never leave your infrastructure |
| **Economics** | Avoid rate limits and API costs for routine tasks |
| **Availability** | Keeps working when cloud APIs are down or rate-limited |

### 8.2 Infrastructure

| Backend | Location | Models | Access |
|---------|----------|--------|--------|
| Jetson Orin | Local LAN | gemma3:1b, llama3.2:3b, qwen2.5-coder:3b | TLS + cert pinning |
| Remote GPU | Privately hosted | qwen2.5:32b | WireGuard tunnel |
| Cloud APIs | Internet | Claude, GPT-4, etc. | TLS 1.3, API keys in proxy |

### 8.3 Routing

User-declared, not automatic:
- `/sovereign` command → local backends only, NEVER cloud
- `/public` command → cloud-first with local fallback
- Per-channel defaults configurable (e.g., WhatsApp → sovereign)
- Budget/rate limit exceeded → automatic fallback to local

Automatic PII classification was evaluated and rejected (ADR-4): regex detection has ~60-70% recall, NER adds latency, the user knows better than any classifier whether their conversation is sensitive.

---

## 9. OpenClaw Integration Points

### 9.1 What We Verified (against running instance)

| Integration Point | Verified? | How lobsec Uses It |
|-------------------|----------|-------------------|
| `openclaw.json` config schema | YES | lobsec-cli generates hardened config |
| `${VAR_NAME}` env substitution | YES | Inject credentials at startup |
| `baseUrl` per-provider override | YES | Route all LLM traffic through proxy |
| 25+ plugin hooks | YES | lobsec-plugin runtime enforcement |
| `before_tool_call` can block | YES | Tool policy gating |
| `before_model_resolve` can override | YES | Sovereign/public routing |
| `HTTP_PROXY`/`HTTPS_PROXY` env vars | Likely | Route all egress through proxy |
| `openclaw security audit --json` | YES | Startup validation |
| `config.patch` WebSocket RPC | YES | **MUST block** -- can weaken any config |
| Docker sandbox via `docker` binary | YES | lobsec provides sandbox config |
| Plugin loading from directory | YES | lobsec-plugin installed as OpenClaw plugin |
| Env var sanitization for containers | YES | Blocks credential patterns from sandbox |

### 9.2 What We Discovered (source code + runtime exploration)

| Finding | Security Impact | lobsec Response |
|---------|----------------|-----------------|
| `setupCommand` runs `sh -lc` unsanitized | RCE via config.patch | Block via read-only config + tool deny |
| Auto-update = npm install = RCE | Supply chain attack | Disable: `update.auto.enabled: false` |
| Plugin allowlist open by default | Malicious plugin auto-loads | Enforce closed allowlist |
| Plugin code scanner is warn-only | Malicious code passes install | lobsec-plugin validates independently |
| Browser sandbox exposes CDP/VNC ports | Remote debugging access | Block or constrain to loopback |
| Memory system uses SQLite + sqlite-vec | Additional data store (PII) | fscrypt covers directory |
| `OPENCLAW_BROWSER_CONTROL_MODULE` env | Arbitrary module injection | Block via container env sanitization |
| 10+ env vars override module paths | Code injection via env | Strip dangerous env vars at startup |
| Config file rewritten at startup | Migration can weaken config | Mount read-only, verify after startup |
| Gateway logs in /tmp (plaintext) | Log leakage | Redirect to encrypted directory |
| Ollama API key visible in `/proc` | Credential exposure | Never pass keys as command-line args |
| Remote Ollama over plain HTTP | Traffic interception | lobsec-proxy adds TLS + cert pinning |
| `tools.elevated` = sandbox escape hatch | Host execution bypass | Disable: `tools.elevated.enabled: false` |
| `$include` merges external config files | Config injection vector | Disable or restrict includes |
| Config hot-reload can apply channel changes live | Runtime config weakening | Read-only mount prevents writes |
| 30+ `.register(sensitive)` fields in schema | Credential inventory | All must be HSM-backed |

### 9.3 What We Learned from Official Docs (docs.openclaw.ai)

| Topic | Key Finding | lobsec Impact |
|-------|------------|--------------|
| Channel credential storage | Tokens in `openclaw.json`, LLM keys in `auth-profiles.json`, WhatsApp in `credentials/` | Three separate injection strategies needed |
| `tokenFile` pattern | Telegram, IRC, Line support file-based token loading (built for NixOS) | Perfect for HSM → tmpfs → tokenFile JIT |
| Secure baseline config | Official hardened config template available | Use as lobsec-cli generation baseline |
| DM policies | `pairing` (default), `allowlist`, `open`, `disabled` | lobsec enforces `pairing` or `allowlist` |
| Tool groups | `group:automation`, `group:runtime`, `group:fs` | lobsec denies `group:automation` + `group:runtime` by default |
| Incident response | Stop → rotate → audit procedure documented | lobsec automates: HSM destroy → restart → audit |
| Dangerous flags | 11 `dangerously*` flags documented | lobsec blocks ALL at startup |

Full verification details in [`docs/threat-model/verification-resolution.md`](threat-model/verification-resolution.md).

---

## 10. Decisions Made (ADR Summary)

| ADR | Decision | Status |
|-----|----------|--------|
| ADR-1 | **Wrapper, not fork.** Plugin + proxy + config. Don't modify OpenClaw source. | CONFIRMED |
| ADR-2 | **HSM primary** (SoftHSM2 dev, YubiHSM2 prod) via PKCS#11. Same API, zero code changes between environments. | CONFIRMED |
| ADR-3 | **Per-deployment rotation** + HSM instant revocation (`C_DestroyObject`). | CONFIRMED |
| ADR-4 | **User-declared sovereign/public**, not automatic PII classifier. Manual switch, per-channel defaults. | CONFIRMED |
| ADR-5 | **Sovereign inference is first-class** -- privacy, economics, availability. Not just a privacy feature. | CONFIRMED |
| ADR-6 | **Three components**: lobsec-cli (orchestrator), lobsec-plugin (runtime), lobsec-proxy (network). | CONFIRMED |
| ADR-7 | **Use OpenClaw native security**, don't reimplement. Configure what exists, add what's missing. | CONFIRMED |
| ADR-8 | **`auth-profiles.json` on tmpfs**. Never on persistent disk. Bind-mounted read-only into container. | CONFIRMED |
| ADR-9 | **Encryption everywhere**: LUKS full-disk + fscrypt per-directory + mTLS internal + TLS 1.3 external. | DESIGNED |
| ADR-10 | **Certificate management**: self-signed default, ACME/Let's Encrypt public default, custom CA support. | DESIGNED |

Full ADR text in [`docs/STATUS.md`](STATUS.md).

---

## 11. Implementation Phases

| Phase | Layers | What | Prerequisites |
|-------|--------|------|---------------|
| **1** | L1 + L4 + L9 | Hardened config, network perimeter, audit logging | OpenClaw running (DONE) |
| **2** | L2 + L3 + L5 | Caddy reverse proxy, webhook auth, egress firewall | Phase 1 |
| **3** | L6 + L7 | Docker sandbox hardening, HSM credential broker | Docker rootless + SoftHSM2 |
| **4** | L8 | Sovereign inference routing, LLM proxy | Jetson Orin + model benchmarking |

Each phase is independently valuable. Phase 1 alone eliminates the most critical issues (open ports, no sandbox, plaintext secrets).

---

## 12. Document Map

This document is the entry point. It references but does not duplicate the detailed documents:

```
docs/DESIGN.md                          ← YOU ARE HERE (master design, the forest)
  |
  ├── docs/STATUS.md                    ← ADR decisions, open questions, project state
  |
  ├── docs/threat-model/
  |     ├── attack-class-taxonomy.md    ← 12 attack classes, 37 CVEs, mitigation assessment
  |     └── verification-resolution.md  ← 7 items verified against running OpenClaw
  |
  └── docs/architecture/
        ├── security-layers.md          ← 9 layers, cross-reference matrix, hardened config template
        ├── paranoid-isolation.md       ← Container isolation, total visibility, JIT/PAM/HSM
        └── encryption.md              ← LUKS, fscrypt, mTLS, certificate management
```

**Reading order for new readers:**
1. This document (DESIGN.md) -- 15 minutes, complete picture
2. `attack-class-taxonomy.md` -- understand what we're defending against
3. `security-layers.md` -- understand the defense architecture
4. `paranoid-isolation.md` -- understand the container/HSM implementation
5. `encryption.md` -- understand the encryption implementation
6. `verification-resolution.md` -- understand what we verified against running OpenClaw
7. `STATUS.md` -- ADR details and open questions

---

## 13. Open Items

### Decided but not yet verified against running system

| # | Item | Blocking? |
|---|------|-----------|
| 1 | `graphene-pk11` npm: install, open SoftHSM2, store/retrieve key | Yes (Phase 3) |
| 2 | Docker `--internal` network blocks all egress | Yes (Phase 2) |
| 3 | Docker rootless + custom seccomp/AppArmor | Yes (Phase 3) |
| 4 | OpenClaw respects `HTTP_PROXY`/`HTTPS_PROXY` for ALL outbound | Yes (Phase 2) |
| 5 | OpenClaw runs with read-only root filesystem + tmpfs | Yes (Phase 3) |
| 6 | fscrypt on ext4 with HSM-derived protector | Yes (Phase 3) |
| 7 | Caddy mTLS to upstream containers | Yes (Phase 2) |
| 8 | OpenClaw `NODE_EXTRA_CA_CERTS` for internal CA | Yes (Phase 2) |
| 9 | Docker rootless + NVIDIA on Jetson Orin | Yes (Phase 4) |
| 10 | nftables compatible with Docker rootless bridge | Yes (Phase 1) |

### Not yet designed

| # | Item | Priority |
|---|------|----------|
| 1 | L8 detailed design (sovereign/public routing protocol) | Phase 4 |
| 2 | lobsec-plugin internal architecture (hook priority, error handling) | Phase 1 |
| 3 | lobsec-proxy protocol (Anthropic API? OpenAI API? translation for Ollama?) | Phase 4 |
| 4 | Monitoring and alerting (who reads L9 logs?) | Phase 2 |
| 5 | OpenClaw update strategy (update without losing lobsec config) | Phase 2 |
| 6 | Auto-update disable mechanism (config vs env vs both) | Phase 1 |
| 7 | Dangerous env var stripping at container startup | Phase 1 |
| 8 | Browser sandbox port exposure control | Phase 3 |
