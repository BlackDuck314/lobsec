# lobsec Security Layer Architecture

> Defense-in-depth wrapper design for OpenClaw hardening.
> Ordered from outermost (network perimeter) to innermost (data at rest).
>
> **Date:** 2026-02-24
> **Status:** DRAFT -- pending verification against running OpenClaw instance
> **Upstream:** [openclaw/openclaw](https://github.com/openclaw/openclaw) (224K+ stars, TypeScript, MIT)
> **Taxonomy:** Attack classes reference [`attack-class-taxonomy.md`](../threat-model/attack-class-taxonomy.md)

---

## Design Principles

1. **lobsec is a wrapper, not a fork.** We configure, proxy, and sandbox OpenClaw. We do not modify its source code. Every integration point uses OpenClaw's existing configuration surface, reverse proxy capabilities, or OS-level containment.

2. **Defense in depth.** No single layer is trusted to be sufficient. Each layer assumes the layers outside it may have been bypassed.

3. **Fail closed.** If a layer cannot make a security determination, it denies the request. No silent pass-through.

4. **Auditable by design.** Every enforcement decision is logged with enough context to reconstruct the decision chain.

5. **Commodity hardware.** Everything runs on Ubuntu 24.04 x86_64 or Jetson Orin (aarch64). No cloud-specific services required.

---

## Goals Reference

| # | Goal | Short |
|---|------|-------|
| G1 | Zero public attack surface | Perimeter |
| G2 | PII never leaves the local machine | Privacy |
| G3 | JIT credentials | Secrets |
| G4 | Auditable by design | Audit |
| G5 | Deployable on commodity hardware | Hardware |

---

## Layer Overview

```
 Internet
    |
    X  (no open ports -- all traffic via SSH/Tailscale tunnel)
    |
[L1 Network Perimeter]     nftables default-deny, loopback binding, mDNS kill
    |
[L2 Reverse Proxy Gate]    Caddy: Origin validation, mTLS, CSP, rate limits
    |
[L3 Webhook Authenticator] Mandatory signature verification per channel
    |
[L4 Gateway Policy]        Hardened openclaw.json, drift detection, tool deny
    |
[L5 Egress Firewall]       Outbound allowlist: block RFC1918/metadata/IPv6-mapped
    |
[L6 Execution Sandbox]     Docker rootless, RO fs, cap_drop ALL, no-new-privs
    |
[L7 Credential Broker]     Encrypted storage, JIT env injection, log redaction
    |
[L8 Privacy Engine]        RED/AMBER/GREEN classify, local inference routing
    |
[L9 Audit Logger]          Structured JSON, hash chain, correlation IDs
```

---

## L1: Network Perimeter

**Responsibility:** Ensure zero network services are reachable from the public internet.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 9 (Network Discovery) -- primary; Class 5 (WebSocket Abuse), Class 11 (Insecure Defaults) -- defense-in-depth |
| **Goals** | G1, G5 |
| **Phase** | 1 (deploy immediately) |

### Mechanisms

1. **nftables default-deny** -- Drop all inbound on public interfaces. Allow only established/related and explicit SSH.
2. **Loopback-only binding** -- OpenClaw gateway binds to `127.0.0.1:18789` only via `gateway.bind` config.
3. **mDNS suppression** -- Disable service broadcasting. `[NEEDS VERIFICATION]` Config key: `discovery.mdns.mode: "off"` or env `OPENCLAW_DISABLE_BONJOUR=1`.
4. **Tunnel-only remote access** -- Tailscale, WireGuard, or SSH for any non-local access. No port forwarding.
5. **Port 18789 blocked at perimeter** -- Even if binding config is overridden, nftables blocks it.

### Integration with OpenClaw

- Config: `gateway.bind: "127.0.0.1"` (or `"loopback"`) in `~/.openclaw/openclaw.json`
- Environment: `OPENCLAW_DISABLE_BONJOUR=1`
- External: nftables rules, Tailscale/WireGuard config (independent of OpenClaw)

### Previous Design

- **Validated:** VPN-only access, loopback binding
- **New:** mDNS suppression (addresses Class 9, not in previous design)
- **Modified:** Now also supports Tailscale (OpenClaw has native Tailscale Serve integration)

### Open Questions

- `[NEEDS VERIFICATION]` Does `gateway.bind` accept `"127.0.0.1"` or a named preset like `"loopback"`?
- `[NEEDS VERIFICATION]` Can `config.patch` via WebSocket override `gateway.bind` at runtime?
- `[NEEDS VERIFICATION]` How to disable mDNS -- config option or firewall UDP 5353?

---

## L2: Reverse Proxy Gate

**Responsibility:** Terminate tunnel traffic and enforce protocol-level security before requests reach OpenClaw.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 5 (WebSocket Abuse) -- primary; Class 8 (XSS), Class 11 (Insecure Defaults) -- defense-in-depth |
| **Goals** | G1, G4 |
| **Phase** | 2 |

### Mechanisms

1. **Caddy reverse proxy** between tunnel endpoint and `127.0.0.1:18789`. All traffic must transit the proxy.
2. **Origin header validation on WebSocket upgrades** -- Primary mitigation for CVE-2026-25253 (1-Click RCE via CSWSH). Only allow `Origin` headers matching expected gateway host.
3. **Mandatory authentication** -- Proxy requires valid auth token before forwarding.
4. **Security headers:**
   - `Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'`
   - `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
   - `Referrer-Policy: strict-origin-when-cross-origin`
5. **Request size limits** -- Cap body size (10 MB) and WebSocket frame size (DoS mitigation, vuln #29).
6. **Rate limiting** -- Per-IP connection and request rate limits.
7. **TLS 1.3 only** -- No downgrade. HSTS.
8. **DNS rebinding protection** -- `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback: false`
9. **Trusted proxy config** -- `gateway.trustedProxies: ["127.0.0.1"]` so OpenClaw correctly attributes client IPs.

### Integration with OpenClaw

- Config: `gateway.trustedProxies`, `gateway.controlUi.allowedOrigins`, `gateway.http.securityHeaders.*`
- External: Caddy config (lobsec-managed)
- Network: Proxy binds to tunnel interface; OpenClaw binds to 127.0.0.1:18789

### Previous Design

- **Validated:** Caddy mTLS, TLS 1.3 only, CSP headers
- **New:** Origin validation for WebSocket (primary CVE-2026-25253 mitigation), `gateway.trustedProxies`, DNS rebinding protection
- **Dropped:** WAF-style request inspection (OpenClaw's surface is WebSocket/webhook, not traditional HTTP)

### Open Questions

- `[NEEDS VERIFICATION]` Does OpenClaw's Control UI set its own CSP headers? Conflict risk.
- `[NEEDS VERIFICATION]` WebSocket frame-level inspection in Caddy -- can we validate individual WS frames at proxy level, or must L4 handle it?
- `[NEEDS VERIFICATION]` Does OpenClaw already validate WebSocket Origin in v2026.2.19? (Defense-in-depth regardless)

---

## L3: Webhook Authenticator

**Responsibility:** Mandatory cryptographic signature verification for every inbound channel webhook. Refuse to start if secrets are not configured.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 3 (Webhook Auth Bypass) -- primary; Class 12 (Prompt Injection) -- defense-in-depth |
| **Goals** | G1, G4 |
| **Phase** | 2 |

### Mechanisms

1. **Startup gate** -- lobsec refuses to start if any enabled channel's webhook secret is not configured:
   - Telegram: `X-Telegram-Bot-Api-Secret-Token` verification
   - Twilio: `X-Twilio-Signature` HMAC-SHA1
   - Telnyx: Ed25519 signature via public key
   - Slack: `X-Slack-Signature` HMAC-SHA256
   - Discord: Ed25519 with bot public key
   - WhatsApp (Cloud API): `X-Hub-Signature-256` HMAC-SHA256
   - `[NEEDS VERIFICATION]` Signal, Google Chat, Teams verification mechanisms

2. **Pre-gateway verification** -- If OpenClaw's native verification is insufficient, lobsec interposes thin HTTP middleware before webhooks reach OpenClaw.

3. **Replay protection** -- Enforce timestamp checks on webhook payloads. Reject events older than 5 minutes.

### Integration with OpenClaw

- Config: Channel-specific webhook secret fields in `~/.openclaw/openclaw.json`
- Startup: lobsec reads config, validates secrets present for each enabled channel
- `[NEEDS VERIFICATION]` Which channels use webhooks vs. persistent connections? (Baileys/WhatsApp is likely persistent, not webhooks)

### Previous Design

- **New:** Entirely new layer. Zero previous coverage of webhook authentication.

### Open Questions

- `[NEEDS VERIFICATION]` Which channels already have native verification in v2026.2.19?
- `[NEEDS VERIFICATION]` Can webhook verification happen at proxy level (L2) or must it be application-level?
- `[NEEDS VERIFICATION]` WhatsApp via Baileys -- does it use webhooks at all?

---

## L4: Gateway Policy Enforcer

**Responsibility:** Generate, enforce, and monitor a hardened OpenClaw configuration. Prevent runtime configuration drift. This is lobsec's core mission layer.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 11 (Insecure Defaults), Class 5 (WebSocket Abuse) -- primary; Class 6 (Sandbox Bypass), Class 1 (Command Injection), Class 12 (Prompt Injection) -- defense-in-depth |
| **Goals** | G1, G2, G3, G4 |
| **Phase** | 1 (deploy immediately) |

### Mechanisms

1. **Hardened config generation** -- lobsec generates and owns `~/.openclaw/openclaw.json`:
   ```
   gateway.bind: "loopback"
   gateway.auth.mode: "token"
   gateway.auth.token: <generated, stored encrypted in L7>
   session.dmScope: "per-channel-peer"
   tools.profile: "messaging"
   tools.deny: ["group:automation", "group:runtime", "group:fs",
                 "sessions_spawn", "sessions_send"]
   tools.exec.security: "deny"
   tools.exec.ask: "always"
   tools.fs.workspaceOnly: true
   agents.defaults.sandbox.mode: "all"
   agents.defaults.sandbox.scope: "agent"
   agents.defaults.sandbox.docker.readOnlyRoot: true
   browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: false
   discovery.mdns.mode: "off"
   logging.redactSensitive: true
   ```

2. **Configuration drift detection** -- Periodic + startup comparison of running config vs hardened template. Alert on any security-relevant divergence.

3. **Runtime config lock** -- Prevent `config.patch`/`config.apply` via WebSocket from weakening security:
   - Option A: `tools.deny: ["gateway"]` to block agent config changes
   - Option B: WebSocket frame filtering at L2 to block config messages
   - Option C: Filesystem permissions -- config file read-only to OpenClaw process
   - `[NEEDS VERIFICATION]` Which approach works? May need all three.

4. **DM access control** -- Require `dmPolicy: "pairing"` for all channels. Block `"open"`.

5. **Tool execution gating** -- Independent validation of actual command (not declared command) before execution. Addresses rawCommand/command[] mismatch (vuln #14).

6. **Session isolation** -- `session.dmScope: "per-channel-peer"` prevents cross-session transcript access (vuln #25).

7. **Security audit integration** -- Run `openclaw security audit --json` on startup. Parse results. Block startup if critical findings.

### Integration with OpenClaw

- Direct management of `~/.openclaw/openclaw.json`
- `tools.deny`, `tools.exec.security`, `tools.exec.safeBins` config keys
- `openclaw security audit` CLI
- File permissions on `~/.openclaw/`
- Process management: lobsec starts/supervises OpenClaw gateway

### Previous Design

- **Modified:** Previous "Tool Call Policy Engine" with custom DSL is replaced by OpenClaw's native config. OpenClaw already has tool profiles, deny lists, sandbox modes, DM policies, and security audit. lobsec's job is to enforce, not reimplement.
- **Validated:** Secure defaults, tool allowlists, session isolation, DM control
- **New:** Drift detection, `openclaw security audit` integration, `config.patch` blocking

### Open Questions

- `[NEEDS VERIFICATION]` Can `config.patch` via WebSocket override `tools.deny`?
- `[NEEDS VERIFICATION]` Does `tools.deny: ["gateway"]` block config changes?
- `[NEEDS VERIFICATION]` Full list of security-relevant config keys
- `[NEEDS VERIFICATION]` Can the agent modify its own config via tool calls?
- `[NEEDS VERIFICATION]` `openclaw security audit --json` output format

---

## L5: Egress Firewall

**Responsibility:** Allowlist-based outbound network control. Prevent SSRF and data exfiltration.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 2 (SSRF, 6 vulns) -- primary; Class 7 (Credential Leakage), Class 10 (Supply Chain) -- defense-in-depth |
| **Goals** | G1, G2 |
| **Phase** | 2 |

### Mechanisms

1. **Docker sandbox: `network: "none"` default** -- Tools with no network need get no network.

2. **Host-level nftables egress rules** for the gateway process:
   - **Allow:** LLM API endpoints, messaging platform APIs, loopback
   - **Block:** RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - **Block:** Link-local (`169.254.0.0/16`, `fe80::/10`)
   - **Block:** Cloud metadata (`169.254.169.254/32`, `fd00:ec2::254`)
   - **Block:** IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:10.0.0.0/104`) -- directly addresses vuln #13
   - **Block:** All other outbound

3. **OpenClaw SSRF policy hardening:**
   ```
   browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: false
   browser.ssrfPolicy.hostnameAllowlist: [<explicit list>]
   ```

4. **DNS-level control** -- Local resolver that blocks internal hostname resolution for OpenClaw process.

### Integration with OpenClaw

- Config: `browser.ssrfPolicy.*`
- Docker: Sandbox `network: "none"` default
- External: nftables egress rules, DNS resolver config
- Proxy: Tools needing outbound go through lobsec HTTP proxy with URL allowlist

### Previous Design

- **New:** Entirely new layer. Previous design had zero SSRF coverage. Biggest gap revealed by taxonomy.

### Open Questions

- `[NEEDS VERIFICATION]` Does OpenClaw's SSRF guard cover ALL outbound paths (tools, skills, webhooks, media, cron) or only browser tool?
- `[NEEDS VERIFICATION]` Full list of legitimate outbound destinations OpenClaw needs
- `[NEEDS VERIFICATION]` Can nftables egress rules target only the OpenClaw process (via cgroups/uidowner)?
- `[NEEDS VERIFICATION]` Feishu exfil (#15) -- `file://` scheme or HTTP to localhost?

---

## L6: Execution Sandbox

**Responsibility:** Container isolation for all tool and skill execution with filesystem containment.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 1 (Command Injection), Class 4 (Path Traversal), Class 6 (Sandbox Bypass) -- primary; Class 10 (Supply Chain) -- defense-in-depth |
| **Goals** | G1, G5 |
| **Phase** | 3 |

### Mechanisms

1. **Docker rootless** -- Daemon runs as unprivileged user. Container escape lands in unprivileged context.

2. **Mandatory sandbox mode** -- `agents.defaults.sandbox.mode: "all"`. Every agent uses containerized execution.

3. **Container hardening:**
   ```
   readOnlyRoot: true
   capDrop: ["ALL"]
   network: "none"
   user: "1000:1000"
   seccomp: default Docker profile
   no-new-privileges: true
   ```

4. **Filesystem containment:**
   - Read-only root filesystem
   - Workspace bind-mounted as only writable volume
   - `realpath()` canonicalization on all paths
   - Symlink resolution before access (vuln #30)
   - No access to `~/.openclaw/` from within sandbox
   - Dedicated tmpfs for `/tmp`

5. **Scope isolation** -- `agents.defaults.sandbox.scope: "agent"`. No container reuse across agents.

6. **Dangerous flag suppression** -- Block `dangerouslyAllowReservedContainerTargets`, `dangerouslyAllowExternalBindSources`. Refuse to start if enabled.

7. **Skill installation sandboxing** -- Extract and validate in temp container. Path traversal checks (vuln #23) and symlink resolution (vuln #30) before placing in real skill directory.

### Integration with OpenClaw

- Config: `agents.defaults.sandbox.*`
- Docker: Rootless daemon config (external to OpenClaw)
- OpenClaw has `Dockerfile.sandbox` and `Dockerfile.sandbox-browser` -- use/customize these
- `[NEEDS VERIFICATION]` Skill installation pipeline and where to intercept

### Previous Design

- **Validated:** Docker rootless, RO filesystem, cap_drop ALL, no-new-privileges, isolated browser container
- **New:** `realpath()` containment, symlink resolution, scope isolation, dangerous flag suppression, skill sandbox
- **Dropped:** Custom seccomp profiles (default is sufficient for v1)
- **Dropped:** Unix Socket IPC for Credential Broker (not needed with env injection model in L7)

### Open Questions

- `[NEEDS VERIFICATION]` Docker rootless on Jetson Orin (aarch64) + NVIDIA Container Toolkit
- `[NEEDS VERIFICATION]` Does sandbox mode prevent ALL file access outside workspace, or only tool-initiated?
- `[NEEDS VERIFICATION]` Hash collision issue (#24) -- is it fixed in current OpenClaw?

---

## L7: Credential Broker

**Responsibility:** Eliminate plaintext credential storage. Encrypted at rest, JIT injection via environment, automatic log redaction.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 7 (Credential Leakage) -- primary; Class 11 (Insecure Defaults) -- defense-in-depth |
| **Goals** | G3, G4 |
| **Phase** | 3 |

### Mechanisms

1. **Encrypted-at-rest storage** (tiered by hardware):
   - **x86_64:** LUKS-encrypted volume for `~/.openclaw/`
   - **Jetson Orin:** TPM2-sealed LUKS if available; else SOPS/Age
   - **Development:** SOPS with Age keys
   - HSM (YubiHSM2) is optional hardening, not baseline

2. **JIT environment injection:**
   - Secrets never written to OpenClaw config files in plaintext
   - lobsec startup: decrypt -> export env vars -> launch OpenClaw
   - **Finding: OpenClaw stores API keys in `auth-profiles.json`** -- lobsec must either:
     - (a) Generate `auth-profiles.json` at startup from encrypted storage, on tmpfs, destroyed on shutdown
     - (b) Find env var alternatives for all credentials in `auth-profiles.json`
     - (c) Encrypt `auth-profiles.json` at rest and decrypt to tmpfs at startup
   - `[NEEDS VERIFICATION]` Full schema of `auth-profiles.json` and whether env vars can replace it

3. **Credential rotation:**
   - Gateway auth token: regenerated per deployment
   - Webhook secrets: rotated on schedule
   - LLM API keys: rotated if provider supports it

4. **Log redaction (dual layer):**
   - lobsec wraps OpenClaw stdout/stderr with regex redaction (API key patterns: `sk-...`, `ghp_...`, `xoxb-...`, bearer tokens, etc.)
   - OpenClaw native: `logging.redactSensitive: true` as defense-in-depth

5. **Credential access logging** -- Every decrypt/inject event logged with: timestamp, credential ID (not value), target component.

### Integration with OpenClaw

- **`auth-profiles.json`** -- Key finding: this file stores per-agent API keys in plaintext. lobsec must manage this file's lifecycle.
- **Environment variables** -- `[NEEDS VERIFICATION]` Which credentials does OpenClaw read from env? (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENCLAW_GATEWAY_PASSWORD`, etc.)
- **`~/.openclaw/credentials/`** -- Plaintext credential directory. lobsec replaces with encrypted storage.
- Config: `logging.redactSensitive`, `logging.redactPatterns`
- Process: lobsec starts OpenClaw with injected env vars

### Previous Design

- **Modified:** HSM/PKCS#11 downgraded from baseline to optional. LUKS/TPM/SOPS is practical for commodity hardware (G5).
- **Dropped:** Per-request credential checkout/checkin -- impractical for real API key lifecycle
- **Dropped:** Six independent policy checks (scope, concurrency, daily limits, cooldown, time-of-day, budget) -- over-engineered for single-user
- **Dropped:** Approval Gateway via WhatsApp -- circular dependency
- **Dropped:** Anomaly Detection -- premature
- **Validated:** Encrypted storage, log redaction, rotation -- core concepts hold

### Open Questions

- `[NEEDS VERIFICATION]` Full `auth-profiles.json` schema -- what exactly is stored?
- `[NEEDS VERIFICATION]` Can ALL credentials be injected via env vars, or does OpenClaw require file-based config for some?
- `[NEEDS VERIFICATION]` Can OpenClaw hot-reload credentials or does it require restart?
- `[NEEDS VERIFICATION]` Does OpenClaw's OAuth refresh flow write tokens back to disk?
- `[NEEDS VERIFICATION]` Jetson Orin TPM2 availability on Ubuntu 24.04

---

## L8: Privacy Engine

**Responsibility:** Classify data sensitivity (RED/AMBER/GREEN) and enforce that RED data never leaves the local machine. Route RED inference to Jetson Orin.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | Class 7 (Info Disclosure), Class 12 (Prompt Injection) -- primary; Class 2 (SSRF/exfil) -- defense-in-depth |
| **Goals** | G2, G5 |
| **Phase** | 4 (most unknowns, requires Jetson Orin) |

### Mechanisms

1. **RED/AMBER/GREEN classifier:**
   - **RED:** PII detected (names, emails, phones, addresses, SSNs, financial, health). Local inference only.
   - **AMBER:** Indirect PII or context-sensitive. Tokenize before cloud, or route local.
   - **GREEN:** Non-sensitive. Cloud inference permitted.
   - v1: Regex + keyword patterns
   - v2: NER model on Jetson for higher accuracy

2. **Entity tokenizer:**
   - Deterministic, reversible: `John Smith` -> `[PERSON_1]`
   - Same entity -> same token within conversation
   - AES-256-GCM encrypted mappings per conversation, 24h TTL
   - Token collision escaping: user input containing `[TYPE_N]` patterns escaped first

3. **Local inference routing:**
   - RED -> Jetson Orin (Ollama/llama.cpp with quantized models)
   - Block any cloud API call for RED data
   - `[NEEDS VERIFICATION]` Can OpenClaw's model routing support content-based backend selection?

4. **Budget-aware routing:**
   - At 80%/90%/100% API budget thresholds, progressively shift to local
   - Graceful degradation instead of hard failure
   - `[NEEDS VERIFICATION]` Does OpenClaw expose usage/budget APIs?

5. **Output validation (post-inference):**
   - Scan responses for: credential patterns, system prompt leakage, PII, invalid tokens
   - `[NEEDS VERIFICATION]` Where in OpenClaw's response pipeline can we hook?

6. **Prompt/response boundary enforcement:**
   - Structural separation: user content (untrusted) vs system prompts (trusted)
   - No string concatenation of user content into system prompts

### Integration with OpenClaw

This layer has the **most unknowns:**

- `[NEEDS VERIFICATION]` Pi agent runtime -- how does it route LLM requests? Configurable backend URL?
- `[NEEDS VERIFICATION]` Can we register a custom model backend that is lobsec's privacy router?
- `[NEEDS VERIFICATION]` Does OpenClaw support hooks/middleware on the message pipeline?
- `[NEEDS VERIFICATION]` Streaming response interception -- can we validate in-flight?
- `[NEEDS VERIFICATION]` Can Ollama be configured as a model backend in `auth-profiles.json`?

### Previous Design

- **Validated:** RED/AMBER/GREEN classification, entity tokenizer, local inference routing, multi-pass loops, budget routing, output validation pipeline
- **Modified:** NER deferred to v2. Regex + keywords first.
- **Modified:** Integration approach -- investigate OpenClaw native multi-backend support before building custom proxy
- **Dropped:** Sub-1ms task complexity assessment -- simplify for v1

### Open Questions

- `[NEEDS VERIFICATION]` OpenClaw's LLM backend config -- dynamic routing based on content?
- `[NEEDS VERIFICATION]` Plugin/hook system for message interception?
- `[NEEDS VERIFICATION]` Jetson Orin performance with quantized models (Llama 3 8B Q4_K_M)
- `[NEEDS VERIFICATION]` Ollama compatibility with OpenClaw's Pi agent runtime
- **This is the layer with the most unknowns. Depends heavily on OpenClaw internals.**

---

## L9: Audit Logger

**Responsibility:** Structured, tamper-evident logging of all security events across all layers.

| Attribute | Detail |
|-----------|--------|
| **Attack Classes** | All 12 (detection/forensics, not prevention) |
| **Goals** | G4 |
| **Phase** | 1 (deploy immediately) |

### Mechanisms

1. **Structured JSON events:**
   ```json
   {
     "ts": "ISO-8601",
     "layer": "L1-L9",
     "event": "allow|deny|alert|error",
     "source": "<component>",
     "detail": { },
     "trace_id": "<correlation-id>",
     "attack_class": [2, 5]
   }
   ```

2. **Event sources per layer:**
   - L1: Firewall rule hits
   - L2: Rejected origins, oversized requests
   - L3: Webhook verification failures
   - L4: Config drift alerts, tool denials, audit findings
   - L5: Blocked egress, SSRF triggers
   - L6: Sandbox lifecycle, capability violations
   - L7: Credential decrypt/inject events, redaction triggers
   - L8: Classification decisions, routing decisions

3. **Hash chain integrity** -- Each entry includes SHA-256 hash of previous entry. Tamper-evident.

4. **Append-only storage** -- `chattr +a` on log files, or dedicated append-only volume.

5. **Attack class traceability** -- Every event tagged with relevant attack class(es). Enables: "show me all Class 2 events in 24h."

6. **OpenClaw audit integration** -- Periodically run `openclaw security audit --json`, log results as L4 events.

### Previous Design

- **Validated:** Structured logging, hash chain, traceability
- **Modified:** HMAC-SHA256 with HSM is optional. SHA-256 chain for v1.
- **New:** Attack class tagging, correlation IDs, OpenClaw audit integration

---

## Cross-Reference Matrix

**P** = Primary mitigation, **D** = Defense-in-depth, **-** = N/A

| Attack Class | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 | L9 |
|---|---|---|---|---|---|---|---|---|---|
| 1. Command Injection | - | - | - | D | - | **P** | - | - | D |
| 2. SSRF (6 vulns) | - | - | - | - | **P** | D | - | D | D |
| 3. Webhook Auth (3 vulns) | - | - | **P** | - | - | - | - | - | D |
| 4. Path Traversal (4 vulns) | - | - | - | - | - | **P** | - | - | D |
| 5. WebSocket Abuse (CVSS 8.8) | **P** | **P** | - | **P** | - | - | - | - | D |
| 6. Sandbox Bypass | - | - | - | D | - | **P** | - | - | D |
| 7. Credential Leakage | - | - | - | - | D | - | **P** | **P** | D |
| 8. XSS (residual) | - | D | - | - | - | - | - | - | D |
| 9. Network Discovery | **P** | - | - | D | - | - | - | - | D |
| 10. Supply Chain | - | - | - | - | D | **P** | - | - | D |
| 11. Insecure Defaults | D | D | - | **P** | - | D | D | - | D |
| 12. Prompt Injection | - | - | D | D | - | - | - | D | D |

### Key observations:

- **Every class has at least one P and one D.** No single point of failure.
- **Class 5 (WebSocket)** gets triple-primary (L1+L2+L4). Justified: CVSS 8.8, 1-click RCE.
- **Class 8 (XSS)** is weakest: D only. Accepted residual risk -- requires upstream fix.
- **L9 provides D for all 12 classes.** Doesn't prevent attacks but enables detection.

---

## Implementation Phases

| Phase | Layers | Rationale | Prereqs |
|-------|--------|-----------|---------|
| **1** | L1 + L4 + L9 | Highest impact, lowest complexity. Perimeter + config + logging. | OpenClaw running locally |
| **2** | L2 + L3 + L5 | Network controls. Proxy, webhook auth, egress. | Understanding OpenClaw's network behavior |
| **3** | L6 + L7 | Sandbox + credentials. | Docker rootless setup, encryption infra |
| **4** | L8 | Privacy engine. Most unknowns. | Jetson Orin, model benchmarking, message pipeline understanding |

---

## Residual Risks (Cannot Fix at Wrapper Level)

| Risk | Class | Why | Best Mitigation |
|------|-------|-----|-----------------|
| XSS in Control UI | 8 | Upstream output encoding needed | CSP via L2 |
| macOS/iOS/Android app vulns | 1, 8 | Client-side, outside lobsec scope | N/A (server-side only) |
| rawCommand/command[] mismatch | 6 | Upstream logic bug | Independent validation in L4 if unpatched |
| Prompt injection (structural) | 12 | Unsolved industry-wide | Defense-in-depth across L4+L6+L8 |
| LLM structural risks ("Terrifying Five") | 11 | Inherent to LLM agents | All layers contribute partial mitigation |
| Supabase RLS | 11 | Database-level fix | lobsec doesn't require Supabase |

---

## Decisions Log

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | LUKS/SOPS/Age over HSM-PKCS#11 as baseline | Commodity hardware (G5). HSM optional. |
| D2 | Per-deployment credential rotation, not per-request | Real APIs don't support per-request issuance |
| D3 | Leverage OpenClaw native security config | Wrapper, not fork. Configure > rewrite. |
| D4 | Drop WhatsApp approval gateway | Circular dependency on system being secured |
| D5 | Drop credential anomaly detection from baseline | Premature for single-user system |
| D6 | Regex + keywords for PII classification v1 | Ship fast, iterate. NER is Phase 2. |
| D7 | 9 layers with separation of concerns | Defense-in-depth requires independent failure domains |
| D8 | `auth-profiles.json` managed via tmpfs | Never store plaintext credentials on persistent disk |

---

## Critical [NEEDS VERIFICATION] -- Priority Order

Resolve these first once OpenClaw is running:

1. **Can `config.patch` via WebSocket override security settings?** (Determines if L4 is bypassable)
2. **`auth-profiles.json` full schema** (Determines L7 strategy for credential injection)
3. **Which channels use webhooks vs persistent connections?** (Determines L3 scope)
4. **OpenClaw's LLM backend routing** (Determines L8 integration approach)
5. **Docker rootless + NVIDIA Container Toolkit on Jetson Orin** (Determines L6/L8 feasibility)
6. **Full list of security-relevant config keys** (Determines L4 hardened config completeness)
7. **`openclaw security audit --json` output format** (Determines L9 integration)
