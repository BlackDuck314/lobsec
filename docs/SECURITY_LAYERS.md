# Security Layer Architecture

lobsec wraps OpenClaw with nine independent security layers, ordered from the outermost network perimeter to innermost data-at-rest protections. No single layer is trusted to be sufficient. Each layer assumes every layer outside it has already been bypassed.

---

## Design Principles

1. **Wrapper, not fork.** lobsec configures, proxies, and sandboxes OpenClaw. It does not modify OpenClaw source code. Every integration point uses OpenClaw's existing configuration surface, reverse proxy capabilities, or OS-level containment.

2. **Defense in depth.** No single layer is trusted to be sufficient. Each layer assumes the layers outside it may have been bypassed. Every attack class is covered by at least one primary mitigation and at least one defense-in-depth backup.

3. **Fail closed.** If a layer cannot make a security determination, it denies the request. No silent pass-through. Missing configuration, unavailable backends, and ambiguous inputs all result in denial.

4. **Auditable by design.** Every enforcement decision is logged with enough context to reconstruct the decision chain. Audit logs are tamper-evident via cryptographic hash chains and HSM-backed signing.

5. **Commodity hardware.** Everything runs on standard Linux x86_64 or ARM64 hardware. No cloud-specific services, no specialized appliances, no vendor lock-in.

---

## Layer Overview

```
 Internet
    |
    X  (no open ports -- all traffic via SSH/VPN tunnel)
    |
[L1 Network Perimeter]     nftables default-deny, loopback binding, mDNS disabled
    |
[L2 Reverse Proxy Gate]    Caddy: TLS 1.3, origin validation, CSP, rate limits
    |
[L3 Webhook Authenticator] HSM-backed signature verification per channel
    |
[L4 Gateway Policy]        Hardened config, tool deny lists, drift detection
    |
[L5 Egress Firewall]       Outbound allowlist, RFC1918 block, IPv6-mapped block
    |
[L6 Execution Sandbox]     Docker rootless, RO fs, cap_drop ALL, no network, seccomp
    |
[L7 Credential Broker]     HSM storage, JIT injection, log redaction
    |
[L8 Privacy Engine]        Sovereign/public routing, LLM proxy, output validation
    |
[L9 Audit Logger]          HSM-signed hash chain, structured JSON, correlation IDs
```

---

## Detailed Layer Documentation

### L1: Network Perimeter

**Purpose:** Ensure zero network services are reachable from the public internet. The gateway and all internal services bind exclusively to the loopback interface. No port is open to any external network.

**Implementation:** OS-level network configuration, independent of the application.

- nftables default-deny ruleset: drop all inbound on public interfaces, allow only established/related and explicit SSH.
- Gateway bound to `127.0.0.1` only via application config (`gateway.bind`).
- mDNS/Bonjour service broadcasting disabled to prevent LAN discovery.
- Remote access exclusively through SSH tunnels, WireGuard, or similar VPN. No port forwarding.
- Gateway port blocked at the firewall even if application binding config is overridden.

**What it prevents:**
- Network discovery and service enumeration (primary).
- WebSocket abuse from external networks (defense-in-depth).
- Exploitation of insecure default configurations that bind to all interfaces (defense-in-depth).

**Key configuration:**
- `gateway.bind: "127.0.0.1"` in application config.
- nftables INPUT policy: DROP. Explicit ACCEPT for SSH and established connections only.
- mDNS disabled via environment variable and/or UDP 5353 blocked.

**Independence:** Even if the application is reconfigured to bind to `0.0.0.0`, nftables blocks inbound connections at the kernel level. Even if nftables is flushed, the application still binds to loopback. Two independent mechanisms enforce the same guarantee.

---

### L2: Reverse Proxy Gate

**Purpose:** Terminate tunnel traffic and enforce protocol-level security before any request reaches the application gateway. All traffic must transit this proxy -- there is no direct path to the gateway.

**Implementation:** Caddy reverse proxy, configured and managed by lobsec.

- TLS 1.3 only with HSTS. No protocol downgrade permitted.
- Origin header validation on WebSocket upgrade requests. Only expected origins are accepted (primary mitigation for cross-site WebSocket hijacking).
- Mandatory authentication before forwarding any request.
- Security headers injected on all responses:
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- Request body size cap (10 MB) and WebSocket frame size limits for DoS mitigation.
- Per-IP connection and request rate limiting.
- DNS rebinding protection via strict host header validation.
- Trusted proxy configuration so the gateway correctly attributes client IPs.

**What it prevents:**
- Cross-site WebSocket hijacking (primary).
- XSS exploitation via missing security headers (defense-in-depth).
- Denial of service via oversized requests or connection flooding.
- DNS rebinding attacks.

**Key configuration:**
- Caddy reverse proxy pointing to `127.0.0.1:<gateway-port>`.
- `gateway.trustedProxies: ["127.0.0.1"]` in application config.
- Allowed origins list for WebSocket upgrade validation.
- Rate limit thresholds per IP.

**Independence:** Even if L1 is bypassed and an attacker reaches the gateway port directly, the gateway still requires authentication (L4). Even if L2 itself is bypassed, L3 validates webhook signatures and L4 enforces policy independently.

---

### L3: Webhook Authenticator

**Purpose:** Mandatory cryptographic signature verification for every inbound channel webhook. The system refuses to start if webhook secrets are not configured for any enabled channel.

**Implementation:** Application-level verification, enforced at startup and runtime.

- Startup gate: lobsec validates that every enabled channel has its webhook secret configured. Missing secrets prevent startup entirely.
- Per-channel verification:
  - Telegram: secret token header verification.
  - Slack: HMAC-SHA256 signature verification.
  - Discord: Ed25519 signature with bot public key.
  - WhatsApp (Cloud API): HMAC-SHA256 hub signature verification.
  - Other channels: appropriate cryptographic verification per platform specification.
- Replay protection: timestamp checks on webhook payloads, rejecting events older than 5 minutes.
- Pre-gateway verification middleware for channels where native verification is insufficient.

**What it prevents:**
- Webhook authentication bypass and message forgery (primary).
- Prompt injection via forged webhook payloads (defense-in-depth).

**Key configuration:**
- Channel-specific webhook secret fields in application config.
- Replay window threshold (default: 5 minutes).
- Enabled channel list determining which secrets are required at startup.

**Independence:** Even if L1 and L2 are bypassed and an attacker can send arbitrary HTTP requests to the webhook endpoints, L3 rejects any request without a valid cryptographic signature. This layer operates entirely on cryptographic proof, not network position.

---

### L4: Gateway Policy Enforcer

**Purpose:** Generate, enforce, and monitor a hardened application configuration. Prevent runtime configuration drift. This is lobsec's core mission layer -- it defines what the gateway is allowed to do.

**Implementation:** Configuration management via lobsec-cli, runtime enforcement via lobsec-plugin.

- Hardened configuration generation with security-critical defaults:
  - Gateway bound to loopback with token authentication.
  - Session isolation: per-channel-peer DM scope.
  - Tool deny lists blocking dangerous tool groups (automation, runtime, filesystem).
  - Mandatory sandbox mode for all agents.
  - Read-only root filesystem for sandbox containers.
  - SSRF policy denying private network access.
  - Sensitive value redaction in logs enabled.
- Configuration drift detection: periodic and startup comparison of running config against the hardened template. Any security-relevant divergence triggers an alert.
- Runtime config lock: prevention of `config.patch`/`config.apply` via WebSocket from weakening security settings (filesystem permissions, tool deny lists, and WebSocket frame filtering).
- DM access control requiring pairing-based authentication. Open DM policy blocked.
- Tool execution gating: independent validation of actual commands before execution.
- Security audit integration: `security audit` command run at startup, blocking launch on critical findings.

**What it prevents:**
- Exploitation of insecure default configurations (primary).
- WebSocket abuse via config manipulation (primary).
- Sandbox bypass via configuration weakening (defense-in-depth).
- Command injection via unauthorized tool execution (defense-in-depth).
- Prompt injection leading to configuration changes (defense-in-depth).

**Key configuration:**
- `tools.deny` list (dangerous tool groups and specific tools).
- `agents.defaults.sandbox.mode: "all"`.
- `tools.exec.security: "deny"`.
- `session.dmScope: "per-channel-peer"`.
- `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: false`.
- All `dangerously*` flags disabled.

**Independence:** Even if L1-L3 are all bypassed and an attacker sends authenticated requests, L4 ensures the gateway operates within a constrained policy envelope. Tool deny lists, sandbox requirements, and DM policies are enforced regardless of how the request arrived.

---

### L5: Egress Firewall

**Purpose:** Allowlist-based outbound network control. Prevent SSRF, data exfiltration, and unauthorized communication with internal or external services.

**Implementation:** OS-level nftables rules, Docker network isolation, and application-level SSRF policy.

- Docker sandbox containers default to `network: "none"`. Tools with no network need get no network.
- Host-level nftables egress rules for the gateway process:
  - Allow: LLM API endpoints, messaging platform APIs, loopback.
  - Block: RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Block: Link-local (`169.254.0.0/16`, `fe80::/10`).
  - Block: Cloud metadata endpoints (`169.254.169.254/32`).
  - Block: IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`, `::ffff:10.0.0.0/104`).
  - Block: All other outbound destinations.
- Application-level SSRF policy hardening: private network access denied, hostname allowlist enforced.
- DNS-level control: local resolver blocks internal hostname resolution for the gateway process.

**What it prevents:**
- Server-side request forgery (primary).
- Data exfiltration to unauthorized endpoints (defense-in-depth).
- Credential leakage via outbound requests to attacker-controlled servers (defense-in-depth).
- Cloud metadata service access from compromised containers.

**Key configuration:**
- nftables OUTPUT chain with UID/cgroup-based process matching.
- `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: false`.
- Explicit hostname allowlist for permitted outbound destinations.
- Docker network mode per container.

**Independence:** Even if the application is fully compromised (L4 bypassed) and an attacker gains code execution, L5 prevents outbound connections to unauthorized destinations at the kernel level. The nftables rules operate independently of any application-layer controls.

---

### L6: Execution Sandbox

**Purpose:** Container isolation for all tool and skill execution. Every command runs inside a restricted container with no access to the host filesystem, network, or privileged capabilities.

**Implementation:** Docker rootless with hardened container configuration.

- Docker daemon runs as an unprivileged user. Container escape lands in an unprivileged context.
- Mandatory sandbox mode: every agent uses containerized execution. No exceptions.
- Container hardening profile:
  - Read-only root filesystem.
  - All Linux capabilities dropped (`cap_drop: ALL`).
  - No network access (`network: "none"`).
  - Non-root user inside container.
  - Default Docker seccomp profile applied.
  - `no-new-privileges` flag set.
- Filesystem containment:
  - Workspace bind-mounted as the only writable volume.
  - `realpath()` canonicalization on all paths before access.
  - Symlink resolution before access to prevent traversal.
  - No access to application config or data directories from within the sandbox.
  - Dedicated tmpfs for `/tmp`.
- Scope isolation: no container reuse across agents.
- Dangerous flag suppression: refuse to start if `dangerouslyAllowReservedContainerTargets` or `dangerouslyAllowExternalBindSources` are enabled.
- Skill installation sandboxing: extract and validate in a temporary container with path traversal and symlink checks before placement.

**What it prevents:**
- OS command injection leading to host compromise (primary).
- Path traversal attacks escaping the workspace (primary).
- Sandbox bypass via container misconfiguration (primary).
- Supply chain attacks via malicious skills (defense-in-depth).

**Key configuration:**
- `agents.defaults.sandbox.mode: "all"`.
- `agents.defaults.sandbox.scope: "agent"`.
- `agents.defaults.sandbox.docker.readOnlyRoot: true`.
- Docker rootless daemon configuration.
- Custom seccomp profile (whitelist of permitted syscalls).

**Independence:** Even if L1-L5 are all bypassed and an attacker achieves code execution within the application, L6 confines that execution to an isolated container with no network, no capabilities, and a read-only filesystem. Escaping the container requires a separate kernel or Docker exploit.

---

### L7: Credential Broker

**Purpose:** Eliminate plaintext credential storage. All secrets are encrypted at rest in an HSM (hardware or software), injected transiently at runtime, and automatically redacted from logs.

**Implementation:** HSM via PKCS#11 (SoftHSM2 for development, hardware HSM for production), managed by lobsec-cli.

- Encrypted-at-rest storage tiered by deployment:
  - Full-disk encryption (LUKS2, AES-256-XTS) as the base layer.
  - Per-directory encryption (fscrypt, AES-256) for defense-in-depth.
  - HSM token storage for credentials and signing keys.
- JIT environment injection:
  - Secrets never written to application config files in plaintext.
  - Startup sequence: decrypt from HSM, export as environment variables, launch application.
  - LLM API key files generated on tmpfs at startup, destroyed on shutdown.
  - Sensitive config files bind-mounted read-only from tmpfs.
- Credential rotation:
  - Gateway auth token regenerated per deployment.
  - Webhook secrets rotated on schedule.
  - Internal mTLS certificates with short lifetimes and automatic renewal.
- Log redaction (dual layer):
  - lobsec wraps application stdout/stderr with regex redaction for API key patterns.
  - Application native log redaction enabled as defense-in-depth.
- Credential access logging: every decrypt/inject event logged with timestamp, credential ID (never the value), and target component.

**What it prevents:**
- Credential leakage from filesystem compromise (primary).
- Credential exposure in log files (primary).
- Exploitation of insecure default credential storage (defense-in-depth).
- Long-lived credential compromise via mandatory rotation.

**Key configuration:**
- HSM token and PIN configuration.
- Credential class definitions (extractable vs. non-extractable).
- Log redaction patterns for API key formats.
- `logging.redactSensitive: true` in application config.
- tmpfs mount points for transient credential files.

**Independence:** Even if all network layers (L1-L5) are bypassed and the application is compromised, L7 ensures real API keys are never present in the application's memory or configuration. The LLM proxy holds real keys; the gateway holds only an internal proxy token. Filesystem compromise yields only encrypted data.

---

### L8: Privacy Engine

**Purpose:** Enforce data sovereignty by routing inference requests to sovereign (local/private) or public (cloud) backends based on user declaration. Ensure sensitive conversations never leave controlled infrastructure.

**Implementation:** LLM proxy (lobsec-proxy) with sovereign-first routing.

- User-declared routing via commands:
  - Sovereign mode: all inference routed to local/private backends only. No cloud API calls permitted.
  - Public mode: cloud-first routing with local fallback.
  - Per-channel defaults configurable.
- LLM proxy as the sole egress point for inference:
  - All LLM traffic from the gateway routes through lobsec-proxy via `baseUrl` override.
  - The gateway never contacts LLM backends directly.
  - Real API keys held only in the proxy, never in the gateway.
- Budget-aware routing:
  - Progressive shift to local inference as API budget thresholds are reached.
  - Graceful degradation instead of hard failure.
- Output validation (post-inference):
  - Scan responses for credential patterns, system prompt leakage, and PII.
  - Block responses that fail validation.
- Prompt/response boundary enforcement:
  - Structural separation of user content (untrusted) from system prompts (trusted).

**What it prevents:**
- Sensitive data exfiltration to cloud APIs (primary).
- Credential leakage in LLM responses (primary).
- SSRF via LLM-generated requests (defense-in-depth).
- Prompt injection leading to data disclosure (defense-in-depth).

**Key configuration:**
- `baseUrl` override pointing all LLM providers to lobsec-proxy.
- Sovereign backend endpoints (local inference servers).
- Per-channel default routing mode.
- Budget thresholds for automatic routing adjustment.
- Output validation patterns.

**Independence:** Even if L1-L7 are all bypassed, L8 ensures that the only path to external LLM services goes through the proxy. The gateway has no direct network route to cloud APIs (enforced by Docker network isolation at L5/L6) and no real API keys (enforced by L7). The proxy makes the final routing decision independently.

---

### L9: Audit Logger

**Purpose:** Structured, tamper-evident logging of all security events across all layers. Provides detection, forensics, and accountability even when prevention fails.

**Implementation:** Structured JSON logging with cryptographic integrity, managed by lobsec.

- Structured JSON events with consistent schema:
  ```
  {
    "ts": "ISO-8601 timestamp",
    "layer": "L1 through L9",
    "event": "allow | deny | alert | error",
    "source": "component identifier",
    "detail": { ... },
    "trace_id": "correlation ID",
    "attack_class": [class numbers]
  }
  ```
- Event sources across all layers:
  - L1: Firewall rule hits (blocked connections).
  - L2: Rejected origins, oversized requests, rate limit triggers.
  - L3: Webhook verification failures.
  - L4: Configuration drift alerts, tool denials, security audit findings.
  - L5: Blocked egress attempts, SSRF triggers.
  - L6: Sandbox lifecycle events, capability violations.
  - L7: Credential decrypt/inject events, log redaction triggers.
  - L8: Routing decisions, output validation results.
- Hash chain integrity: each log entry includes the SHA-256 hash of the previous entry. Any tampering breaks the chain.
- HSM-backed signing: periodic batch signing of log entries using a non-extractable RSA key stored in the HSM.
- Append-only storage: log files marked append-only at the filesystem level.
- Attack class tagging: every event tagged with relevant attack class numbers, enabling queries like "show all SSRF-related events in the last 24 hours."
- Correlation IDs: trace a single request across all nine layers.

**What it prevents:**
- L9 does not prevent attacks. It provides defense-in-depth detection and forensic capability for all 12 attack classes. When prevention fails at any layer, L9 ensures the failure is recorded with enough context to investigate and respond.

**Key configuration:**
- Log output path (encrypted directory via fscrypt).
- HSM signing key reference.
- Batch signing interval.
- Retention policy.
- Alert thresholds for high-severity events.

**Independence:** L9 operates across all layers and has no dependency on any single layer functioning correctly. Even if an attacker bypasses L1-L8, the audit trail captures the bypass. The hash chain and HSM signatures ensure that log tampering is detectable even if the attacker gains filesystem access.

---

## Cross-Reference Matrix

How each layer contributes to mitigating each attack class. **P** = Primary mitigation, **D** = Defense-in-depth, **-** = Not applicable.

| Attack Class                     | L1    | L2    | L3    | L4    | L5    | L6    | L7    | L8    | L9  |
|----------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-----|
| 1. Command Injection             | -     | -     | -     | D     | -     | **P** | -     | -     | D   |
| 2. SSRF                          | -     | -     | -     | -     | **P** | D     | -     | D     | D   |
| 3. Webhook Auth Bypass           | -     | -     | **P** | -     | -     | -     | -     | -     | D   |
| 4. Path Traversal                | -     | -     | -     | -     | -     | **P** | -     | -     | D   |
| 5. WebSocket Abuse               | **P** | **P** | -     | **P** | -     | -     | -     | -     | D   |
| 6. Sandbox Bypass                | -     | -     | -     | D     | -     | **P** | -     | -     | D   |
| 7. Credential Leakage            | -     | -     | -     | -     | D     | -     | **P** | **P** | D   |
| 8. XSS (residual)               | -     | D     | -     | -     | -     | -     | -     | -     | D   |
| 9. Network Discovery             | **P** | -     | -     | D     | -     | -     | -     | -     | D   |
| 10. Supply Chain                 | -     | -     | -     | -     | D     | **P** | -     | -     | D   |
| 11. Insecure Defaults            | D     | D     | -     | **P** | -     | D     | D     | -     | D   |
| 12. Prompt Injection             | -     | -     | D     | D     | -     | -     | -     | D     | D   |

**Key observations:**

- Every attack class has at least one primary mitigation (P) and at least one defense-in-depth backup (D). No single point of failure.
- Class 5 (WebSocket Abuse) receives triple-primary coverage (L1 + L2 + L4), justified by its CVSS 8.8 severity and 1-click RCE potential.
- Class 8 (XSS) has defense-in-depth only. This is an accepted residual risk that requires upstream fixes.
- L9 provides defense-in-depth for all 12 attack classes. It does not prevent attacks but ensures every attack is detectable.

---

## Design Guarantee

Each layer operates independently. If any single layer is completely bypassed, the remaining layers still provide meaningful security. This is the core architectural guarantee.
