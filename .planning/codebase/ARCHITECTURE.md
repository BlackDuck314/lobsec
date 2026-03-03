# lobsec Architecture

## Overview

**lobsec** is a defense-in-depth security wrapper around [OpenClaw](https://github.com/openclaw/openclaw) (a personal AI assistant platform). It does NOT fork OpenClaw; instead, it wraps it via a modular TypeScript monorepo with four main packages that enforce security policies across nine hardening layers.

- **Upstream**: OpenClaw v2026.2.24 at `/opt/lobsec/openclaw`, WebSocket at `ws://127.0.0.1:18789`
- **Runtime**: Node.js 22 LTS, TypeScript strict, pnpm monorepo, Vitest (680 tests), oxlint zero-warnings
- **Deployment**: Ubuntu 25.04, rootless Docker, systemd, HSM-backed audit signing

---

## Core Design Principles

1. **Zero Upstream Modification** — OpenClaw source untouched; lobsec hooks via plugin interface and network proxies
2. **Integration-First Architecture** — All components tested against real dependencies (OpenClaw, SoftHSM2, Ollama, Anthropic)
3. **Defense in Depth** — Nine security layers, each independently verifiable and testable
4. **Sovereign-First Routing** — Local/private inference defaults; cloud fallback only when explicitly configured
5. **Auditable by Design** — HSM-signed audit logs, credential lifecycle traceability, drift detection

---

## Four-Package Architecture

### 1. `@lobsec/shared` — Foundational Infrastructure

**Purpose**: Reusable security, logging, cryptography, and orchestration primitives shared by all packages.

**Key Modules**:

| Module | Purpose |
|--------|---------|
| **types/** | Shared type definitions (logs, config, credentials, OpenClaw hardening rules) |
| **logger.ts** | Structured logging with trace IDs, redaction, SHA256 chain hashing |
| **config-generator.ts** | Generate hardened OpenClaw configs, substitute credentials |
| **drift-detector.ts** | Detect config changes, cron anomalies, heartbeat failures |
| **hsm-client.ts** | Interface to SoftHSM2 for JIT credential generation, audit key signing |
| **cert-manager.ts** | mTLS certificate lifecycle (ACME + custom, P-256/ECDSA, 30-day renewal) |
| **encryption.ts** | LUKS and fscrypt managers (AES-256-XTS, per-directory encryption policies) |
| **audit-signer.ts** | HSM-backed batch signing of audit logs, hash-chain verification |
| **container-orchestrator.ts** | Docker container lifecycle, network/security validation, startup order |
| **backup.ts** | Backup manifest, component-level snapshots, restore workflows |
| **resilience.ts** | Retry with backoff, circuit breaker, graceful degradation patterns |
| **monitor.ts** | SystemMonitor for health checks, alerts, threshold-based escalation |
| **network-perimeter.ts** | nftables rules generation, port exposure validation, MDNS suppression |
| **caddy-config.ts** | Caddyfile L2 proxy generation, security headers (CSP, HSTS, etc.) |

**Exports**: 50+ types, 30+ utility functions, used by all other packages.

**Dependencies**: None (minimal, no external npm deps except types).

---

### 2. `@lobsec/plugin` — OpenClaw Message Pipeline Hooks

**Purpose**: Inject security enforcement into OpenClaw's message processing pipeline via plugin interface. Hooks fire before/after tool execution, message routing, config loading.

**Key Modules**:

| Module | Purpose |
|--------|---------|
| **hook-registry.ts** | Extensible hook system (9 named hooks: pre/post-tool, pre/post-message, config-drift, etc.) |
| **tool-validator.ts** | Validate tool calls against deny-list, detect command injection, check symlinks |
| **credential-redactor.ts** | PII/credential pattern matching in logs/LLM responses (regex-based) |
| **sovereign-router.ts** | Route inference requests to local backends (Ollama, Jetson) before cloud (Claude) |
| **config-monitor.ts** | Detect OpenClaw config drift, emit alerts on unauthorized changes |
| **openclaw-adapter/** | Adapter to integrate hooks into OpenClaw's plugin loader |

**Entry Point**: `src/index.ts` exports `HookRegistry`, `createDefaultRegistry()`, all validator/router types.

**Deployment**: Plugin JAR at `/opt/lobsec/plugins/lobsec-security/`, loaded by OpenClaw on startup.

**Dependencies**: `@lobsec/shared` (types, logger).

---

### 3. `@lobsec/proxy` — LLM Request Proxy & Credential Isolation

**Purpose**: Stand-alone HTTP/WebSocket server (127.0.0.1:18790) that intercepts LLM requests from OpenClaw, validates source, enforces budget, routes to backends, manages JIT credentials via HSM.

**Key Modules**:

| Module | Purpose |
|--------|---------|
| **server.ts** | Express/WebSocket server, request routing, error handling |
| **credential-manager.ts** | JIT credential injection (pull from HSM, inject into request, revoke after response) |
| **credential-store.ts** | In-memory cached credential store with access logging |
| **llm-router.ts** | Detect LLM provider (Anthropic, OpenAI, Ollama), extract model, estimate tokens |
| **backend-manager.ts** | Health checks, budget tracking, failover between backends, routing decisions |
| **egress-firewall.ts** | Block calls to metadata services (169.254.x.x), check destination IP allowlist |
| **webhook-validator.ts** | Validate incoming webhooks (Telegram, Slack, Discord timestamp/signature checks) |

**Entry Point**: `src/index.ts` exports `createProxyServer()`, `startProxyFromEnv()`.

**Deployment**: systemd service `lobsec-proxy` at 127.0.0.1:18790, token-authenticated.

**Dependencies**: `@lobsec/shared` (HSM, audit, resilience, network validation).

---

### 4. `@lobsec/cli` — Lifecycle Orchestrator

**Purpose**: Command-line tool (entry point: `lobsec` binary) for operator-driven lifecycle management (init, start, stop, status, logs). Manages system startup/shutdown order, health probes, configuration generation.

**Key Modules**:

| Module | Purpose |
|--------|---------|
| **commands/init.ts** | One-time initialization: generate configs, bootstrap HSM token, encrypt directories |
| **commands/start.ts** | Startup: unlock encryption, load HSM credentials, start gateway + proxy, verify health |
| **commands/stop.ts** | Shutdown: graceful service termination, audit log finalization, cleanup |
| **commands/status.ts** | Health probe: OpenClaw gateway, proxy, audit signer, HSM connectivity |
| **commands/logs.ts** | Tail audit logs, filter by component/severity, decode signed batches |
| **orchestrator.ts** | Coordinates container startup order, waits for health checks, escalates failures |
| **lifecycle.ts** | State machine for boot sequence (encryption → HSM → gateway → proxy → healthcheck) |
| **output.ts** | Structured JSON + human-readable terminal output |

**Entry Point**: `src/index.ts` (shebang: `#!/usr/bin/env node`), registered as `bin.lobsec` in package.json.

**Dependencies**: `@lobsec/shared` (all config/orchestration logic), pino logger, commander CLI framework.

---

### 5. `@lobsec/tools` — Utility Tools (Optional)

**Purpose**: External system tools (email notifications, webhook dispatchers). Minimal package; not core to security layers.

**Status**: Placeholder; not deployed in current phase.

---

## Data Flow

### Startup Sequence

```
CLI: lobsec start
  ↓
Orchestrator.startup()
  ├─→ Encryption unlock (fscrypt, LUKS via PIN)
  ├─→ HSM token initialization (SoftHSM2)
  ├─→ Load credentials into HSM (JIT secrets)
  ├─→ Generate OpenClaw hardened config (substitute creds)
  ├─→ Start Docker gateway (OpenClaw + Caddy L2 proxy)
  ├─→ Start proxy service (127.0.0.1:18790)
  ├─→ Wait for health checks (gateway, proxy, audit-signer)
  └─→ Start audit signing timer (batch HSM-sign every 5 min)
```

### Message Flow (Inference Request)

```
Telegram User
  ↓ (WhatsApp/Discord/Slack/etc. via OpenClaw webhook)
  ↓
OpenClaw Gateway (127.0.0.1:18789)
  ├─→ [Plugin: pre-tool] Validate tool call
  ├─→ [Plugin: credential-redactor] Strip PII from context
  ├─→ [Plugin: sovereign-router] Route inference locally first
  └─→ HTTP/REST to LLM backend
      ↓
      Proxy Server (127.0.0.1:18790)
      ├─→ [egress-firewall] Verify destination IP
      ├─→ [credential-manager] Fetch JIT creds from HSM
      ├─→ [llm-router] Detect backend, extract model
      ├─→ [backend-manager] Check budget, health, route
      └─→ LLM Backend (local Ollama, Jetson, or Claude cloud)
          ↓
Response (credentials injected, audit logged)
  ↓
[Plugin: post-tool] Redact logs, sign audit entry
  ↓
OpenClaw processes response, sends to channel
```

### Audit Trail

```
Every inference request → Audit log entry (JSONL)
  ↓
Batch (every 5 min or on shutdown)
  ├─→ Read unsigned entries
  ├─→ Compute SHA256 chain (hash previous batch + new entries)
  ├─→ HSM RSA-2048 sign the chain hash
  ├─→ Write signed batch to /opt/lobsec/logs/audit-signed/
  └─→ Append signature to unsigned log (immutable proof)
```

---

## Nine Security Layers

1. **Network Isolation** (nftables + Caddy L2 proxy)
   - Zero public ports; SSH/VPN only
   - Egress whitelist (no metadata services)
   - MDNS suppression

2. **Authentication & Authorization** (Token-based)
   - OpenClaw gateway: token auth only
   - Proxy: token auth
   - No default credentials

3. **Message Pipeline Security** (Plugin hooks)
   - Tool call validation (deny-list, command injection)
   - PII redaction (regex patterns for credentials, email, SSN, etc.)
   - Config drift detection

4. **Sovereign Routing** (Local-first inference)
   - Default to local Ollama or Jetson backends
   - Cloud (Claude) only on explicit fallback
   - Per-session routing state machine

5. **JIT Credential Management** (HSM-backed)
   - Credentials stored in SoftHSM2 (never in env vars long-term)
   - Per-request injection, immediate revocation
   - Audit trail of all credential accesses

6. **Encryption at Rest** (fscrypt + LUKS)
   - /opt/lobsec/hsm/ — AES-256-XTS (SoftHSM2 tokens)
   - /opt/lobsec/config/ — AES-256-XTS (OpenClaw config + secrets)
   - /opt/lobsec/logs/ — AES-256-XTS (audit logs)
   - /opt/lobsec/.openclaw/ — AES-256-XTS (OpenClaw data)

7. **Auditing & Logging** (HSM-signed)
   - Structured JSONL audit logs (traceId, component, severity, event)
   - Batch HSM signing (RSA-2048 signature chain)
   - Hash-chain verification (detect log tampering)

8. **mTLS & Certificate Management** (P-256/ECDSA, auto-renewal)
   - Self-signed CA (generated at init)
   - 30-day auto-renewal cycle
   - Enforced between proxy ↔ gateway (future)

9. **Container & Process Hardening** (systemd + Docker)
   - NoNewPrivileges, ProtectSystem=strict, ProtectHome
   - Empty CapabilityBoundingSet (minimal privileges)
   - seccomp whitelist profile (hardened sandbox image)
   - Docker rootless mode

---

## Package Dependency Graph

```
@lobsec/shared (no dependencies)
    ↑
    ├── @lobsec/plugin (depends on @lobsec/shared)
    ├── @lobsec/proxy (depends on @lobsec/shared)
    └── @lobsec/cli (depends on @lobsec/shared, pino, commander)

@lobsec/tools (no core dependencies)
```

**Import Pattern**: All packages import from `@lobsec/shared`. Sibling packages do NOT import each other (enforced via CI lint rules).

---

## Key Abstractions

### HookRegistry (Plugin)

Named hook system with priority-based execution:
- `pre-tool`: Before tool execution
- `post-tool`: After tool execution
- `pre-message`: Before message processing
- `post-message`: After message processing
- `credential-required`: When credential needed
- `config-drift`: When config changes detected
- `audit-event`: When audit log entry created
- `backend-unavailable`: When inference backend fails
- `degradation-started`: When service enters degraded mode

Each hook is async, supports early return (short-circuit), logs all fires.

### SovereignRouter (Plugin)

Stateful router for inference requests:
- **RoutingMode**: `local-only`, `local-first`, `cloud-first`, `cloud-only`
- **SessionState**: Tracks per-user/per-session routing decisions, backend health history
- Fallback logic: If local backend unreachable, escalate to next tier
- Budget tracking per backend

### CredentialManager (Proxy)

JIT lifecycle:
1. Request arrives at proxy
2. Fetch credential from HSM (per `@requestId`)
3. Inject into request header/body
4. Forward to backend
5. On response, revoke credential from HSM
6. Log access (credential ID, requester, timestamp, duration)

### ContainerOrchestrator (Shared)

Manages Docker container lifecycle with strict ordering:
- Startup: base network → gateway → proxy → audit-signer (wait for health on each)
- Shutdown: reverse order, graceful termination
- Validates security context (no privileged mode, AppArmor/seccomp profiles applied)

### CircuitBreaker & DegradationManager (Shared)

Resilience patterns for backend failures:
- **CircuitBreaker**: Fail-open after N failures, half-open retry after backoff
- **DegradationManager**: Service continues at reduced capacity (degradation level: none → partial → critical)

---

## Testing Strategy

- **Vitest**: 680 tests across 29 test files
- **Integration tests**: Real OpenClaw instance, SoftHSM2, Ollama, Docker
- **Unit tests**: Individual functions, pattern matching, config validation
- **Property-based tests**: fast-check for credential injection, log chain validation

**Test Organization**:
- `.test.ts` suffix (co-located with source)
- 100% coverage target for security-critical paths (HSM, credential, audit, routing)
- CI enforces zero lint warnings (oxlint)

---

## Configuration

### Bootstrap (`/opt/lobsec/boot/`)

Unencrypted (required at boot before filesystem decryption):
- `softhsm2.conf` — SoftHSM2 token paths and PIN policy
- `pin.env` — HSM PIN (loaded into systemd EnvironmentFile)
- `fscrypt-key.bin` — Master fscrypt key (loaded once, not re-read)

### Runtime (`/opt/lobsec/` + subdirs)

Generated by `lobsec init`:
- `.openclaw/config.json` — Hardened OpenClaw config (encrypted)
- `hsm/tokens/` — SoftHSM2 persistent state (encrypted)
- `logs/audit.jsonl` — Audit log entries (encrypted, unsigned)
- `logs/audit-signed/` — Signed audit batches
- `run/certs/` — mTLS CA + leaf certs

### Environment Variables

Loaded from:
- `/opt/lobsec/boot/pin.env` (HSM PIN)
- systemd `EnvironmentFile=` (service-specific secrets)
- `.env` (development only; `.gitignore`d)

---

## Error Handling & Recovery

1. **Plugin Hook Failure**: Logged, short-circuits to next hook, fallback inference route
2. **HSM Unavailable**: Circuit breaker opens; operations queued; retry on reconnect
3. **Backend Timeout**: Sovereign router escalates to next tier
4. **Credential Injection Failure**: Audit logged with `severity: critical`; request rejected
5. **Audit Log Signing Failure**: Unsigned entries queued; retry every 30 sec

---

## Performance & Scalability

- **Latency**: Proxy hop adds ~50ms (credential fetch + routing decision)
- **Throughput**: No bottleneck; proxy is async
- **Memory**: Gateway + proxy + audit-signer ~500MB resident (Docker limits enforced)
- **Disk**: Audit logs ~1MB/day per user; rotation policy TBD

---

## Security Considerations

1. **Threat: Direct OpenClaw Compromise** → Mitigated by plugin hooks (tool validation, redaction)
2. **Threat: Credential Leakage** → Mitigated by JIT management + HSM isolation
3. **Threat: Egress to Cloud Without Permission** → Mitigated by sovereign router + egress firewall
4. **Threat: Audit Log Tampering** → Mitigated by HSM-signed hash chain
5. **Threat: Privilege Escalation** → Mitigated by systemd hardening + seccomp
6. **Threat: Config Drift** → Mitigated by drift detector + alerts

---

## Future Roadmap

- **mTLS Enforcement**: Currently generated; not enforced between services
- **LUKS Full-Disk**: Requires re-encrypt or fresh install; deferred
- **Hardened Sandbox Active**: Image built; OpenClaw still uses default sandbox
- **Monitoring & Alerting**: SystemMonitor class exists; not deployed
- **Backup Automation**: BackupManager class exists; not deployed

---

## References

- **Source**: `/root/lobsec/packages/{plugin,proxy,shared,cli}/src/`
- **Tests**: `.test.ts` files throughout
- **Deployment**: `/etc/systemd/system/lobsec*.service`
- **OpenClaw**: https://github.com/openclaw/openclaw (v2026.2.24)
- **SoftHSM2**: https://github.com/opendnssec/SoftHSMv2 (v2.6.1)
