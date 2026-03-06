# lobsec

**9-layer security architecture for OpenClaw. Your agent never holds real credentials.**

[![Tests](https://img.shields.io/badge/tests-765%20passing-green)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Is (And What It Isn't)

lobsec is a security hardening wrapper for [OpenClaw](https://github.com/openclaw/openclaw), the 224K-star open-source AI assistant framework that connects WhatsApp, Telegram, Discord, Slack, Signal, iMessage, Teams, Matrix, and more.

lobsec **wraps** OpenClaw. It never forks it. It does not add AI capabilities. It does not modify OpenClaw source code. It is a security perimeter that makes OpenClaw safe to deploy on a real server connected to real messaging platforms with real API keys.

OpenClaw handles messaging, tool execution, and multi-channel coordination. lobsec handles credential isolation, inference routing, egress filtering, tool validation, and making sure a compromised agent cannot exfiltrate your API keys or reach your internal network.

Five components, zero source modifications:

| Component | Role |
|-----------|------|
| `@lobsec/plugin` | OpenClaw plugin -- hooks into the message pipeline for tool gating, credential redaction, sovereign routing |
| `@lobsec/proxy` | LLM proxy -- credential isolation, sovereign-first inference routing, egress filtering |
| `@lobsec/tools` | Plugin tools -- weather, email, calendar, contacts, GitHub issues, QA automation |
| `@lobsec/shared` | Shared primitives -- HSM client, audit logging, encryption, monitoring, resilience patterns |
| `@lobsec/cli` | CLI orchestrator -- lifecycle management, startup/shutdown, health checks |

---

## Why This Matters

AI assistants with tool access are high-value targets. They hold API keys, execute arbitrary commands, and sit on networks with access to internal services.

Deng et al.'s ["AI Agents Under Threat"](https://arxiv.org/abs/2406.02630) survey (2024, ACM Computing Surveys) and Sophos's ["Beyond the Hype"](https://news.sophos.com/en-us/2025/01/28/beyond-the-hype-the-business-reality-of-ai-for-cybersecurity/) analysis of AI-assisted attack chains (2025) both document a consistent pattern: once an attacker controls the agent, they control everything the agent can reach -- credentials, filesystems, internal networks, cloud APIs.

OpenClaw's default security posture reflects its design as a single-user tool on a trusted laptop:

- Gateway binds to all network interfaces (`0.0.0.0`)
- API keys stored in plaintext JSON on disk
- Sandbox mode disabled by default
- SSRF policy allows private network access
- No credential rotation or revocation
- Tool execution is unrestricted

This is fine on a personal laptop behind a NAT. It is not fine on a server connected to five messaging platforms with API keys worth thousands of dollars. lobsec closes every one of these gaps without touching OpenClaw's source code.

---

## What's Different

- **Credentials never touch disk.** Secrets live in an HSM (SoftHSM2 or YubiHSM2). They are injected just-in-time into ephemeral processes and wiped on shutdown. OpenClaw never holds real API keys -- only an internal proxy token. A full memory dump of the gateway reveals nothing.

- **Sovereign-first routing.** Local inference (Ollama on Jetson Orin, remote GPU) is the default. Cloud APIs are a fallback, not a primary. Sensitive conversations never leave your infrastructure unless you explicitly choose otherwise.

- **Tool call validation.** Every tool invocation passes through path containment checks, symlink resolution, command deny lists, and sandbox enforcement before execution. The plugin validates independently of OpenClaw's own sandbox.

- **Egress firewall.** Outbound traffic from the OpenClaw process is filtered by nftables default-deny rules. SSRF attempts against RFC1918 addresses, cloud metadata endpoints, and IPv6-mapped addresses are blocked at both the kernel and application layers.

- **Tamper-evident audit.** Every LLM request, tool call, routing decision, and credential access is logged to structured JSONL with HSM-signed hash chains. Logs cannot be silently modified.

---

## Comparison

|  | Config Hardening | Vault Wrapper | lobsec (Full Wrapper) |
|--|-----------------|---------------|----------------------|
| **Credential storage** | `.env` file, plaintext | External vault, fetched at startup | HSM-backed, JIT per-request, wiped on shutdown |
| **Network isolation** | Loopback binding only | Loopback + firewall rules | Zero internet route from gateway, proxy-only egress, nftables default-deny |
| **Tool validation** | Disable dangerous tools | Disable dangerous tools | Runtime validation per invocation: path containment, deny lists, sandbox enforcement |
| **Inference routing** | Single provider | Single provider | Sovereign-first multi-backend: local Ollama, remote GPU, cloud fallback |
| **Audit logging** | Application logs | Application logs + vault audit | HSM-signed hash chain, structured JSONL, correlation IDs |
| **Sandbox enforcement** | Enable Docker sandbox | Enable Docker sandbox | Independent policy enforcement, custom seccomp profile, rootless Docker, read-only filesystem |
| **Config drift detection** | Manual | Manual | Automatic: runtime drift detection, hardened config mounted read-only |

---

## Architecture

```
 Channels (Telegram, WhatsApp, Discord, Slack, Signal, ...)
    |
    | TLS 1.3
    v
 [Caddy Reverse Proxy]  -- L2: rate limiting, origin validation, security headers
    |
    v
 [OpenClaw Gateway]     -- loopback only, sandbox=all, no internet route
    |
    +-- @lobsec/plugin hooks:
    |     before_tool_call    -> tool validation, deny lists
    |     before_model_resolve -> sovereign/public routing
    |     before_message_write -> credential redaction (persistence)
    |     tool_result_persist -> secret redaction
    |     llm_input/output    -> audit logging
    |
    v
 [@lobsec/proxy]        -- L8: credential injection, egress filtering
    |
    +---> Ollama (Jetson Orin)    -- local LAN, TLS + cert pinning
    +---> Ollama (Remote GPU)     -- privately hosted, WireGuard tunnel
    +---> Cloud APIs (Anthropic)  -- TLS 1.3, API key injected per-request
```

OpenClaw never knows lobsec exists. It sees a hardened config, plugin hooks that gate risky operations, and an LLM proxy at `127.0.0.1:18790` that handles all inference routing. The real API keys live only in the proxy's memory, retrieved from the HSM at startup.

---

## Security Layers

Defense-in-depth. No single layer is trusted to be sufficient. Each layer assumes the layers outside it have been bypassed.

| Layer | Name | What It Prevents |
|-------|------|-----------------|
| L1 | Network Perimeter | Unauthorized network access. nftables default-deny, loopback-only binding, mDNS disabled, SSH/VPN only. |
| L2 | Reverse Proxy | Protocol-level attacks. Caddy with TLS 1.3, origin validation, CSP headers, rate limiting. |
| L3 | Webhook Authentication | Forged inbound messages. HSM-backed HMAC signature verification per channel. |
| L4 | Gateway Policy | Configuration weakening. Hardened `openclaw.json` mounted read-only, drift detection, tool deny lists. |
| L5 | Egress Firewall | SSRF and data exfiltration. Domain allowlist, RFC1918 blocking, metadata endpoint blocking, IPv6-mapped blocking. |
| L6 | Execution Sandbox | Container escape. Docker rootless, read-only filesystem, `cap_drop: ALL`, no-new-privileges, custom seccomp profile. |
| L7 | Credential Broker | Credential theft. HSM storage (PKCS#11), JIT injection, log redaction, immediate destruction on shutdown. |
| L8 | Privacy Engine | Data sovereignty violations. Sovereign-first routing, LLM proxy credential isolation, output validation. |
| L9 | Audit Logger | Undetected tampering. HSM-signed hash chains, structured JSONL, correlation IDs across all layers. |

Cross-reference: 12 attack classes (derived from 37 real CVEs) mapped against all 9 layers. See [docs/DESIGN.md](docs/DESIGN.md) Section 5 for the full matrix.

---

## Why a Wrapper, Not a Fork

OpenClaw has 224K stars and active development. Forking means maintaining a diverging codebase, cherry-picking security patches, and eventually falling so far behind that upstream fixes no longer apply cleanly.

Wrapping means:

- **Upstream security fixes land automatically.** Update OpenClaw, lobsec continues to work.
- **No merge conflicts.** lobsec uses OpenClaw's documented configuration surface, plugin hooks, and proxy capabilities. It does not patch internal code.
- **Clear responsibility boundary.** OpenClaw handles messaging and AI coordination. lobsec handles security and privacy. Neither needs to understand the other's internals.
- **Simpler auditing.** The security perimeter is four packages with defined interfaces, not a modified copy of a large upstream project.

The tradeoff: lobsec cannot fix vulnerabilities inside OpenClaw's core. It can only contain their blast radius. This is an explicit design choice documented in ADR-1.

---

## Production Status

Engineering honesty. What works, what doesn't, and what's still pending. Verified against the live deployment on 2026-03-06.

### Verified Working in Production

These features have been tested end-to-end with real traffic, not just unit tests.

| Feature | Evidence |
|---------|----------|
| LLM proxy with credential injection | Ollama and Anthropic traffic routed through proxy. Real API keys never touch the gateway. Verified via Telegram end-to-end. |
| HSM-signed audit logging | 63+ events in `audit.jsonl`. 30 signed batches with SHA-256 hash chain and RSA-PKCS HSM signatures. |
| Plugin hooks (7 of 9 active) | `before_tool_call`, `before_model_resolve`, `before_message_write`, `tool_result_persist`, `llm_input`, `llm_output`, `gateway_start/stop` — all confirmed firing. |
| Credential redaction at persistence | `before_message_write` hook redacts API key patterns from stored messages. Verified: LLM-generated `.env` file had `[API-KEY-REDACTED]` markers. |
| Tool validation and deny | `eval` tool denied and logged in production audit trail. |
| Sovereign-first routing | All Telegram traffic defaults to sovereign GPU (private infrastructure). Cloud APIs are fallback only. |
| fscrypt encryption | 4 directories AES-256-XTS encrypted (hsm, config, logs, .openclaw). Verified active. |
| nftables egress filtering | 10 rules active. Default-deny with logging for lobsec UID. |
| TLS between gateway and proxy | P-256/ECDSA certificates. Gateway trusts lobsec CA via `NODE_EXTRA_CA_CERTS`. |
| Telegram bot integration | End-to-end: user message → sovereign LLM → redacted response → Telegram delivery. |
| Tool integrations | 9 tools registered: weather, email_send, email_read, calendar_list, calendar_add, contacts_list, contacts_add, github, examy_test. |
| Web search | Perplexity Sonar web search working via native OpenClaw tools. |
| Automated QA | Playwright-based browser testing with LLM-driven student personas, visual regression, GitHub issue lifecycle, daily scheduling. |

### Known Limitations and Pending Work

Each item is tracked as a GitHub issue. These are real gaps, not roadmap marketing.

1. **Jetson not routed through proxy.** Jetson backend still connects directly — needs custom header injection support in the proxy. ([#10](https://github.com/BlackDuck314/lobsec/issues/10))
2. **Gateway and proxy share same UID.** Cannot enforce "gateway has no internet route" at the kernel level because both processes share the same UID. ([#11](https://github.com/BlackDuck314/lobsec/issues/11))
3. **Docker sandbox image built but not active.** Hardened image (74.8 MB, custom seccomp) exists. OpenClaw still uses its default image. ([#1](https://github.com/BlackDuck314/lobsec/issues/1))
4. **mTLS generated but not enforced.** Certificates exist and auto-renew. Proxy does not require client certificates. ([#5](https://github.com/BlackDuck314/lobsec/issues/5))
5. **No automated backups.** BackupManager class exists (18 tests passing). No scheduled service. ([#3](https://github.com/BlackDuck314/lobsec/issues/3))
6. **No monitoring or alerting.** SystemMonitor class exists (29 tests passing). Health checks run but nobody is notified. ([#4](https://github.com/BlackDuck314/lobsec/issues/4))
7. **LUKS full-disk encryption deferred.** fscrypt covers sensitive directories. Boot directory with HSM PIN remains on unencrypted filesystem. ([#8](https://github.com/BlackDuck314/lobsec/issues/8))
8. **OLLAMA_API_KEY still in gateway env.** No longer needed since proxy wiring. Defense-in-depth: should be removed. ([#9](https://github.com/BlackDuck314/lobsec/issues/9))
9. **`message_sending` hook never fires.** Registered but OpenClaw doesn't call it. Outbound credential scanning relies on persistence hooks and proxy isolation instead. ([#6](https://github.com/BlackDuck314/lobsec/issues/6))
10. **End-to-end integration tests limited.** 765 unit tests pass. Production integration coverage is manual and incomplete. ([#2](https://github.com/BlackDuck314/lobsec/issues/2))
12. **SoftHSM2 in production.** No hardware HSM yet. Keys protected by filesystem permissions + fscrypt, not tamper-resistant hardware.
13. **No automatic PII classification.** Sovereign/public routing is user-declared. No NER or automatic content classification.
14. **No multi-user support.** Single operator assumed. No per-user credential scoping or multi-tenant audit separation.
15. **No formal security audit.** Self-assessed threat model. Not reviewed by a third-party security firm.
16. **Prompt injection defense is defense-in-depth only.** Input sanitization, output validation, and tool gating applied, but no perfect solution exists.

---

## Current Integrations

| Category | Integration | Status | Details |
|----------|------------|--------|---------|
| Messaging | Telegram (via OpenClaw) | Working | Primary channel. WhatsApp, Discord, Slack, Signal, and others supported by OpenClaw. |
| Local inference | Ollama (sovereign GPU) | Working (via proxy) | Remote GPU, qwen2.5:32b. Routed through lobsec-proxy with credential injection. |
| Local inference | Ollama (Jetson) | Working (direct) | Jetson Orin, gemma3:1b, llama3.2:3b, qwen2.5-coder:3b. Not yet routed through proxy ([#10](https://github.com/BlackDuck314/lobsec/issues/10)). |
| Cloud fallback | Anthropic Claude | Working (via proxy) | Full model family via `@lobsec/proxy` credential injection. |
| HSM | SoftHSM2 | Working | PKCS#11 interface. 15 data objects + 2 key pairs in production. |
| Weather | Tomorrow.io | Working | Via lobsec-tools plugin, API key in HSM. |
| Email | Gmail SMTP/IMAP | Working | Send and read via lobsec-tools plugin, app password in HSM. |
| Calendar | Radicale CalDAV | Working | Local CalDAV server on loopback, htpasswd auth. |
| Contacts | Radicale CardDAV | Working | Local CardDAV address book. |
| Web search | Perplexity Sonar | Working | Via native OpenClaw tools.web.search, API key in HSM. |
| QA automation | Playwright + Claude | Working | Daily automated testing with LLM-driven student personas, visual regression, GitHub issue lifecycle. |

---

## Quick Start

### Prerequisites

- Ubuntu 24.04+
- Node.js 22 LTS
- pnpm 9+
- Docker 27+ (rootless mode recommended)
- SoftHSM2 (`apt install softhsm2`)

### Installation

```bash
# Clone
git clone https://github.com/BlackDuck314/lobsec.git
cd lobsec

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Initialize HSM token
softhsm2-util --init-token --slot 0 --label lobsec --pin <your-pin> --so-pin <your-so-pin>

# Generate hardened OpenClaw config
# (Review deploy/lobsec.conf for configuration options)
cp deploy/lobsec.conf .env
# Edit .env with your credentials, then:

# Store credentials in HSM
# (See docs/setup.md for detailed HSM credential storage)

# Start the stack
docker compose -f deploy/docker-compose.yml up -d
```

For detailed setup instructions including HSM credential storage, fscrypt encryption, and systemd service installation, see [docs/setup.md](docs/setup.md).

---

## Project Structure

```
packages/
  shared/              # Core security primitives: HSM, crypto, config, containers
  cli/                 # CLI orchestrator: init, start, stop, status, health
  plugin/              # OpenClaw plugin: tool validation, redaction, routing hooks
  proxy/               # LLM proxy: routing, credential injection, egress filtering
  tools/               # Plugin tools: weather, email, calendar, contacts, github, QA

docs/
  DESIGN.md            # Master security design document
  STATUS.md            # ADR decisions and project state
  architecture/
    security-layers.md # L1-L9 layer specifications
    paranoid-isolation.md  # Container isolation, HSM/JIT design
    encryption.md      # LUKS, fscrypt, mTLS, certificate management
  threat-model/
    attack-class-taxonomy.md   # 12 attack classes from 37 CVEs
    verification-resolution.md # Verified against running OpenClaw
  security/
    openclaw-vulnerability-report.md  # CVE analysis and reproduction
    acid-tests.md      # Security validation tests
    hsm-inventory.md   # HSM object inventory

deploy/
  docker-compose.yml   # Container orchestration
  caddy/Caddyfile      # Reverse proxy configuration
  docker/              # Dockerfile.sandbox, seccomp profile
  lobsec-egress.conf   # nftables egress rules
  bin/                 # Operational scripts (HSM, fscrypt, audit, backup)
  *.service, *.timer   # systemd units
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/DESIGN.md](docs/DESIGN.md) | Master security design document. Start here. |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Trust boundaries, attack classes, and threat model assumptions. |
| [docs/MITRE_MAPPING.md](docs/MITRE_MAPPING.md) | MITRE ATT&CK, NIST SP 800-160, and OWASP ASI mapping. |
| [docs/SECURITY_LAYERS.md](docs/SECURITY_LAYERS.md) | Detailed L1-L9 layer documentation with cross-reference matrix. |
| [docs/CVE_ANALYSIS.md](docs/CVE_ANALYSIS.md) | CVE reproduction and mitigation analysis. |
| [docs/architecture/paranoid-isolation.md](docs/architecture/paranoid-isolation.md) | Container isolation design, HSM/JIT credential flow, total visibility proxy. |
| [docs/architecture/encryption.md](docs/architecture/encryption.md) | Encryption architecture: LUKS, fscrypt, mTLS, certificate management. |
| [docs/STATUS.md](docs/STATUS.md) | Architecture Decision Records and project state. |
| [docs/AUDIT-MATRIX.md](docs/AUDIT-MATRIX.md) | Requirements traceability matrix. |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

Summary:

- Tests are required for every change. Run `pnpm test && pnpm typecheck` before opening a PR.
- Security-sensitive changes require a security impact assessment in the PR description.
- Use [Conventional Commits](https://www.conventionalcommits.org/) format (`feat`, `fix`, `security`, `docs`, `test`, `refactor`).
- If you discover a vulnerability, follow the process in [SECURITY.md](SECURITY.md) instead of opening a public issue.

---

## License

MIT. See [LICENSE](LICENSE) for details.

OpenClaw is also MIT licensed. lobsec does not fork or modify OpenClaw source code. It wraps OpenClaw through its documented configuration, plugin, and proxy interfaces.

---

Built with: Node.js 22, TypeScript strict, pnpm, Vitest, oxlint, Docker rootless, Caddy, WireGuard, SoftHSM2.
