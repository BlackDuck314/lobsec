```
    ╦  ╔═╗╔╗ ╔═╗╔═╗╔═╗
    ║  ║ ║╠╩╗╚═╗║╣ ║
    ╩═╝╚═╝╚═╝╚═╝╚═╝╚═╝
```

**Your agent can't leak what it never had.**

[![Tests](https://img.shields.io/badge/tests-767%20passing-green)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Problem Nobody Talks About

Everyone worries about prompt injection, jailbreaks, and AI alignment. Conference talks. Research papers. Twitter threads.

Meanwhile, your AI assistant stores API keys in a plaintext JSON file, binds to all network interfaces, runs tools with no validation, and has unrestricted outbound network access. A compromised agent doesn't need a sophisticated attack. `cat config.json` works fine.

The most dangerous thing about your AI assistant isn't the AI. It's that it holds your keys.

lobsec fixes this by making sure it doesn't.

---

## What This Is

lobsec is a security wrapper for [OpenClaw](https://github.com/openclaw/openclaw), the 224K-star open-source AI assistant framework. It connects to Telegram, WhatsApp, Discord, Slack, Signal, and more.

lobsec does not fork OpenClaw. Does not modify its source code. Does not add AI capabilities. It wraps OpenClaw through its own plugin system, configuration surface, and proxy interface -- five packages that make it safe to deploy on a real server with real API keys.

**The core idea:** OpenClaw thinks it has your API keys. It doesn't. It has a proxy token that points to `127.0.0.1`. The real keys live in an HSM, injected per-request into an isolated proxy, and wiped on shutdown. A full memory dump of the gateway reveals nothing useful.

---

## Five Things That Change

**1. Credentials never touch disk.**
Secrets live in an HSM (SoftHSM2 or YubiHSM2). Injected just-in-time. Wiped on shutdown. OpenClaw never holds real API keys -- only an internal proxy token.

**2. Sovereign-first routing.**
Local inference is the default. Cloud APIs are a fallback. Sensitive conversations never leave your infrastructure unless you choose otherwise.

**3. Every tool call is validated.**
Path containment, symlink resolution, command deny lists, sandbox enforcement. The plugin validates independently of OpenClaw's own sandbox. Belt and suspenders.

**4. Default-deny egress.**
nftables rules. No outbound traffic unless explicitly allowlisted. SSRF against RFC1918, cloud metadata, IPv6-mapped -- all blocked at the kernel.

**5. Tamper-evident audit trail.**
Every LLM request, tool call, routing decision logged to structured JSONL. HSM-signed hash chains. You'll know if someone touched the logs.

---

## Architecture

```
 Messaging channels
    |
    | TLS 1.3
    v
 ┌─────────────────────────────────────────────────────┐
 │  Caddy                 rate limiting, CSP, origin    │
 └──────────────────────────┬──────────────────────────┘
                            v
 ┌─────────────────────────────────────────────────────┐
 │  OpenClaw Gateway        loopback only, no internet  │
 │                                                      │
 │  ┌─── lobsec plugin ──────────────────────────────┐ │
 │  │  before_tool_call   → validate, deny            │ │
 │  │  before_model_resolve → sovereign/public route  │ │
 │  │  before_message_write → redact credentials      │ │
 │  │  tool_result_persist → redact secrets           │ │
 │  │  llm_input/output   → audit log                │ │
 │  └─────────────────────────────────────────────────┘ │
 └──────────────────────────┬──────────────────────────┘
                            v
 ┌─────────────────────────────────────────────────────┐
 │  lobsec proxy            credential injection        │
 │                          egress filtering            │
 │  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
 │  │ Local GPU│ │Remote GPU│ │ Cloud APIs (Anthropic)│ │
 │  │ sovereign│ │ sovereign│ │ fallback only         │ │
 │  └──────────┘ └──────────┘ └──────────────────────┘ │
 └─────────────────────────────────────────────────────┘
```

OpenClaw never knows lobsec exists. It sees a hardened config, hooks that gate risky operations, and a proxy that handles routing. The real API keys live only in the proxy's memory, retrieved from the HSM at startup.

---

## Nine Layers

| | Layer | One-liner |
|--|-------|-----------|
| L1 | **Network Perimeter** | nftables default-deny, loopback-only, SSH/VPN only |
| L2 | **Reverse Proxy** | Caddy, TLS 1.3, origin validation, rate limiting |
| L3 | **Webhook Auth** | HSM-backed HMAC verification per channel |
| L4 | **Gateway Policy** | Hardened config, drift detection, tool deny lists |
| L5 | **Egress Firewall** | Domain allowlist, RFC1918 block, metadata block |
| L6 | **Execution Sandbox** | Docker rootless, read-only fs, custom seccomp |
| L7 | **Credential Broker** | HSM (PKCS#11), JIT injection, log redaction |
| L8 | **Privacy Engine** | Sovereign-first routing, proxy credential isolation |
| L9 | **Audit Logger** | HSM-signed hash chains, structured JSONL |

Each layer assumes the layers outside it have been compromised. 12 attack classes (from 37 real CVEs) mapped against all 9. See [docs/DESIGN.md](docs/DESIGN.md) for the full matrix.

---

## Before / After

|  | Default OpenClaw | With lobsec |
|--|-----------------|-------------|
| **API keys** | Plaintext JSON on disk | HSM-backed, JIT, wiped on shutdown |
| **Network** | Binds to `0.0.0.0` | Loopback only, proxy-only egress |
| **Tools** | Execute anything | Validated per-call: paths, deny lists, sandbox |
| **Routing** | Single cloud provider | Sovereign-first, cloud fallback |
| **Audit** | Application logs | HSM-signed hash chain, tamper-evident |
| **Sandbox** | Off by default | Docker rootless, custom seccomp, read-only fs |
| **SSRF** | Private network access allowed | RFC1918 + metadata + IPv6-mapped blocked |

---

## Why a Wrapper

Forking a 224K-star project with active development means maintaining a diverging codebase forever. Cherry-picking security patches. Merge conflicts. Eventually falling so far behind that fixes no longer apply.

Wrapping means upstream updates land automatically. No merge conflicts. Clear responsibility: OpenClaw handles messaging and AI, lobsec handles security. Four packages with defined interfaces, not a patched copy of a large upstream project.

The tradeoff is real: lobsec cannot fix vulnerabilities inside OpenClaw's core. It can only contain their blast radius. This is documented in [ADR-1](docs/STATUS.md).

---

## Production Status

Verified against a live deployment. Updated 2026-03-17.

### Working

| Feature | Notes |
|---------|-------|
| LLM proxy + credential injection | Multiple inference backends routed through proxy. Real keys never touch the gateway. |
| HSM-signed audit logging | Signed batches, SHA-256 hash chain, RSA-PKCS signatures. |
| Plugin hooks (7 of 9) | Tool gating, routing, redaction, audit -- all confirmed firing. |
| Credential redaction | API key patterns scrubbed from stored messages. |
| Sovereign routing | Configurable per channel. Cloud or local-first. |
| fscrypt encryption | 4 directories AES-256-XTS encrypted. |
| nftables egress | Default-deny with per-destination allowlist. |
| Internal TLS | P-256/ECDSA self-signed certs with auto-renewal. |
| Plugin tools | Weather, email, calendar, contacts, GitHub, and custom tools. |
| Web search | Native OpenClaw web search, API key in HSM. |

### Honest Gaps

These are real limitations, not roadmap marketing.

- **One inference backend not proxied.** Needs custom header injection in the proxy.
- **Gateway and proxy share a UID.** Can't enforce network isolation at kernel level.
- **Docker sandbox built but inactive.** Hardened image exists, not yet the default.
- **mTLS certs exist but not enforced.** Auto-renew works, mutual auth doesn't.
- **No automated backups or monitoring.** Classes exist, services don't.
- **SoftHSM2, not hardware HSM.** Protected by fscrypt, not tamper-resistant silicon.
- **No automatic PII classification.** Routing is user-declared, not NER-based.
- **No formal security audit.** Self-assessed. Not reviewed by a third party.
- **Prompt injection is defense-in-depth.** No perfect solution exists.

---

## Packages

```
packages/
  shared/    Core: HSM client, audit, crypto, monitoring, resilience
  cli/       Lifecycle: init, start, stop, status, health
  plugin/    OpenClaw hooks: tool gating, redaction, routing, audit
  proxy/     LLM proxy: routing, credential injection, egress filtering
  tools/     Plugin tools: weather, email, calendar, contacts, github
```

---

## Quick Start

```bash
git clone https://github.com/BlackDuck314/lobsec.git
cd lobsec
pnpm install && pnpm build && pnpm test

# Initialize HSM
softhsm2-util --init-token --slot 0 --label lobsec \
  --pin <your-pin> --so-pin <your-so-pin>

# Configure and deploy
cp deploy/lobsec.conf .env    # edit with your credentials
# See docs/setup.md for HSM credential storage, fscrypt, systemd
docker compose -f deploy/docker-compose.yml up -d
```

**Requires:** Ubuntu 24.04+, Node.js 22, pnpm 10+, Docker 27+, SoftHSM2.

---

## Docs

| | |
|--|--|
| [DESIGN.md](docs/DESIGN.md) | Master security design. Start here. |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Trust boundaries, attack classes, assumptions. |
| [MITRE_MAPPING.md](docs/MITRE_MAPPING.md) | ATT&CK, NIST 800-160, OWASP ASI mapping. |
| [SECURITY_LAYERS.md](docs/SECURITY_LAYERS.md) | L1-L9 specs with cross-reference matrix. |
| [CVE_ANALYSIS.md](docs/CVE_ANALYSIS.md) | 37 CVEs analyzed, reproduced, mitigated. |
| [STATUS.md](docs/STATUS.md) | ADRs and project state. |

---

## Contributing

Tests required. Security impact assessment for sensitive changes. [Conventional Commits](https://www.conventionalcommits.org/). Vulnerabilities go to [SECURITY.md](SECURITY.md), not public issues.

Full guide: [CONTRIBUTING.md](CONTRIBUTING.md).

---

MIT. Built with Node.js 22, TypeScript strict, pnpm, Vitest, oxlint, Docker rootless, Caddy, SoftHSM2.
