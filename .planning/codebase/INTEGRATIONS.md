# External Integrations — lobsec

Generated: 2026-03-03

## Upstream Dependencies

### OpenClaw (Primary Upstream)

| Property | Value | Notes |
|----------|-------|-------|
| **URL** | https://github.com/openclaw/openclaw | MIT, 224K+ stars |
| **Version** | v2026.2.24 | Pinned in production |
| **Installation** | `/opt/lobsec/openclaw` (production) `/root/openclaw` (dev) | WebSocket: ws://127.0.0.1:18789 |
| **Role** | AI assistant platform | Upstream, never forked |
| **Integration** | Plugin hooks, proxy routing, config wrapping | Packages A–D wrap, don't modify |

## LLM Backends (Inference)

### 1. Ollama — Sovereign (Local/Private)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Open-source local inference server | Alternative to cloud APIs |
| **URL** (Primary) | `http://<remote-gpu-host>:11435` | Sovereign GPU server |
| **Model** | qwen2.5:32b | Routing default for sovereign traffic |
| **Credential** | `ollama-api-key` (HSM-stored) | Usually empty string for local Ollama |
| **Protocol** | HTTP (LAN, no TLS initially) | Proxy terminates TLS to client |
| **Supported Models** | `qwen2.5:32b`, others | Plugin references in `openclaw-adapter/index.ts` |

### 2. Ollama — Jetson (Sovereign/Private)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Local inference on Jetson device | Cloudflare Access protected |
| **URL** | `https://<your-domain>` | CF-Access tunneled |
| **Models** | `gemma3:1b`, `llama3.2:3b`, `qwen2.5-coder:3b` | Edge device models |
| **Credential** | `ollama-api-key` (same HSM label) | API key for Jetson CF-Access |
| **Protocol** | HTTPS with CF-Access | Client certificate authentication |
| **Supported** | Yes, via llama-cpp or vllm wrapper | Sovereign-first default |

### 3. Anthropic API (Public Cloud)

| Property | Value | Notes |
|----------|-------|-------|
| **URL** | `https://api.anthropic.com` | Public cloud LLM provider |
| **API Version** | Latest (via `anthropic-version` header) | Header passthrough in proxy |
| **Credential** | `anthropic-api-key` (HSM-stored) | Environment: `ANTHROPIC_API_KEY` |
| **Protocol** | HTTPS (REST, no WebSocket) | Token in Authorization header |
| **Endpoint** | `/v1/messages` | Detected by proxy for routing |
| **Models** | Full Anthropic family (Claude 3, etc.) | Latest via API, version negotiation |
| **Role** | Fallback for cloud inference | Sovereign-first, cloud second |

### 4. OpenAI API (Public Cloud, Referenced)

| Property | Value | Notes |
|----------|-------|-------|
| **URL** | `https://api.openai.com` | Public cloud LLM provider |
| **Credential** | Not deployed (placeholder) | Would need `openai-api-key` |
| **Status** | Configuration exists, not yet deployed | Future integration point |

## Messaging & Communication Channels

### Telegram

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Messaging platform (Signal alternative) | MTproto protocol |
| **Bot Token** | `telegram-bot-token` (HSM-stored) | Stored as HSM data object |
| **Bot Handle** | `@lobsec_bot` | Registered, healthy, deployed |
| **Webhook/Polling** | Polling (long-pull) | No webhook (inbound firewall only) |
| **OpenClaw Channel** | Fully integrated | Messages → plugin → sovereign routing |
| **Config Reference** | `packages/shared/src/types/config.ts` | Channel type: "telegram" |

### Slack (Supported, Not Deployed)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Enterprise messaging | OAuth + webhooks |
| **Credentials** | `slack-bot-token`, `slack-user-token` (HSM slots) | Both stored but not active |
| **OpenClaw Integration** | Channel exists | Config in shared package |
| **Monitoring** | Alert channel (webhook URL support) | Webhook: `https://hooks.slack.com/...` |
| **Status** | Configured, awaiting deployment | User can activate |

### Discord (Supported, Not Deployed)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Community chat platform | Bot API v10+ |
| **OpenClaw Integration** | Channel type exists | Config in shared package |
| **Status** | Scaffolding ready | Not yet deployed |

### Matrix (Supported, Not Deployed)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Open protocol, self-hosted chat | Federation support |
| **OpenClaw Integration** | Channel type exists | Config in shared package |
| **Status** | Scaffolding ready | Not yet deployed |

### iMessage, WhatsApp, Teams, Signal

| Item | Status | Notes |
|------|--------|-------|
| **Supported** | Yes (OpenClaw upstream) | All integrated into OpenClaw |
| **lobsec Wrapper** | Transparent pass-through | Plugin hooks work on all channels |
| **Deployed** | Only Telegram active | Others via future OpenClaw versions |

## Authentication & Credential Management

### HSM (Hardware Security Module)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | SoftHSM2 v2.6.1 (software emulation) | PKCS#11 compliant |
| **Location** | `/opt/lobsec/hsm/` (fscrypt encrypted) | Token name: "lobsec" |
| **Config** | `/opt/lobsec/boot/softhsm2.conf` | Unencrypted bootstrap |
| **PIN** | `/opt/lobsec/boot/pin.env` | Plaintext during boot (bootstrap dir) |
| **Stored Objects** | 8 data + 2 keys (10 total) | Per MEMORY.md |

**Credential Objects**:
1. `telegram-bot-token` (data)
2. `ollama-api-key` (data)
3. `ollama-api-key-2` (data, alternate)
4. `gateway-auth-token` (data)
5. `jetson-cf-client-id` (data)
6. `jetson-cf-client-secret` (data)
7. `anthropic-api-key` (data)
8. `fscrypt-master-key` (data, encryption key)

**Key Objects**:
- `lobsec-audit-signing` (RSA-2048, non-extractable, signing)
- TBD (future keys for mTLS, backup encryption)

### Cloudflare Access (Optional, Jetson Integration)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Zero Trust, identity-based access | BeyondCorp model |
| **Usage** | Jetson LLM (`<your-domain>`) | CF-Access tunneled |
| **Credential** | `jetson-cf-client-id` + `jetson-cf-client-secret` | HSM-stored for mTLS |
| **Protocol** | mTLS to Cloudflare tunnel | Service token auth |
| **Purpose** | Sovereign edge device protection | Private inference without public IP |

## System Services & Communication

### systemd Services

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| `lobsec.service` | 127.0.0.1:18789 | WebSocket | Gateway (loopback only) |
| `lobsec-proxy.service` | 127.0.0.1:18790 | HTTP/HTTPS | LLM proxy (loopback only) |
| `lobsec-audit-sign.timer` | — | File I/O | Batch audit log signing (5-min interval) |

**No public ports** — SSH/VPN only, zero inbound exposure.

## Email & Calendar Services

### Nodemailer (SMTP Transport)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Email sender library | SMTP/SMTP+TLS |
| **Config** | In `packages/tools/src/email.ts` | Transport creation + credentials |
| **TLS Support** | Yes (via `node:tls`) | STARTTLS or direct TLS |
| **Use Case** | Tool for OpenClaw email actions | Read/send email via OpenClaw |
| **Auth** | User/password or OAuth2 (config) | Not yet hardened for HSM |

### Radicale (CalDAV Server)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | CalDAV/CardDAV protocol | Self-hosted calendar |
| **Integration** | `packages/tools/src/calendar.ts` | Read/write events |
| **Status** | Scaffolding only | Not yet deployed/connected |
| **Use Case** | Tool for OpenClaw calendar actions | Future integration |

## Monitoring & Alerting

### SystemMonitor (Class, Not Deployed)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Event monitoring + alerting | Threshold-based |
| **Alert Channels** | Slack, Discord, Email, Generic webhooks | Channel routing in config |
| **Webhook Format** | Generic HTTPS POST | Signature validation (HMAC-SHA256) |
| **Status** | Implemented, not yet activated | Ready for deployment |
| **Config** | `packages/shared/src/monitor.ts` | MinSeverity filtering |

### Slack Webhook (Monitoring)

| Property | Value | Notes |
|----------|-------|-------|
| **URL Pattern** | `https://hooks.slack.com/services/...` | Incoming webhook |
| **Purpose** | Alert delivery channel | High-severity events only |
| **Auth** | URL contains secret token | No additional auth needed |

## Caddy Reverse Proxy (Layer 2 Infrastructure)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | HTTP/2 reverse proxy + TLS | Auto-renewal, mTLS support |
| **Role** | Layer 2 between gateway/clients | CORS, rate limiting, TLS |
| **Config Generator** | `packages/shared/src/caddy-config.ts` | Dynamic config generation |
| **Features** | CORS headers, origin allowlist, TLS cert auto-renewal | P-256/ECDSA self-signed (30-day renewal) |
| **Deployment** | Not yet enforced in services | mTLS certs generated but unused |
| **Port** | Would intercept before 18789/18790 | TLS termination |

## Backup & Disaster Recovery

### BackupManager (Class, Not Deployed)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Backup orchestration | Encryption + compression |
| **Backends** | Local filesystem, S3-compatible | Plugin architecture |
| **Encryption** | HSM-backed key derivation | Scrypt KDF for backup encryption |
| **Status** | Implemented, not yet automated | Ready for cronSchedule |
| **Config** | `packages/shared/src/backup.ts` | Retention policies, frequency |

### S3-Compatible Backup (Future)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Object storage | S3 API compatible |
| **Use Case** | Off-site backup destination | Encrypted, stored in HSM |
| **Status** | Planned, not deployed | Configuration scaffolding only |

## Encryption & Key Management

### fscrypt (File-System Encryption)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | AES-256-XTS filesystem-level encryption | ext4 native |
| **Directories** | 4 encrypted in production | hsm, config, logs, .openclaw |
| **Master Key** | `fscrypt-master-key` (HSM-stored) | Scrypt derivation from PIN |
| **Boot Dependency** | PIN file in unencrypted bootstrap | `/opt/lobsec/boot/pin.env` |
| **Policy Version** | v2 | Latest fscrypt standard |

### LUKS (Full-Disk Encryption)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | dm-crypt LUKS2 | Full-disk encryption |
| **Status** | Deferred | Maintenance window required |
| **Reason** | Would require re-encrypt or fresh install | Resource-intensive setup |

## Audit & Compliance

### Audit Log Signing

| Property | Value | Notes |
|----------|-------|-------|
| **Signer** | `lobsec-audit-signing` (RSA-2048, HSM) | Non-extractable key |
| **Hash Chain** | SHA-256 sequential hashing | Tamper detection |
| **Batch Interval** | 5 minutes (systemd timer) | `lobsec-audit-sign.timer` |
| **Output** | `/opt/lobsec/logs/audit-signed/` | Signed batches (JSON) |
| **Log Source** | `/opt/lobsec/logs/audit.jsonl` | Unsigned entries |
| **Signature Verification** | Public key in HSM | Audit trail integrity |

## Certificate Management

### mTLS Certificates

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | P-256/ECDSA, self-signed | Elliptic curve, modern |
| **CA** | Self-signed CA (generated) | Not yet issued |
| **Renewal** | 30-day auto-renewal | Systemd timer (planned) |
| **Location** | `/opt/lobsec/run/certs/` | Symlink to current cert |
| **Status** | Generated, not yet enforced | Caddy wiring planned |
| **Purpose** | Service-to-service TLS | Proxy ↔ Gateway, etc. |

### Let's Encrypt (ACME, Referenced)

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Public CA for domain certs | Auto-renewal capable |
| **URL** | `https://acme-v02.api.letsencrypt.org/directory` | Standard ACME v2 endpoint |
| **Status** | Configuration reference only | Not yet deployed |
| **Purpose** | Future external domain TLS | For public-facing Caddy proxy |

## Docker & Container Registry

### Docker Images

| Image | Registry | Size | Purpose |
|-------|----------|------|---------|
| `lobsec-sandbox:hardened` | Local (built) | 74.8MB | Seccomp hardened runtime |
| `openclaw-sandbox:bookworm-slim` | Upstream | TBD | Current sandbox (to replace) |

### Seccomp Profile

| Property | Value | Notes |
|----------|-------|-------|
| **Type** | Syscall whitelist | Blocks dangerous ops |
| **Format** | OCI seccomp JSON | Container runtime compatible |
| **Application** | Docker run `--security-opt seccomp=...` | Per-container isolation |
| **Status** | Profile built, not yet enforced | OpenClaw still uses old image |

## External References & Standards

### Security Standards

| Reference | Purpose | Notes |
|-----------|---------|-------|
| **NIST SP 800-53** | Security controls | Audit logging, encryption, access control |
| **CWE** | Vulnerability classification | Tool validation checks CWE-78 (command injection) |
| **OWASP** | Web app security | CORS, header validation, rate limiting |

### Protocols

| Protocol | Use | Notes |
|----------|-----|-------|
| **WebSocket** | OpenClaw gateway | ws://127.0.0.1:18789 |
| **HTTP/2** | REST APIs, proxy | Caddy, OpenClaw, LLM backends |
| **HTTPS** | Secure transport | TLS 1.3+, P-256/ECDSA certs |
| **SMTP/SMTP+TLS** | Email | Nodemailer for email tools |
| **CalDAV/CardDAV** | Calendar/Contacts | Radicale (future) |
| **MTproto** | Telegram | Native Telegram protocol (OpenClaw) |
| **PKCS#11** | HSM client | SoftHSM2 interface |

## Configuration & Secrets Management

### Environment Variables (Runtime)

| Variable | Purpose | Storage | Notes |
|----------|---------|---------|-------|
| `ANTHROPIC_API_KEY` | Claude inference | HSM (`anthropic-api-key`) | Injected at startup |
| `OLLAMA_BACKEND_URL` | Custom Ollama server | Proxy env, default: Portullama | Override default backend |
| `LOBSEC_PROXY_TOKEN` | Proxy authentication | HSM (`gateway-auth-token`) | Token validation in proxy |
| `OPENCLAW_GATEWAY_TOKEN` | OpenClaw auth | HSM | Same as gateway-auth-token |
| `TELEGRAM_BOT_TOKEN` | Telegram API | HSM (`telegram-bot-token`) | Bot authentication |
| `JETSON_CF_CLIENT_ID` | Cloudflare Access | HSM | Jetson tunnel mTLS |
| `JETSON_CF_CLIENT_SECRET` | Cloudflare Access | HSM | Jetson tunnel secret |

### Files (gitignored)

| File | Purpose | Location | Notes |
|------|---------|----------|-------|
| `.env` | Development secrets | `/root/lobsec/.env` | Not committed, test fixtures only |
| `softhsm2.conf` | HSM config | `/opt/lobsec/boot/softhsm2.conf` | Unencrypted bootstrap |
| `pin.env` | HSM PIN | `/opt/lobsec/boot/pin.env` | Plaintext, bootstrap only |
| `fscrypt-key.bin` | Master key for fscrypt | `/opt/lobsec/boot/fscrypt-key.bin` | Raw key material |

## Summary of Integration Topology

```
Internet
    ├─ Telegram API ──→ Telegram Bot ──→ @lobsec_bot
    ├─ Anthropic API ──→ Proxy ──→ LLM Router
    ├─ Ollama (Portullama) ──→ Sovereign Inference
    ├─ Ollama (Jetson/CF-Access) ──→ Edge Inference
    ├─ OpenAI API ──→ (Reserved)
    └─ S3-compatible Storage ──→ (Future backup)

Local Network (Loopback: 127.0.0.1)
    ├─ 18789 (Gateway/WebSocket) ──→ OpenClaw
    ├─ 18790 (Proxy) ──→ LLM Router
    └─ SoftHSM2 ──→ Credential Store

Monitoring & Alerting (Optional, Not Active)
    ├─ Slack Webhooks ──→ Alert Channel
    ├─ Discord Webhooks ──→ (Reserved)
    ├─ Email (SMTP) ──→ (Future)
    └─ Generic Webhooks ──→ Custom Integrations

File System (Encrypted)
    ├─ /opt/lobsec/.openclaw/ ──→ OpenClaw Config (fscrypt)
    ├─ /opt/lobsec/hsm/ ──→ SoftHSM2 Token (fscrypt)
    ├─ /opt/lobsec/logs/ ──→ Audit Logs (fscrypt)
    └─ /opt/lobsec/run/certs/ ──→ mTLS Certificates

Bootstrap (Unencrypted, Ephemeral)
    ├─ softhsm2.conf ──→ HSM Config
    ├─ pin.env ──→ HSM PIN
    └─ fscrypt-key.bin ──→ Master Key
```

## Credential Injection Methods

| Method | Status | Implementation | Notes |
|--------|--------|-----------------|-------|
| **HSM (PKCS#11)** | Deployed | C library + Node.js binding | Primary secure storage |
| **Environment Variables** | Deployed | Kernel environment | Process startup injection |
| **Kernel Keyring** | Designed | Blocked by unprivileged ops | Requires CAP_SYS_ADMIN or setuid |
| **File (Encrypted)** | Fallback | fscrypt-protected directory | Not preferred, requires unlock |

## No Public Attack Surface

- **SSH/VPN only**: No exposed HTTP/HTTPS ports
- **Loopback binding**: Gateway & Proxy listen 127.0.0.1 only
- **Outbound only**: Telegram, Anthropic, Ollama (outbound HTTPS/HTTP)
- **Inbound firewall**: nftables egress rules, no ingress
- **Sandbox mode**: OpenClaw sandbox=all, no exec escalation
