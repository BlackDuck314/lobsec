# lobsec Design Audit Matrix

> **Purpose:** Verify that implementation specs (e.g., from Kiro) accurately reflect
> all design decisions documented in `DESIGN.md` and supporting documents.
>
> **How to use:** For each row, check the implementation spec. Mark the Status column:
> - `OK` -- spec correctly reflects the requirement
> - `MISSING` -- requirement not addressed in spec
> - `WRONG` -- spec contradicts the requirement
> - `PARTIAL` -- spec partially addresses it (add note)
> - `N/A` -- not applicable to this phase/spec
>
> **Date:** 2026-02-24

---

## A. Architecture Decisions (ADRs)

| ID | Requirement | Verification Criteria | Source | Status |
|----|-------------|----------------------|--------|--------|
| A1 | Wrapper, not fork. Never modify OpenClaw source. | Spec uses only: config files, plugin hooks, proxy, OS containment. No OpenClaw source patches. | ADR-1 | |
| A2 | HSM is PRIMARY credential storage (SoftHSM2 dev, YubiHSM2 prod). | Spec uses PKCS#11 via `graphene-pk11`. NOT LUKS/SOPS/Age as primary. HSM is not optional. | ADR-2 | |
| A3 | Same PKCS#11 API for dev and prod. Zero code changes between SoftHSM2 and YubiHSM2. | Only `LOBSEC_PKCS11_MODULE` path changes. No `if (softHSM)` conditionals in code. | ADR-2 | |
| A4 | Per-deployment credential rotation + HSM instant revocation. | Uses `C_DestroyObject` for immediate key destruction. Not per-request checkout/checkin. | ADR-3 | |
| A5 | User-declared sovereign/public mode, NOT automatic PII classifier. | `/sovereign` and `/public` commands. No regex PII scanner as routing mechanism. | ADR-4 | |
| A6 | Per-channel defaults for sovereign/public (configurable). | e.g., WhatsApp defaults to sovereign, WebChat defaults to public. | ADR-4 | |
| A7 | Sovereign inference serves three purposes: privacy, economics, availability. | Not just a privacy feature. Fallback to local on rate limit/budget. | ADR-5 | |
| A8 | Three components: lobsec-cli, lobsec-plugin, lobsec-proxy. | Exactly three. Not two, not four. Each has distinct role. | ADR-6 | |
| A9 | lobsec-cli is the ONLY trusted component and ONLY one with HSM access. | No other component touches PKCS#11. Proxy gets keys via env injection. | ADR-6 | |
| A10 | Use OpenClaw native security features, don't reimplement. | `tools.deny`, `sandbox.mode`, `logging.redactSensitive`, `security audit` -- configured, not rebuilt. | ADR-7 | |
| A11 | `auth-profiles.json` on tmpfs, bind-mounted read-only into container. | Never on persistent disk. Path: `/run/lobsec/auth-profiles.json`. | ADR-8 | |
| A12 | Triple-layer encryption at rest: LUKS + fscrypt + HSM. | All three present. LUKS for disk, fscrypt for directories, HSM for credentials. | ADR-9 | |
| A13 | All in-transit encrypted: external TLS 1.3 + internal mTLS + backend TLS/WG. | Zero plaintext network traffic. Every container-to-container link is mTLS. | ADR-9 | |
| A14 | Three certificate tiers: self-signed (default), ACME (public default), custom CA. | Self-signed works out of box. ACME supports LE + ZeroSSL + Buypass + custom. Custom CA accepts user cert/key/chain. | ADR-10 | |
| A15 | Internal mTLS always on, always HSM-backed, 24h cert lifetime, not configurable. | User cannot disable internal mTLS. CA private key in HSM, non-extractable. | ADR-10 | |

---

## B. Component Architecture

| ID | Requirement | Verification Criteria | Source | Status |
|----|-------------|----------------------|--------|--------|
| B1 | lobsec-cli runs on host (not containerized). | Host process with direct HSM access, manages Docker. | DESIGN 4.1 | |
| B2 | lobsec-plugin runs inside OpenClaw's process. | Installed as OpenClaw plugin in `~/.openclaw/plugins/lobsec/`. Uses `api.on()` hooks. | DESIGN 4.1 | |
| B3 | lobsec-proxy runs in its own container. | Separate Docker container on `lobsec-internal` + `lobsec-egress` networks. | DESIGN 4.1 | |
| B4 | Six isolation domains (containers): caddy, lobsec-proxy, openclaw-gateway, sandbox-exec, sandbox-browser, lobsec-cli (host). | Exactly six. No more, no less. | paranoid-isolation 1.2 | |
| B5 | Three Docker networks: lobsec-internal (no internet), lobsec-sandbox (air-gapped), lobsec-egress (proxy only). | `--internal` flag on internal + sandbox. Only proxy on egress. | paranoid-isolation 1.3 | |
| B6 | openclaw-gateway has NO route to the internet. | On `lobsec-internal` (--internal) only. All outbound via `HTTP_PROXY` to lobsec-proxy. | paranoid-isolation 1.3 | |
| B7 | OpenClaw config mounted read-only into gateway container. | `openclaw.json` bind mount with `:ro`. Gateway cannot modify its own security config. | paranoid-isolation 1.4 | |
| B8 | Docker socket NEVER mounted into any container. | Explicit check: no `-v /var/run/docker.sock` anywhere. | paranoid-isolation 1.4 | |
| B9 | All containers: read-only root fs, cap_drop ALL, no-new-privileges, seccomp. | Every container in docker-compose has these four settings. | paranoid-isolation 1.5-1.7 | |

---

## C. Security Layers

| ID | Requirement | Verification Criteria | Source | Status |
|----|-------------|----------------------|--------|--------|
| C1 | L1: nftables default-deny on host. | `policy drop` on input chain. Only SSH + WireGuard/Tailscale allowed inbound. | security-layers L1 | |
| C2 | L1: Gateway binds to `127.0.0.1` only. | Config: `gateway.bind: "loopback"`. CLI flag: `--bind loopback`. | security-layers L1 | |
| C3 | L1: mDNS disabled. | Config: `discovery.mdns.mode: "off"`. Env: `OPENCLAW_DISABLE_BONJOUR=1`. nftables blocks UDP 5353. | security-layers L1 | |
| C4 | L2: Caddy as reverse proxy with TLS 1.3, Origin validation, CSP, rate limiting. | Caddyfile present. TLS 1.3 only (no 1.2). Origin checked on WebSocket upgrade. Rate limit per IP. | security-layers L2 | |
| C5 | L2: Request body size cap (10 MB). | Caddy config: `request_body { max_size 10MB }`. | paranoid-isolation 2.4 | |
| C6 | L3: Webhook signature verification per channel (HSM-backed). | Telegram: header comparison. Slack: HMAC-SHA256. Discord: Ed25519. Twilio: HMAC-SHA1. HSM does HMAC where possible. | security-layers L3 | |
| C7 | L3: Replay protection on webhooks (reject > 5 min old). | Timestamp validation on webhook payloads. | paranoid-isolation 2.4 | |
| C8 | L3: Startup gate -- refuse to start if enabled channel lacks webhook secret in HSM. | lobsec-cli checks before starting gateway. | paranoid-isolation Class 3 | |
| C9 | L4: `tools.deny: ["gateway", "sessions_spawn", "sessions_send"]`. | These three tools blocked. `gateway` prevents config changes. `sessions_*` prevent agent self-replication. | security-layers L4 | |
| C10 | L4: `tools.elevated.enabled: false`. | No sandbox escape hatch. | DESIGN 9.2 | |
| C11 | L4: `update.auto.enabled: false`. | Auto-update disabled (RCE via npm). | DESIGN 9.2 | |
| C12 | L4: Config drift detection. | lobsec-plugin periodically hashes running config, compares to hardened template. | security-layers L4 | |
| C13 | L5: All egress through lobsec-proxy with domain allowlist. | `HTTP_PROXY`/`HTTPS_PROXY` env vars in gateway container. Proxy validates destinations. | security-layers L5 | |
| C14 | L5: Denylist includes RFC1918, link-local, metadata (169.254.169.254), IPv4-mapped IPv6. | Explicit denylist in proxy. Checked AFTER DNS resolution (prevents DNS rebinding). | paranoid-isolation 2.3 | |
| C15 | L6: Sandbox mode `"all"` (all tool execution sandboxed). | Config: `agents.defaults.sandbox.mode: "all"`. | security-layers L6 | |
| C16 | L6: Sandbox containers: no network, read-only root, cap_drop ALL. | Sandbox on `lobsec-sandbox` network (--internal) or `network: none`. | paranoid-isolation 1.2 | |
| C17 | L7: OpenClaw gateway NEVER holds real LLM API keys. | Gateway has `LOBSEC_PROXY_TOKEN` only. Real keys in lobsec-proxy memory. | paranoid-isolation 3.4 | |
| C18 | L7: Log redaction for credential patterns. | lobsec-plugin hooks + OpenClaw `logging.redactSensitive: true`. Proxy strips Authorization headers. | security-layers L7 | |
| C19 | L8: Sovereign/public routing via `before_model_resolve` hook + `baseUrl` override. | Plugin intercepts model selection. Proxy routes based on session mode. | security-layers L8 | |
| C20 | L9: Structured JSON audit log with HSM-signed hash chain. | Every entry has `prev_hash` (SHA-256 chain) and `hsm_signature` (RSA from non-extractable key). | paranoid-isolation 3.7 | |
| C21 | L9: Startup security audit via `openclaw security audit --json`. | lobsec-cli runs at startup. Blocks startup on critical findings. | security-layers L9 | |

---

## D. Credential Management

| ID | Requirement | Verification Criteria | Source | Status |
|----|-------------|----------------------|--------|--------|
| D1 | Channel tokens (Telegram, Discord, Slack, etc.) stored in HSM. | All `.register(sensitive)` fields from OpenClaw schema stored as PKCS#11 objects. | DESIGN 7.3 | |
| D2 | Telegram uses `tokenFile` for JIT injection (HSM → tmpfs file). | Config: `channels.telegram.tokenFile: "/run/lobsec/telegram-bot-token"`. | DESIGN 7.4 | |
| D3 | Discord/Slack/Teams use `${VAR_NAME}` for JIT injection. | Config: `channels.discord.token: "${DISCORD_TOKEN}"`. Env var set from HSM at startup. | DESIGN 7.4 | |
| D4 | LLM API keys: lobsec-proxy holds real keys, OpenClaw gets proxy token. | OpenClaw `baseUrl` points to `http://lobsec-proxy:8080`. Proxy injects real key per-request. | DESIGN 7.4 | |
| D5 | Webhook signing secrets: non-extractable in HSM. HSM performs HMAC directly. | `extractable: false` on webhook secrets. lobsec-proxy calls HSM `C_Sign` for verification. | paranoid-isolation 3.5 | |
| D6 | WhatsApp credentials: fscrypt-encrypted directory (not JIT). | `~/.openclaw/credentials/whatsapp/` under fscrypt. Persistent session, can't do JIT. | DESIGN 7.4 | |
| D7 | API key exposure window minimized. Key exists in ONE process (lobsec-proxy). | Timeline: HSM → lobsec-cli (~50ms) → proxy env → lobsec-cli clears. Gateway never has it. | paranoid-isolation 3.4 | |
| D8 | All 30+ `.register(sensitive)` fields covered by HSM/JIT. | Cross-check against exhaustive list in verification-resolution.md. None stored plaintext on disk. | verification-resolution | |
| D9 | Credential rotation: 90 days for API keys, 30 days for gateway/proxy tokens. | lobsec-cli cron or manual `lobsec-cli credential rotate`. | encryption 4.2 | |
| D10 | Credential revocation: instant via `C_DestroyObject` + proxy restart. | Emergency revocation procedure: destroy in HSM → stop proxy → stop gateway → audit. | paranoid-isolation 3.6 | |

---

## E. Encryption

| ID | Requirement | Verification Criteria | Source | Status |
|----|-------------|----------------------|--------|--------|
| E1 | LUKS2 full-disk: AES-256-XTS, argon2id, 512-bit key. | `cryptsetup luksFormat` with these params. | encryption 1.1 | |
| E2 | LUKS unlock: passphrase (dev), TPM2 (prod), SSH/dropbear (VPS), Tang/Clevis (headless). | Multiple unlock strategies, not hardcoded to one. | encryption 1.1 | |
| E3 | fscrypt on `workspace/`, `agents/`, `logs/`, `canvas/`. | Four directories encrypted. Key from HSM. Locked on shutdown, unlocked at startup. | encryption 1.2 | |
| E4 | fscrypt protector key stored in HSM (extractable, sensitive). | `fscrypt-master-key` in HSM. Kernel needs raw key for unlock. | encryption 1.2 | |
| E5 | External TLS: TLS 1.3 only. No 1.2, no 1.1. | Caddy config: `protocols tls1.3`. | encryption 2.1 | |
| E6 | Internal mTLS: HSM-backed CA, 24h certs, auto-rotated every 12h. | Per-container certs with CN + SANs. Graceful reload on rotation. | encryption 2.2 | |
| E7 | Ollama (Jetson): TLS + cert pinning or WireGuard. | Proxy config has `pin_sha256` for Jetson cert. | encryption 2.3 | |
| E8 | Ollama (remote GPU): WireGuard tunnel (+ optional TLS). | Already encrypted at network layer. | encryption 2.3 | |
| E9 | All certs on tmpfs (RAM only), destroyed on shutdown. | Path: `/run/lobsec/certs/`. No persistent cert files. | encryption 3.5 | |
| E10 | ACME supports DNS-01 challenge (no open ports needed for G1). | Caddy DNS-01 with Cloudflare/Route53/etc. Compatible with zero-public-surface goal. | encryption 3.3 | |
| E11 | Key hierarchy rooted in HSM. Every crypto key traceable to HSM storage. | Key tree documented. No orphan keys outside HSM. | encryption 4.0 | |
| E12 | Backup: HSM token backup + age-encrypted offsite copy. | SoftHSM2 token dir backup + `age -p` encryption. | encryption 4.1 | |

---

## F. OpenClaw Integration

| ID | Requirement | Verification Criteria | Source | Status |
|----|-------------|----------------------|--------|--------|
| F1 | Plugin uses these hooks: `before_tool_call`, `before_model_resolve`, `message_sending`, `tool_result_persist`, `before_message_write`, `llm_input`, `llm_output`. | All seven hooks registered in lobsec-plugin. | DESIGN 4.1 | |
| F2 | Plugin registers `/sovereign` and `/public` commands via `registerCommand`. | User can type these in any channel to switch mode. | DESIGN 4.1 | |
| F3 | `baseUrl` override routes all LLM traffic through lobsec-proxy. | Config: `models.providers.*.baseUrl: "http://lobsec-proxy:8080"`. | DESIGN 9.1 | |
| F4 | `config.patch` blocked by three mechanisms: tool deny, read-only mount, WebSocket filtering. | Triple defense. No single point of failure. | verification-resolution V1 | |
| F5 | Auto-update disabled. | Config: `update.auto.enabled: false` OR env: `OPENCLAW_NIX_MODE=1`. | DESIGN 9.2 | |
| F6 | Plugin allowlist enforced (closed by default). | Config: `plugins.allow: ["lobsec"]`. Only lobsec plugin loads. | DESIGN 9.2 | |
| F7 | Dangerous env vars stripped from container environment. | `OPENCLAW_BROWSER_CONTROL_MODULE`, `OPENCLAW_BUNDLED_*_DIR`, `OPENCLAW_LIVE_CLI_BACKEND` -- not set. | DESIGN 9.2 | |
| F8 | `tools.elevated.enabled: false`. | No host execution escape from sandbox. | DESIGN 9.2 | |
| F9 | All 11 `dangerously*` flags blocked at startup. | lobsec-cli refuses to start if any is enabled. | DESIGN 9.3 | |
| F10 | `session.dmScope: "per-channel-peer"`. | Per-sender session isolation. | security docs | |
| F11 | Tool groups denied: `group:automation`, `group:runtime`. | In addition to individual tool denies. | DESIGN 9.3 | |
| F12 | Gateway logs redirected from `/tmp` to encrypted log directory. | Logs go to fscrypt-protected `~/.openclaw/logs/`, not `/tmp/openclaw/`. | DESIGN 9.2 | |

---

## G. Hardened Configuration (lobsec-generated openclaw.json)

| ID | Setting | Required Value | Default (insecure) | Status |
|----|---------|---------------|-------------------|--------|
| G1 | `gateway.bind` | `"loopback"` | `"lan"` | |
| G2 | `gateway.auth.mode` | `"token"` | `"none"` | |
| G3 | `gateway.controlUi.dangerouslyDisableDeviceAuth` | `false` | user had `true` | |
| G4 | `agents.defaults.sandbox.mode` | `"all"` | `"off"` | |
| G5 | `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` | `false` | `true` | |
| G6 | `discovery.mdns.mode` | `"off"` | `"minimal"` | |
| G7 | `tools.deny` | `["gateway", "sessions_spawn", "sessions_send"]` | not set | |
| G8 | `tools.exec.security` | `"deny"` | `"deny"` (already safe) | |
| G9 | `logging.redactSensitive` | `true` | not set | |
| G10 | `tools.elevated.enabled` | `false` | varies | |
| G11 | `update.auto.enabled` | `false` | varies | |
| G12 | `session.dmScope` | `"per-channel-peer"` | `"main"` | |
| G13 | `tools.fs.workspaceOnly` | `true` | varies | |
| G14 | All `dangerously*` flags | `false` or absent | varies | |

---

## H. Threat Coverage

| ID | Attack Class | Vuln Count | Primary Layer | Verification Criteria | Status |
|----|-------------|-----------|--------------|----------------------|--------|
| H1 | OS Command Injection | 4 | L6 (Sandbox) | Sandbox containers: no network, RO fs, cap_drop ALL. `before_tool_call` validates commands. | |
| H2 | SSRF | 6 | L5 (Egress) | Gateway has no internet route. All egress through proxy with allowlist + denylist. IPv4-mapped IPv6 blocked. | |
| H3 | Webhook Auth Bypass | 3 | L3 (Webhook) | Crypto verification per channel. HSM-backed. Replay protection. Startup gate. | |
| H4 | Path Traversal | 4 | L6 (Sandbox) | Container filesystem isolation. `realpath()` validation. Symlink blocking. AppArmor. | |
| H5 | WebSocket/Gateway Abuse | 2 | L1+L2+L4 | Loopback binding + Caddy Origin validation + `tools.deny: ["gateway"]` + read-only config mount. | |
| H6 | Sandbox Bypass | 4 | L6 (Sandbox) | Independent command validation. Deterministic config. Container immutability. Read-only root. | |
| H7 | Credential Leakage | 4 | L7 (Credential) | HSM storage. Real keys only in proxy. Dual-layer log redaction. Session isolation. | |
| H8 | XSS | 2 | L2 (CSP) | CSP headers via Caddy. X-Frame-Options DENY. Mostly upstream responsibility. | |
| H9 | Network Discovery | 1 | L1 (Perimeter) | mDNS off. No open ports. nftables blocks UDP 5353. VPN-only access. | |
| H10 | Supply Chain (Skills) | 1 | L6 (Sandbox) | Skill allowlist. Sandboxed installation. Static analysis. HSM-signed integrity. HEARTBEAT/cron monitoring. | |
| H11 | Insecure Defaults | 3 | L4 (Policy) | Hardened config (Section G above). Drift detection. Startup audit. Read-only config mount. Dangerous flag blocking. | |
| H12 | Prompt Injection | 3 | Defense-in-depth | Structural separation. Output validation. Tool gating. Identity verification. Sandbox as backstop. | |

---

## Audit Summary

| Category | Items | OK | Missing | Wrong | Partial | N/A |
|----------|------:|---:|--------:|------:|--------:|----:|
| A. ADRs | 15 | | | | | |
| B. Components | 9 | | | | | |
| C. Security Layers | 21 | | | | | |
| D. Credentials | 10 | | | | | |
| E. Encryption | 12 | | | | | |
| F. OpenClaw Integration | 12 | | | | | |
| G. Hardened Config | 14 | | | | | |
| H. Threat Coverage | 12 | | | | | |
| **TOTAL** | **105** | | | | | |

---

## Notes

_Use this space to record audit findings, discrepancies, or items needing discussion._
