# lobsec Security Architecture

## Overview

lobsec is a security hardening wrapper for AI assistant frameworks. It provides 9 security layers (L1-L9) protecting against 12 attack classes.

## Security Layers

| Layer | Name | Description |
|-------|------|-------------|
| L1 | Network Perimeter | Zero public ports, nftables firewall, SSH/VPN only |
| L2 | Reverse Proxy | Caddy with security headers, rate limiting, TLS termination |
| L3 | HSM Credential Management | PKCS#11 HSM-backed key storage, JIT credential injection |
| L4 | Configuration Hardening | Drift detection, hash chain integrity, canonical config |
| L5 | Credential Redaction | API key, PII, and token scanning in all outputs |
| L6 | Tool Call Validation | Path containment, symlink resolution, deny lists |
| L7 | Egress Firewall | SSRF prevention, RFC1918 blocking, metadata endpoint blocking |
| L8 | LLM Proxy | Sovereign/public routing, budget enforcement, API key injection |
| L9 | Audit Logging | HSM-signed hash chain, tamper detection, structured logging |

## Attack Classes

| ID | Attack Class | Primary Layer | Defense-in-Depth |
|----|-------------|---------------|------------------|
| 1 | Unauthorized remote access | L1 | L2, L4 |
| 2 | Man-in-the-middle | L2 | L3 |
| 3 | Credential theft | L3 | L5, L9 |
| 4 | Tool abuse | L6 | L9 |
| 5 | Path traversal | L6 | L4 |
| 6 | Command injection | L6 | L9 |
| 7 | Prompt injection | L5 | L6 |
| 8 | Data exfiltration | L7 | L5 |
| 9 | Configuration tampering | L4 | L9 |
| 10 | Audit log tampering | L9 | L3 |
| 11 | Container escape | L1 | L4 |
| 12 | Supply chain compromise | L4 | L3, L9 |

## Package Structure

```
packages/
  shared/    — Core security primitives (HSM, crypto, config, containers)
  cli/       — lobsec CLI commands (init, start, stop, status, logs)
  plugin/    — Runtime hooks (tool validation, redaction, routing)
  proxy/     — LLM proxy (routing, credentials, egress, webhooks)
```

## Sovereign/Public Routing

lobsec supports three routing modes for LLM requests:
- **Sovereign**: All requests go to local inference (Jetson Orin, remote GPU). Cloud is never used. Sensitive data never leaves infrastructure.
- **Public**: Requests go to cloud APIs (Anthropic, OpenAI) with sovereign fallback.
- **Auto**: Cloud preferred when available, sovereign fallback. Budget-aware.

Budget thresholds: warn at 80%, downgrade model at 90%, block cloud at 100%.

## HSM Integration

All sensitive keys are stored in PKCS#11 HSM (SoftHSM2 for dev, YubiHSM2 for prod):
- Audit signing keys: RSA-2048, non-extractable
- Internal CA keys: EC-P256, non-extractable
- API keys: AES-256, extractable for injection
- fscrypt master keys: AES-256, extractable

## Container Security

5 containers with strict security contexts:
- `cap_drop: ALL`, `no-new-privileges`, `read-only rootfs`
- 3 networks: internal (proxy↔gateway), sandbox (isolated), egress (filtered)
- No Docker socket exposure
- Non-root user (1000:1000)

## Encryption at Rest

- **LUKS2**: AES-256-XTS, argon2id KDF (1 GiB memory)
- **fscrypt**: Directory-level encryption for workspace, agents, logs, canvas
- HSM-backed master keys for fscrypt
