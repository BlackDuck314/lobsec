# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-02-27

### Added
- 9-layer security architecture (L1-L9) wrapping OpenClaw
- OpenClaw plugin with 9 security hooks (tool gating, credential redaction, sovereign routing, config drift detection, audit logging)
- LLM proxy with sovereign-first inference routing and credential injection
- HSM credential management via PKCS#11 (SoftHSM2)
- fscrypt per-directory encryption for sensitive data directories
- HSM-signed tamper-evident audit logging with SHA-256 hash chains
- Docker sandbox hardening (rootless, cap_drop ALL, read-only rootfs, seccomp whitelist)
- Caddy L2 reverse proxy with TLS 1.3, rate limiting, and security headers
- nftables egress firewall with SSRF prevention and RFC1918 blocking
- mTLS certificate generation (P-256/ECDSA, self-signed CA, 30-day auto-renewal)
- Tool call validation with path containment, symlink resolution, and deny lists
- Credential redaction from all outputs (API keys, tokens, PII patterns)
- Sovereign/public inference routing via plugin hooks and proxy
- Budget enforcement framework for cloud API spend control
- systemd service units with NoNewPrivileges, ProtectSystem=strict, ProtectHome
- 706 tests across 33 test files (Vitest)
- Comprehensive documentation: design doc, threat model, security layers, encryption architecture
- OpenClaw update script with preflight checks, backup, and rollback
- Health check automation (15 checks every 5 minutes)

### Security
- All credentials stored in HSM, never on persistent disk
- JIT credential injection: HSM to tmpfs to env vars, wiped on shutdown
- Zero public attack surface: loopback-only binding, SSH/VPN access only
- Config drift detection prevents runtime weakening of security posture
- Audit log integrity protected by HSM RSA-2048 signing key (non-extractable)
