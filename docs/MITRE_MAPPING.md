# MITRE ATT&CK and Framework Mapping

> **Version:** 1.0
> **Date:** 2026-02-27
> **Status:** Current as of lobsec production deployment

This document maps lobsec's nine security layers (L1--L9) to industry-standard threat and resilience frameworks. The goal is to make lobsec's coverage -- and its gaps -- legible to anyone familiar with MITRE ATT&CK, NIST SP 800-160 Vol. 2, or the OWASP AI Security & Integrity Top 10.

For full layer definitions, see [DESIGN.md](DESIGN.md) Section 5.

---

## 1. MITRE ATT&CK Mapping

ATT&CK techniques selected for relevance to an AI assistant gateway handling messaging channels, LLM inference, and tool execution.

| Technique ID | Technique Name | lobsec Layer | Mitigation |
|---|---|---|---|
| T1059 | Command and Scripting Interpreter | L6 Execution Sandbox + L4 Gateway Policy | Tool execution runs in a rootless Docker container with no network, read-only filesystem, cap_drop ALL, and seccomp filtering. L4 enforces tool deny lists (`group:automation`, `group:runtime` blocked) and validates commands before they reach the sandbox. |
| T1190 | Exploit Public-Facing Application | L1 Network Perimeter | No ports are exposed to the public internet. The gateway binds to loopback only. All administrative access requires SSH or VPN. nftables enforces default-deny inbound. mDNS advertising is disabled. |
| T1552 | Unsecured Credentials | L7 Credential Broker | All secrets are stored in an HSM (SoftHSM2/YubiHSM2) via PKCS#11. Credentials are injected just-in-time into tmpfs or environment variables, never written to persistent disk. Signing and webhook verification keys are non-extractable -- the HSM performs cryptographic operations directly. |
| T1048 | Exfiltration Over Alternative Protocol | L5 Egress Firewall | The OpenClaw gateway container has no route to the internet. All outbound traffic must traverse the lobsec-proxy, which enforces a domain allowlist, blocks RFC1918 and IPv6-mapped addresses, and logs every egress request. |
| T1105 | Ingress Tool Transfer | L6 Execution Sandbox | Sandbox containers have no network access and a read-only filesystem. There is no path to download tools, binaries, or payloads into the execution environment. |
| T1078 | Valid Accounts | L3 Webhook Authenticator + L4 Gateway Policy | Inbound webhooks are verified with HSM-backed cryptographic signatures before reaching the gateway. The gateway itself requires token authentication. Device pairing auth is enforced (the `dangerouslyDisableDeviceAuth` flag is blocked at startup). |
| T1071 | Application Layer Protocol | L5 Egress Firewall | All outbound HTTP/HTTPS traffic passes through the egress proxy. Only explicitly allowlisted domains are reachable. The proxy inspects and logs application-layer requests, preventing covert channels over permitted protocols. |
| T1562 | Impair Defenses | L4 Gateway Policy | The OpenClaw configuration is mounted read-only. The lobsec-plugin detects config drift at runtime and blocks `config.patch` WebSocket RPC calls that could weaken security settings. All `dangerously*` flags are rejected at startup. |
| T1565 | Data Manipulation | L9 Audit Logger | Audit entries are structured JSON with correlation IDs. Entries are chained via SHA-256 hashes, forming a tamper-evident log. The chain is periodically signed with a non-extractable RSA-2048 key in the HSM. Altering any entry breaks the hash chain. |
| T1499 | Endpoint Denial of Service | L2 Reverse Proxy Gate | Caddy sits in front of the gateway and enforces rate limiting, connection limits, and request size caps. TLS 1.3 termination at Caddy prevents the gateway from bearing TLS handshake costs directly. |

---

## 2. NIST SP 800-160 Vol. 2 -- Cyber Resiliency Techniques

Mapping of NIST cyber resiliency techniques to lobsec's design and operational capabilities.

| Resiliency Technique | lobsec Implementation | Notes |
|---|---|---|
| Adaptive Response | Sovereign/public routing fallback. When a cloud backend is unavailable or a budget limit is exceeded, inference falls back to sovereign (local) backends automatically. User can also switch manually via `/sovereign` and `/public` commands. | Routing is user-declared by default (ADR-4). Automatic fallback is limited to availability and budget triggers. |
| Analytic Monitoring | L9 audit logger captures every LLM request, tool call, egress connection, and webhook event as structured JSON with correlation IDs. HSM-signed hash chain provides tamper evidence. | Alerting on audit data is designed but not yet deployed operationally. |
| Contextual Awareness | The lobsec-plugin tracks per-session mode (sovereign vs. public) and applies routing and redaction rules based on session context. Config drift detection provides awareness of unauthorized changes. | Session context is per-channel and per-conversation, not per-user (OpenClaw is single-user). |
| Coordinated Protection | Nine independent security layers (L1--L9), each designed to operate under the assumption that all outer layers have been bypassed. Cross-reference matrix documents primary and defense-in-depth coverage for all 12 attack classes. | See DESIGN.md Section 5 for the full cross-reference matrix. |
| Deception | **Not implemented.** No honeypots, decoy credentials, or canary tokens are deployed. | Identified as a gap. See Section 5 below. |
| Diversity | Multiple inference backends across different hardware and providers: local GPU (Jetson), remote sovereign GPU, and cloud APIs. Different model families (Qwen, Gemma, LLaMA, Claude) reduce single-provider dependency. | Diversity is primarily for availability and privacy, not adversarial resilience. |
| Dynamic Positioning | JIT credential injection via HSM. API keys and tokens are retrieved from the HSM, placed on tmpfs, and destroyed after use. The lobsec-proxy holds real credentials in memory only and injects them per-request. OpenClaw never possesses real credentials. | Credential positions change on every restart. Key material is not static on disk. |
| Non-Persistence | Credentials exist only on tmpfs and in process memory. On shutdown, tmpfs is unmounted and memory is released. HSM-backed signing keys are never extracted. The sandbox execution environment is ephemeral -- containers are destroyed after each tool execution. | Persistent state (session transcripts, config) is protected by fscrypt encryption at rest. |
| Privilege Restriction | Sandbox containers run with cap_drop ALL, no-new-privileges, a custom seccomp whitelist, and a read-only filesystem. The gateway runs as a non-root user under systemd with NoNewPrivileges, ProtectSystem=strict, ProtectHome, and an empty CapabilityBoundingSet. | Only lobsec-cli (the orchestrator) has HSM access. No other component is privileged. |
| Redundancy | Sovereign and cloud inference paths provide redundant LLM access. If sovereign backends are unavailable, public cloud is used (and vice versa). The system continues operating in degraded mode if any single backend fails. | Redundancy is currently limited to inference routing. There is no redundancy for the gateway or audit subsystems. |

---

## 3. OWASP AI Security & Integrity (ASI) Top 10

Mapping of the OWASP ASI Top 10 to lobsec's defenses. Items are listed by their ASI identifier.

| ASI ID | Risk | lobsec Defense | Layer(s) |
|---|---|---|---|
| ASI-01 | Prompt Injection | Defense-in-depth. L4 tool gating blocks dangerous commands before execution. L6 sandbox isolates tool execution (no network, RO filesystem, cap_drop ALL). L8 output redaction scans responses for credential leakage. No single layer claims to solve prompt injection -- each limits the blast radius. | L4, L6, L8 |
| ASI-02 | Sensitive Information Disclosure | L7 credential broker ensures real API keys never enter the OpenClaw process. L8 output redaction (via `message_sending` and `tool_result_persist` hooks) scans all outbound messages and tool results for credential patterns and PII. Credentials in logs are redacted. | L7, L8 |
| ASI-03 | Supply Chain Vulnerabilities | Plugin allowlist is enforced (closed by default). Plugin code scanner results are validated independently by the lobsec-plugin. Tool execution runs in a sandboxed container. Auto-update is disabled to prevent remote code execution via npm. | L4, L6 |
| ASI-04 | Data Poisoning | Sovereign routing (L8) allows the operator to control the inference path entirely. When in sovereign mode, prompts and data never leave local infrastructure, eliminating the data poisoning vector via cloud provider compromise. Training data provenance is controlled by model selection. | L8 |
| ASI-05 | Improper Output Handling | L8 credential redaction operates on all outputs via the `message_sending` hook. The plugin scans for credential patterns (API keys, tokens, secrets) and redacts them before the response reaches the messaging channel. Tool results are similarly scrubbed via `tool_result_persist`. | L8 |
| ASI-07 | System Prompt Leakage | L8 output validation inspects outbound messages. The lobsec-plugin hooks into `message_sending` to detect and block responses that contain system prompt content or configuration details. | L8 |
| ASI-08 | Excessive Agency | L4 tool validation enforces deny lists (e.g., `group:automation` and `group:runtime` are blocked by default). The `before_tool_call` hook can block any tool invocation that violates policy. L6 sandbox ensures that even permitted tool calls execute in an isolated, air-gapped environment. | L4, L6 |
| ASI-09 | Overreliance | **Not in scope.** Overreliance is a user behavior risk. lobsec operates as infrastructure-level hardening and does not attempt to mediate the user's trust relationship with the AI. | -- |
| ASI-10 | Unbounded Consumption | Budget tracking and rate limiting are designed in the proxy architecture (per-session and per-provider spend caps). L2 Caddy rate limiting constrains inbound request rates. Budget enforcement at the proxy level is designed but not yet deployed. | L2 (deployed), L5 (designed) |

---

## 4. Cross-Framework Summary

The following table shows which lobsec layers contribute to each framework's coverage.

| Layer | ATT&CK Techniques Mitigated | NIST Resiliency Techniques | OWASP ASI Items |
|---|---|---|---|
| L1 Network Perimeter | T1190 | -- | -- |
| L2 Reverse Proxy Gate | T1499 | -- | ASI-10 |
| L3 Webhook Authenticator | T1078 | -- | -- |
| L4 Gateway Policy | T1059, T1078, T1562 | Contextual Awareness, Coordinated Protection | ASI-01, ASI-03, ASI-08 |
| L5 Egress Firewall | T1048, T1071 | -- | ASI-10 |
| L6 Execution Sandbox | T1059, T1105 | Non-Persistence, Privilege Restriction | ASI-01, ASI-03, ASI-08 |
| L7 Credential Broker | T1552 | Dynamic Positioning, Non-Persistence | ASI-02 |
| L8 Privacy Engine | -- | Adaptive Response, Diversity, Redundancy | ASI-01, ASI-02, ASI-04, ASI-05, ASI-07 |
| L9 Audit Logger | T1565 | Analytic Monitoring | -- |

---

## 5. Coverage Gaps

Honest assessment of techniques and controls that lobsec does NOT address or addresses only partially.

### ATT&CK Gaps

| Technique ID | Technique Name | Gap Description |
|---|---|---|
| T1055 | Process Injection | Container isolation provides some boundary, but lobsec does not include specific hardening against in-process injection techniques (e.g., ptrace, LD_PRELOAD within the container). The seccomp profile restricts some syscalls, but this is not a targeted mitigation. |
| T1027 | Obfuscated Files or Information | No inspection or deobfuscation of tool inputs or outputs beyond credential pattern matching. An adversary could encode exfiltrated data to bypass output redaction. |
| T1021 | Remote Services | Internal service-to-service communication (gateway to proxy) does not yet enforce mTLS. Certificates have been generated but are not yet in use. An attacker with network access to the internal Docker network could impersonate services. |

### NIST Resiliency Gaps

| Technique | Gap Description |
|---|---|
| Deception | No honeypots, canary tokens, or decoy credentials are deployed. An attacker who gains access to the internal network receives no misleading signals. |
| Realignment | No automated mechanism to restore the system to a known-good state after a detected compromise. Recovery is manual. |
| Substantiated Integrity | While the audit log is tamper-evident (hash chain + HSM signing), there is no independent verification service that continuously validates log integrity. |

### OWASP ASI Gaps

| ASI ID | Gap Description |
|---|---|
| ASI-06 | Excessive Autonomy in critical decisions. lobsec restricts tool use but does not implement human-in-the-loop approval for high-risk operations. |
| ASI-09 | Overreliance. Explicitly out of scope -- lobsec is infrastructure hardening, not user behavior management. |
| ASI-10 | Budget enforcement at the proxy level is designed but not yet deployed. Current protection is limited to Caddy rate limiting on inbound requests. |

### General Gaps

- **No RBAC or multi-user access control.** lobsec inherits OpenClaw's single-user trust model. There is no per-user authorization, role separation, or access control beyond the operator/AI boundary.
- **No network intrusion detection.** Traffic is filtered and logged, but there is no IDS/IPS analyzing traffic patterns for anomalies.
- **mTLS not yet enforced.** Internal certificates exist but are not yet loaded by services. Service-to-service traffic on the internal Docker network is currently unencrypted.

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/) -- Enterprise Matrix v15
- [NIST SP 800-160 Vol. 2 Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-160/vol-2-rev-1/final) -- Developing Cyber-Resilient Systems
- [OWASP AI Security & Integrity Top 10](https://owasp.org/www-project-ai-security-and-privacy-guide/) -- 2025 Edition
- [lobsec DESIGN.md](DESIGN.md) -- Security Design Document
- [lobsec security-layers.md](architecture/security-layers.md) -- Nine Layer Architecture
