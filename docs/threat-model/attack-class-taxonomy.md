# OpenClaw Attack-Class Taxonomy

> Derived from the [OpenClaw Vulnerability Report](../OpenClaw%20Vulnerability%20Report%20.md) (30+ CVEs, Feb 2026).
> Every class traces to verified CVEs. Nothing is fabricated.

## Summary Matrix

| # | Attack Class | Vulns | Count | lobsec Wrapper Mitigation |
|---|---|---|---|---|
| 1 | OS Command Injection | 2, 3, 19, 20 | 4 | Partial (gateway: yes; macOS/dev: upstream) |
| 2 | Server-Side Request Forgery | 7, 10, 11, 13, 15, 28 | 6 | **Strong** (egress allowlist, SSRF guard) |
| 3 | Webhook Authentication Bypass | 6, 8, 12 | 3 | **Strong** (mandatory signature verification) |
| 4 | Path Traversal / File Access | 5, 9, 23, 30 | 4 | **Strong** (realpath, chroot, read-only mounts) |
| 5 | WebSocket / Gateway Protocol Abuse | 1, 4 | 2 | **Critical** (origin validation, auth, schema) |
| 6 | Sandbox / Execution Policy Bypass | 14, 21, 24, 27 | 4 | Moderate (independent allowlist eval) |
| 7 | Information Disclosure / Credential Leakage | 17, 25, 26, 34 | 4 | **Strong** (redaction, JIT creds, encryption) |
| 8 | XSS / Client-Side Injection | 16, 22 | 2 | Minimal (CSP headers; upstream for fix) |
| 9 | Network Discovery Poisoning | 18 | 1 | **Strong** (disable mDNS, VPN-only) |
| 10 | Supply Chain Poisoning | 37 | 1 | **Strong** (skill allowlist, signing, sandbox) |
| 11 | Insecure Defaults / Architectural Misdesign | 33, 35, 36 | 3 | **Core mission** (secure-by-default config) |
| 12 | Prompt Injection / Identity Spoofing | 27, 31, 32 | 3 | Moderate (sanitization, defense-in-depth) |

Vulnerability numbers reference the [full enumeration](#vulnerability-index) at the bottom of this document.

---

## Class 1: OS Command Injection

**CWE Family:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

Unsanitized user-controlled input is interpolated into shell command strings passed to `execSync` or equivalent, allowing arbitrary command execution on the host.

**Vulnerabilities:**
- **#2** CVE-2026-24763 -- Docker Sandbox Escape via PATH Injection (CVSS 8.8)
- **#3** CVE-2026-25157 -- SSH Command Injection in macOS App (CVSS 7.8)
- **#19** macOS keychain CLI injection
- **#20** clawtributors.ts command injection

**Affected Components:** Docker sandbox executor, macOS SSH handler (`CommandResolver.swift`), macOS keychain integration, `scripts/update-clawtributors.ts`

**lobsec Mitigation:** Partial. Gateway-side: lobsec can interpose on all `exec`/`spawn` calls via tool execution callbacks, enforcing strict allowlists and argument validation. macOS app and dev-tooling vectors require upstream patching (they occur outside the gateway runtime).

---

## Class 2: Server-Side Request Forgery (SSRF)

**CWE Family:** CWE-918 (Server-Side Request Forgery)

Attacker-controlled URLs or hostnames are passed to server-side HTTP/WebSocket fetch operations without adequate validation, allowing the gateway to probe internal networks, cloud metadata endpoints, or localhost services.

**Vulnerabilities:**
- **#7** CVE-2026-26322 -- SSRF in Gateway tool (CVSS 7.6)
- **#10** GHSA-56f2-hvwg-5743 -- SSRF in image tool (CVSS 7.6)
- **#11** GHSA-pg2v-8xwh-qhcc -- SSRF in Urbit auth (CVSS 6.5)
- **#13** SSRF bypass via IPv4-mapped IPv6
- **#15** Feishu local file exfiltration
- **#28** Cron webhook SSRF

**Affected Components:** Gateway tool URL handler, image tool remote fetch, Urbit auth extension, SSRF guard (`src/infra/net/ssrf.ts`), Feishu channel media handler, cron webhook delivery

**lobsec Mitigation:** Strong. Enforce egress-only allowlist at the network layer (iptables/nftables in Docker sandbox), validate all outbound URLs against strict policy before fetch, block RFC 1918 / link-local / metadata address ranges including IPv4-mapped IPv6 representations. Highest-value wrapper target by volume.

---

## Class 3: Webhook Authentication Bypass

**CWE Family:** CWE-306 (Missing Authentication for Critical Function) / CWE-347 (Improper Verification of Cryptographic Signature)

Channel webhook endpoints accept unauthenticated or insufficiently authenticated HTTP requests when secret/signature verification is absent or misconfigured, allowing attackers to forge inbound events.

**Vulnerabilities:**
- **#6** Telegram Webhook Authentication Bypass
- **#8** CVE-2026-26319 -- Missing Telnyx webhook auth
- **#12** GHSA-c37p-4qqg-3p76 -- Twilio webhook auth bypass

**Affected Components:** Telegram, Telnyx, Twilio webhook handlers

**lobsec Mitigation:** Strong. Enforce mandatory webhook signature verification as a prerequisite for all inbound channel routes. Refuse to start if webhook secrets are not configured. Convert insecure defaults into secure defaults.

---

## Class 4: Path Traversal / Arbitrary File Access

**CWE Family:** CWE-22 (Path Traversal) / CWE-59 (Improper Link Resolution)

User-supplied file paths or directory names are used without canonicalization or containment checks, allowing reads or writes outside the intended sandbox/workspace directory.

**Vulnerabilities:**
- **#5** Arbitrary File Read via isValidMedia()
- **#9** CVE-2026-26329 -- Path traversal in browser upload
- **#23** Skill install path traversal
- **#30** Skill package symlink following

**Affected Components:** Media validation (`isValidMedia()`), browser upload endpoints, skill installation, skill package extraction

**lobsec Mitigation:** Strong. Enforce `realpath()` canonicalization and chroot-style containment for all file operations. Block any resolved path escaping workspace root. Read-only filesystem mounts in Docker sandbox with explicit bind-mount allowlists.

---

## Class 5: WebSocket / Gateway Protocol Abuse

**CWE Family:** CWE-669 (Incorrect Resource Transfer Between Spheres) / CWE-346 (Origin Validation Error)

The WebSocket control channel accepts connections without origin validation or token verification, or allows attacker-controlled parameters to reconfigure gateway behavior.

**Vulnerabilities:**
- **#1** CVE-2026-25253 -- 1-Click RCE via WebSocket Token Exfiltration (CVSS 8.8)
- **#4** Unauthenticated Config Injection via Gateway WebSocket

**Affected Components:** WebSocket server (`ws://localhost:18789`), gateway configuration API (`config.patch`, `exec.approvals.set`)

**lobsec Mitigation:** Critical. This is the single most important mitigation point. CVE-2026-25253 chains through the WebSocket to achieve full RCE even on localhost-only deployments. lobsec must enforce: origin header validation, mandatory auth tokens on all WebSocket connections, frame-level JSON schema validation, and block runtime configuration changes via WebSocket.

---

## Class 6: Sandbox / Execution Policy Bypass

**CWE Family:** CWE-693 (Protection Mechanism Failure) / CWE-863 (Incorrect Authorization)

Security controls meant to constrain tool execution can be circumvented through configuration manipulation, command aliasing, hash collisions, or argument mismatch between policy evaluation and actual execution.

**Vulnerabilities:**
- **#14** rawCommand/command[] mismatch (allowlist bypass)
- **#21** Docker sandbox configuration injection
- **#24** Sandbox config hash collision
- **#27** Workspace path prompt injection

**Affected Components:** Node host `system.run` handler, Docker sandbox config/recreation, command allowlist engine, workspace path resolution

**lobsec Mitigation:** Moderate. Independent allowlist evaluation on the actual command being executed (not declared command). Deterministic sandbox config with SHA-256 hashing. Workspace path validation. The rawCommand/command[] mismatch (#14) is an upstream logic bug requiring upstream fix.

---

## Class 7: Information Disclosure / Credential Leakage

**CWE Family:** CWE-200 (Information Exposure) / CWE-532 (Sensitive Info in Log) / CWE-312 (Cleartext Storage)

Secrets, tokens, API keys, or session data exposed through logs, error messages, API responses, status endpoints, or cross-session leakage.

**Vulnerabilities:**
- **#17** skills.status secrets disclosure
- **#25** Cross-session transcript access
- **#26** Telegram bot token leakage
- **#34** Plaintext secrets storage

**Affected Components:** Skills status API, session/transcript storage, Telegram error logging, credential storage (`~/.openclaw/`)

**lobsec Mitigation:** Strong. Core value proposition. Intercept all outbound log/error output and redact secret patterns. Enforce session isolation. Store credentials in HSM-backed or encrypted-at-rest storage with JIT issuance. Strip tokens from URLs before logging.

---

## Class 8: XSS / Client-Side Injection

**CWE Family:** CWE-79 (XSS)

Unsanitized data rendered into HTML or inline script contexts in the Control UI or deep-link dialogs.

**Vulnerabilities:**
- **#16** macOS deep link message truncation
- **#22** Stored XSS in Control UI

**Affected Components:** Control UI assistant name/avatar rendering, macOS deep link confirmation dialog

**lobsec Mitigation:** Minimal. CSP headers on Control UI (block inline scripts, restrict sources). Deep link truncation (#16) is a macOS app bug requiring upstream fix. Stored XSS (#22) needs upstream output encoding; CSP provides defense-in-depth.

---

## Class 9: Network Discovery Poisoning

**CWE Family:** CWE-300 (Channel Accessible by Non-Endpoint) / CWE-940 (Improper Source Verification)

Unauthenticated mDNS/DNS-SD service announcements expose gateway metadata and can be spoofed for credential theft on shared LANs.

**Vulnerabilities:**
- **#18** mDNS/DNS-SD discovery poisoning

**Affected Components:** mDNS/DNS-SD service broadcaster, client-side service discovery

**lobsec Mitigation:** Strong. Eliminated by architecture: SSH/VPN-only access, no public ports. Disable mDNS broadcasting entirely. Require explicit gateway endpoint configuration.

---

## Class 10: Supply Chain Poisoning (ClawHub Skills)

**CWE Family:** CWE-494 (Download Without Integrity Check) / CWE-506 (Embedded Malicious Code)

The ClawHub skill marketplace allows malicious packages that execute arbitrary code, exfiltrate data, or install backdoors.

**Vulnerabilities:**
- **#37** ClawHub malicious skills (824+ confirmed, 10.8% of sampled)

**Affected Components:** ClawHub registry, skill installation pipeline, skill runtime

**lobsec Mitigation:** Strong. Curated allowlist of vetted skills. Code-signing verification on packages. Sandboxed skill execution with no filesystem/network access beyond explicit grants. Static analysis on manifests before installation.

---

## Class 11: Insecure Defaults / Architectural Misdesign

**CWE Family:** CWE-1188 (Insecure Default Initialization) / CWE-250 (Execution with Unnecessary Privileges)

System ships insecure out of the box: 0.0.0.0 binding, no auth, plaintext secrets, exposed databases.

**Vulnerabilities:**
- **#33** Supabase database exposed without RLS
- **#35** Insecure default configuration
- **#36** Structural LLM agent risks ("The Terrifying Five")

**Affected Components:** Gateway network config, Supabase/database layer, credential storage defaults, agent permission model

**lobsec Mitigation:** This is lobsec's entire reason for existing. Enforce: localhost-only binding behind SSH/VPN, mandatory authentication, encrypted credential storage with JIT issuance, least-privilege tool execution, and ongoing prompt isolation / output validation / tool sandboxing for the structural LLM risks.

---

## Class 12: Prompt Injection / Identity Spoofing

**CWE Family:** CWE-74 (Injection) / CWE-287 (Improper Authentication)

Attacker-controlled content (channel metadata, message payloads, workspace paths) consumed by the LLM as trusted context, enabling behavior manipulation or privilege escalation.

**Vulnerabilities:**
- **#27** Workspace path prompt injection (also in Class 6)
- **#31** Discord moderation identity spoofing
- **#32** Slack channel metadata prompt injection

**Affected Components:** LLM prompt construction, Discord moderation dispatch, Slack metadata ingestion, workspace path resolution

**lobsec Mitigation:** Moderate. Sanitize and structurally separate user content from system prompts (RED/AMBER/GREEN classification). Server-side identity verification for moderation actions. Workspace path validation before prompt injection. Prompt injection is inherently difficult -- defense-in-depth (output validation, tool allowlists, human-in-the-loop) is the realistic approach.

---

## Outlier: Denial of Service

**Vulnerability #29** (ACP bridge oversized prompt) is a resource exhaustion issue (CWE-400). Does not fit the 12 classes above which focus on confidentiality/integrity. lobsec mitigates via request size limits on ACP bridge input.

---

## lobsec Design Priority (by wrapper mitigation value)

| Priority | Attack Class | Rationale |
|----------|-------------|-----------|
| 1 | Class 11 -- Insecure Defaults | This is what lobsec exists for |
| 2 | Class 5 -- WebSocket Protocol Abuse | Highest single-vuln severity (CVSS 8.8) |
| 3 | Class 2 -- SSRF | Largest cluster (6 vulns), clean network-layer mitigation |
| 4 | Class 7 -- Credential Leakage | Core to PII/secret protection goals |
| 5 | Class 3 -- Webhook Auth Bypass | Straightforward enforcement |
| 6 | Class 4 -- Path Traversal | Standard filesystem containment |
| 7 | Class 10 -- Supply Chain | High real-world impact (824+ malicious skills) |
| 8 | Class 1 -- Command Injection | Partially addressable via tool callbacks |
| 9 | Class 6 -- Sandbox Bypass | Requires careful policy re-implementation |
| 10 | Class 12 -- Prompt Injection | Inherently hard; defense-in-depth only |
| 11 | Class 9 -- Network Discovery | Trivially eliminated by VPN-only architecture |
| 12 | Class 8 -- XSS | Mostly upstream; CSP is our only lever |

---

## Vulnerability Index

| # | Vulnerability | CVE/Advisory | CVSS | Version Fixed |
|---|---|---|---|---|
| 1 | 1-Click RCE via WebSocket Token Exfil | CVE-2026-25253 | 8.8 | v2026.1.29 |
| 2 | Docker Sandbox Escape via PATH Injection | CVE-2026-24763 | 8.8 | v2026.1.29 |
| 3 | SSH Command Injection (macOS) | CVE-2026-25157 | 7.8 | v2026.1.29 |
| 4 | Unauth Config Injection via Gateway WS | -- | High | v2026.1.20 |
| 5 | Arbitrary File Read via isValidMedia() | -- | High | v2026.1.30 |
| 6 | Telegram Webhook Auth Bypass | -- | High | v2026.2.1 |
| 7 | SSRF in Gateway tool | CVE-2026-26322 | 7.6 | v2026.2.14 |
| 8 | Missing Telnyx webhook auth | CVE-2026-26319 | 7.5 | v2026.2.14 |
| 9 | Path traversal in browser upload | CVE-2026-26329 | High | v2026.2.14 |
| 10 | SSRF in image tool | GHSA-56f2-hvwg-5743 | 7.6 | v2026.2.14 |
| 11 | SSRF in Urbit auth | GHSA-pg2v-8xwh-qhcc | 6.5 | v2026.2.14 |
| 12 | Twilio webhook auth bypass | GHSA-c37p-4qqg-3p76 | 6.5 | v2026.2.14 |
| 13 | SSRF bypass via IPv4-mapped IPv6 | -- | -- | v2026.2.14 |
| 14 | rawCommand/command[] mismatch | -- | -- | v2026.2.14 |
| 15 | Feishu local file exfiltration | -- | -- | v2026.2.14 |
| 16 | macOS deep link message truncation | -- | -- | v2026.2.14 |
| 17 | skills.status secrets disclosure | -- | -- | v2026.2.14 |
| 18 | mDNS/DNS-SD discovery poisoning | -- | -- | v2026.2.14 |
| 19 | macOS keychain CLI injection | -- | -- | v2026.2.14 |
| 20 | clawtributors.ts command injection | -- | -- | v2026.2.14 |
| 21 | Docker sandbox config injection | -- | -- | v2026.2.15 |
| 22 | Stored XSS in Control UI | -- | -- | v2026.2.15 |
| 23 | Skill install path traversal | -- | -- | v2026.2.15 |
| 24 | Sandbox config hash collision | -- | -- | v2026.2.15 |
| 25 | Cross-session transcript access | -- | -- | v2026.2.15 |
| 26 | Telegram bot token leakage | -- | -- | v2026.2.15 |
| 27 | Workspace path prompt injection | -- | -- | v2026.2.15 |
| 28 | Cron webhook SSRF | -- | -- | v2026.2.19 |
| 29 | ACP bridge oversized prompt (DoS) | -- | -- | v2026.2.19 |
| 30 | Skill package symlink following | -- | -- | v2026.2.18 |
| 31 | Discord moderation identity spoofing | -- | -- | v2026.2.18 |
| 32 | Slack channel metadata prompt injection | -- | -- | v2026.2.3 |
| 33 | Supabase DB exposed without RLS | -- | -- | N/A (config) |
| 34 | Plaintext secrets storage | -- | -- | N/A (design) |
| 35 | Insecure default configuration | -- | -- | N/A (design) |
| 36 | Structural LLM agent risks | -- | -- | N/A (inherent) |
| 37 | ClawHub malicious skills (824+) | -- | -- | Partial (scanning) |
