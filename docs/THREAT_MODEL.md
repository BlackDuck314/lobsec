# lobsec Threat Model

> **Version:** 1.0
> **Date:** 2026-02-27
> **Status:** Current -- reflects deployed production state
> **Companion documents:** [DESIGN.md](DESIGN.md), [security-layers.md](architecture/security-layers.md), [attack-class-taxonomy.md](threat-model/attack-class-taxonomy.md)

---

## 1. Trust Boundaries

Four concentric trust zones govern how lobsec processes every message, tool
call, and inference request. Traffic crossing a boundary must be authenticated,
validated, and logged.

```
+========================================================================+
|                                                                        |
|  UNTRUSTED ZONE                                                        |
|  Internet, messaging platforms, external LLM APIs, ClawHub registry    |
|                                                                        |
|    Telegram / WhatsApp / Discord / Slack / Signal / ...                |
|    Cloud inference endpoints (Anthropic, OpenAI, ...)                  |
|    ClawHub skill marketplace                                           |
|                                                                        |
+============================[ BOUNDARY 1 ]==============================+
|                                                                        |
|  CONTROLLED ZONE                                                       |
|  Caddy L2 reverse proxy, nftables firewall, egress allowlist           |
|                                                                        |
|    +-------------------+       +--------------------------+            |
|    | nftables          |       | Caddy reverse proxy      |            |
|    | default-deny      |       | TLS 1.3, origin check,   |            |
|    | inbound + egress  |       | rate limit, CSP headers   |            |
|    +-------------------+       +--------------------------+            |
|                                                                        |
+============================[ BOUNDARY 2 ]==============================+
|                                                                        |
|  SEMI-TRUSTED ZONE                                                     |
|  OpenClaw gateway -- powerful but contained, never has real secrets     |
|                                                                        |
|    +-------------------------------+   +---------------------------+   |
|    | OpenClaw gateway              |   | lobsec-proxy              |   |
|    | (loopback only, sandbox=all)  |   | (LLM routing, egress      |   |
|    | (lobsec-plugin hooks active)  |   |  filtering, credential    |   |
|    | (read-only config mount)      |   |  injection, audit)        |   |
|    +-------------------------------+   +---------------------------+   |
|    |                                                                   |
|    |  +---------------------+   +---------------------+               |
|    |  | sandbox-exec        |   | sandbox-browser     |               |
|    |  | (air-gapped, no net)|   | (limited net)       |               |
|    |  +---------------------+   +---------------------+               |
|                                                                        |
+============================[ BOUNDARY 3 ]==============================+
|                                                                        |
|  TRUSTED ZONE                                                          |
|  lobsec-cli, HSM, host OS kernel, fscrypt/LUKS, systemd               |
|                                                                        |
|    +------------------+   +------------------+   +------------------+  |
|    | lobsec-cli       |   | SoftHSM2 /       |   | Host OS kernel   |  |
|    | (orchestrator,   |   | YubiHSM2         |   | (nftables,       |  |
|    |  HSM access,     |   | (PKCS#11 token,  |   |  cgroups,        |  |
|    |  cert rotation,  |   |  signing keys,   |   |  namespaces,     |  |
|    |  audit verify)   |   |  credentials)    |   |  seccomp)        |  |
|    +------------------+   +------------------+   +------------------+  |
|                                                                        |
+========================================================================+
```

**Boundary 1** (Untrusted -> Controlled): All inbound traffic must pass through
nftables and Caddy. No ports are open to the internet. Remote access is
SSH/VPN-only. Caddy enforces TLS 1.3, origin validation, and rate limiting.

**Boundary 2** (Controlled -> Semi-trusted): Webhook signatures are verified
(HSM-backed HMAC) before any message reaches OpenClaw. The gateway runs with
sandbox mode enabled, read-only config mounts, and the lobsec-plugin
intercepting every lifecycle hook. OpenClaw never holds real API keys.

**Boundary 3** (Semi-trusted -> Trusted): Only lobsec-cli has HSM access.
Only the host kernel enforces cgroup limits, namespaces, and seccomp profiles.
The HSM signing key is non-extractable. Audit log integrity is verified at
this boundary.

---

## 2. Attack Classes

Derived from 37 verified vulnerabilities across 12 attack classes. See
[attack-class-taxonomy.md](threat-model/attack-class-taxonomy.md) for the full
CVE-level enumeration.

| # | Attack Class | Vector Summary | Primary Layer | Defense-in-Depth Layers | Residual Risk |
|---|---|---|---|---|---|
| 1 | OS Command Injection | Unsanitized input passed to `execSync`/`spawn` in tool execution, achieving arbitrary host command execution. 4 CVEs, worst CVSS 8.8. | L6 (Execution Sandbox) | L4 (tool deny lists), L9 (audit) | Gateway-side contained by sandbox. macOS/dev-tooling vectors require upstream patches and are outside lobsec scope. |
| 2 | SSRF | Attacker-controlled URLs fetched server-side, probing internal networks, cloud metadata, or localhost services. Includes IPv4-mapped IPv6 bypass. 6 CVEs, worst CVSS 7.6. | L5 (Egress Firewall) | L6 (sandbox network isolation), L8 (proxy URL validation), L9 (audit) | Low. Egress allowlist plus air-gapped sandbox network blocks all internal probing. Novel bypass encodings remain theoretically possible. |
| 3 | Webhook Auth Bypass | Unauthenticated or weakly authenticated webhook endpoints accept forged inbound channel events. 3 CVEs, worst CVSS 8.2. | L3 (Webhook Authenticator) | L9 (audit) | Low. HSM-backed signature verification is mandatory. Residual risk if a channel protocol has no signing mechanism (none currently in use). |
| 4 | Path Traversal | User-supplied file paths escape workspace root via `../`, symlinks, or missing canonicalization. 4 CVEs, worst CVSS 7.5. | L6 (Execution Sandbox) | L9 (audit) | Low. Read-only filesystem mounts, explicit bind-mount allowlists, and `realpath()` enforcement in sandbox. Symlink race conditions are theoretically possible but constrained by read-only root. |
| 5 | WebSocket/Gateway Abuse | Unauthenticated WebSocket connections reconfigure gateway or exfiltrate tokens. Includes CVE-2026-25253 (1-click RCE chain, CVSS 8.8). | L1 (Network Perimeter), L2 (Reverse Proxy) | L4 (gateway policy, config.patch blocked), L9 (audit) | Medium. Loopback binding + auth tokens + origin validation block remote exploitation. A localhost attacker (e.g., compromised sandbox) could still attempt WebSocket interaction; mitigated by container network isolation. |
| 6 | Sandbox Bypass | Security controls circumvented via config manipulation, command aliasing, or hash collisions in allowlist evaluation. 4 CVEs, worst CVSS 8.1. | L6 (Execution Sandbox) | L4 (independent allowlist evaluation), L9 (audit) | Medium. lobsec re-evaluates the actual executed command independently. The rawCommand/command[] mismatch (#14) is an upstream logic bug; lobsec mitigates by evaluating both representations. Deterministic SHA-256 config hashing prevents collision attacks. |
| 7 | Credential Leakage | Secrets exposed via logs, error messages, status APIs, or cross-session leakage. 4 CVEs, worst CVSS 7.5. | L7 (Credential Broker) | L5 (egress filtering), L8 (output redaction), L9 (audit) | Low. OpenClaw never holds real API keys (proxy-only injection). Log redaction scans all outbound content. Residual: novel encoding of secrets that bypasses pattern matching. |
| 8 | XSS | Unsanitized data rendered in Control UI or macOS deep-link dialogs. 2 CVEs, worst CVSS 6.1. | Upstream (OpenClaw) | L2 (CSP headers), L9 (audit) | Medium. CSP headers provide defense-in-depth, but the primary fix must come from upstream output encoding. lobsec has limited control over client-side rendering. |
| 9 | Network Discovery | mDNS/DNS-SD service announcements expose gateway presence and metadata on shared networks. 1 CVE, CVSS 5.3. | L1 (Network Perimeter) | L4 (mDNS disabled in config), L9 (audit) | Negligible. Eliminated by architecture: no open ports, mDNS disabled, VPN-only access. |
| 10 | Supply Chain (Skills) | Malicious ClawHub skill packages execute arbitrary code, exfiltrate data, or install backdoors. 824+ confirmed malicious packages. | L6 (Execution Sandbox) | L5 (egress filtering), L9 (audit) | Low. Curated skill allowlist, code-signing verification, sandboxed execution with no filesystem or network access beyond explicit grants. Residual: a vetted skill could be compromised after allowlisting. |
| 11 | Insecure Defaults | System ships with 0.0.0.0 binding, no auth, plaintext secrets, sandbox disabled. This is lobsec's core reason for existing. | L4 (Gateway Policy) | L1, L2, L6, L7, L9 (all layers contribute) | Low. lobsec replaces every known insecure default with a hardened configuration. Residual: new OpenClaw releases may introduce new insecure defaults not yet covered. |
| 12 | Prompt Injection | Attacker-controlled content (channel metadata, message payloads, workspace paths) consumed by the LLM as trusted context. 3 CVEs. | No complete defense | L3 (input validation), L4 (tool deny lists), L8 (output validation), L9 (audit) | High. No known complete mitigation for prompt injection in LLM systems. lobsec applies structural separation of user content from system prompts, tool allowlists, output scanning, and audit logging. A sufficiently sophisticated injection may still manipulate agent behavior within the bounds of allowed tools. |

---

## 3. Assumptions

This threat model depends on the following assumptions. If any assumption is
violated, the security guarantees degrade or fail entirely.

| # | Assumption | Consequence if Violated |
|---|---|---|
| A1 | **Host OS is not compromised.** The Linux kernel, systemd, and base system packages are trusted and unmodified. | Total compromise. lobsec cannot defend against a rootkitted host. All trust zones collapse. |
| A2 | **HSM is physically secure.** The SoftHSM2 token store (or hardware HSM) is accessible only to the lobsec-cli process running as the service user. | Credential extraction. Non-extractable keys (audit signing, CA) remain safe in hardware HSM but are exposed in SoftHSM2. All extractable secrets (API keys, tokens) are compromised. |
| A3 | **Docker daemon is trustworthy.** The container runtime correctly enforces namespace isolation, cgroup limits, seccomp profiles, and capability restrictions. | Sandbox escape. A container breakout grants host-level access, collapsing the semi-trusted zone into the trusted zone. |
| A4 | **Upstream OpenClaw does not intentionally backdoor.** OpenClaw is an open-source project maintained in good faith. Malicious intent from upstream maintainers is not modeled. | Supply chain compromise via trusted update path. lobsec pins to specific versions and disables auto-update, but manual updates could introduce backdoors. |
| A5 | **Network perimeter (nftables + no open ports) is maintained.** The firewall rules are not modified, and no additional services bind to public interfaces. | Boundary 1 collapse. Untrusted traffic reaches the semi-trusted zone without passing through Caddy, enabling direct WebSocket exploitation and SSRF. |
| A6 | **TLS certificate authorities are not compromised.** Public PKI (for external APIs) and the internal CA (for mTLS) issue certificates only to legitimate endpoints. | Man-in-the-middle on transit encryption. Credential injection and LLM responses could be intercepted or modified. |
| A7 | **The operator follows secure practices.** The single human operator does not leak credentials, disable security layers, or grant unauthorized access. | Varies. An operator can intentionally or accidentally weaken any layer. Single-operator model means no separation of duties. |

---

## 4. Out of Scope

The following threats are explicitly excluded from this threat model. They are
acknowledged as real but are not addressable within lobsec's design constraints.

| # | Exclusion | Rationale |
|---|---|---|
| O1 | **Physical attacks beyond disk encryption.** Cold boot attacks, JTAG debugging, hardware implants, electromagnetic side-channel analysis. | LUKS full-disk encryption and fscrypt per-directory encryption address theft-at-rest. Active physical attacks against running hardware require physical security controls outside software scope. |
| O2 | **Nation-state adversaries with zero-day exploits.** Kernel zero-days, Docker runtime zero-days, CPU microarchitectural attacks (Spectre, Meltdown variants). | These bypass all software-layer defenses. Mitigation requires hardware isolation, formal verification, and resources beyond a single-operator deployment. |
| O3 | **Social engineering of the operator.** Phishing, pretexting, coercion, or manipulation of the single human operator who has full system access. | No technical control can prevent a trusted operator from being deceived or coerced. Operational security awareness is assumed (see A7). |
| O4 | **Bugs in the Linux kernel or Docker runtime.** Privilege escalation vulnerabilities in the kernel, container escape via runc/containerd bugs. | These are foundational dependencies. lobsec applies defense-in-depth (seccomp, AppArmor, capability dropping) to reduce the attack surface exposed to containers, but cannot patch kernel bugs. |
| O5 | **Denial of service at the infrastructure level.** Network-layer DDoS, resource exhaustion of the host machine, disk filling. | lobsec applies rate limiting (Caddy) and resource limits (cgroups), but sustained infrastructure-level DoS is an availability problem, not a confidentiality/integrity problem, and is outside the primary threat model scope. |
| O6 | **Compromise of sovereign inference backends.** If a self-hosted LLM backend is compromised, it could return manipulated responses. | lobsec treats sovereign backends as trusted for data privacy (the point of sovereign routing). Backend integrity monitoring is a future consideration. |

---

## 5. Limitations

An honest assessment of known weaknesses in the current deployment.

| # | Limitation | Impact | Mitigation Path |
|---|---|---|---|
| W1 | **SoftHSM2 is software, not hardware.** The HSM token store is a file on disk, protected only by filesystem permissions and fscrypt encryption. A host-level attacker can extract all "non-extractable" keys. | Non-extractable key guarantee (audit signing, CA private key) depends entirely on host integrity (A1). In a hardware HSM, these keys are genuinely non-extractable even with host compromise. | Upgrade to YubiHSM2 or similar hardware HSM for production deployments requiring hardware-grade key protection. The PKCS#11 interface is identical; no code changes needed. |
| W2 | **Prompt injection has no complete defense.** No known technique can fully prevent a sufficiently sophisticated prompt injection from manipulating LLM behavior. lobsec applies structural separation, tool allowlists, and output scanning, but these are heuristic defenses. | An attacker who controls message content (any messaging channel) may be able to manipulate the AI agent into performing unintended actions within the bounds of allowed tools. | Defense-in-depth: restrictive tool allowlists limit blast radius, output scanning catches known patterns, audit logging enables post-incident analysis. Human-in-the-loop for sensitive operations. |
| W3 | **Single-operator model with no RBAC.** One human operator has full access to all system components. There is no role separation, no multi-party authorization, no approval workflows. | A single compromised or malicious operator can disable all security layers. No audit trail is tamper-proof against the operator (who has HSM access). | Acceptable for personal-use deployment. Enterprise deployment would require RBAC, multi-party HSM access, and separation of duties. |
| W4 | **No formal verification.** Security properties are enforced by conventional software (TypeScript, shell scripts, Docker configuration) with unit and integration tests. No formal proofs of correctness exist. | Subtle logic errors in policy enforcement (e.g., allowlist evaluation, egress filtering) could create exploitable gaps not caught by testing. | 706+ tests cover critical paths. Fuzzing and property-based testing could improve coverage. Formal methods are disproportionate for a single-operator personal deployment. |
| W5 | **Log redaction is pattern-based.** Credential leak detection uses regex pattern matching against known secret formats. Novel encodings (base64-wrapped, split across messages, steganographic) may evade detection. | A credential could appear in logs or outbound messages in an unrecognized format. | Multiple layers reduce likelihood: OpenClaw never holds real API keys (proxy-only), egress filtering limits exfiltration channels, audit logs enable retrospective detection. |
| W6 | **Upstream update lag.** lobsec pins to a specific OpenClaw version and disables auto-update. Security patches in newer OpenClaw releases are not applied until the operator manually updates and re-validates. | Known vulnerabilities in the pinned OpenClaw version remain exploitable until manual update. | Operator monitors OpenClaw security advisories. lobsec's wrapper layers (sandbox, proxy, firewall) provide defense-in-depth against most vulnerability classes even when the underlying OpenClaw version is unpatched. |
| W7 | **mTLS not yet enforced on all internal paths.** Certificates have been generated but internal service-to-service communication does not yet require mTLS verification. | Internal traffic between containers is encrypted by Docker network isolation but not cryptographically authenticated. A container-to-container man-in-the-middle is theoretically possible if Docker networking is compromised. | mTLS enforcement is planned. The Docker internal network (no internet route) limits the attack surface in the interim. |

---

## 6. Cross-Reference: Attack Class to Security Layer

Primary defense marked **P**, defense-in-depth marked D.

```
                          L1   L2   L3   L4   L5   L6   L7   L8   L9
                         Net  Prxy Auth  Pol  Egrs Sand Cred Priv Audit
 1. Command Injection     .    .    .    D    .    P    .    .    D
 2. SSRF                  .    .    .    .    P    D    .    D    D
 3. Webhook Auth Bypass   .    .    P    .    .    .    .    .    D
 4. Path Traversal        .    .    .    .    .    P    .    .    D
 5. WebSocket Abuse       P    P    .    P    .    .    .    .    D
 6. Sandbox Bypass        .    .    .    D    .    P    .    .    D
 7. Credential Leakage    .    .    .    .    D    .    P    P    D
 8. XSS                   .    D    .    .    .    .    .    .    D
 9. Network Discovery     P    .    .    D    .    .    .    .    D
10. Supply Chain          .    .    .    .    D    P    .    .    D
11. Insecure Defaults     D    D    .    P    .    D    D    .    D
12. Prompt Injection      .    .    D    D    .    .    .    D    D
```

**Key observation:** L9 (Audit Logger) appears in every row. It is never the
primary defense but always provides post-incident forensic capability. L6
(Execution Sandbox) is the primary defense for the most attack classes (4 of
12). No single layer is a primary defense for more than 4 classes, confirming
that defense-in-depth is structurally necessary.

---

## 7. Revision History

| Date | Version | Change |
|---|---|---|
| 2026-02-27 | 1.0 | Initial threat model based on deployed production state. |
