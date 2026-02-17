# CVE Analysis and Mitigation

> **Version:** 0.1 DRAFT
> **Date:** 2026-02-27
> **Status:** Stub document -- detailed reproduction steps and additional CVEs to be added.

---

## Overview

lobsec's nine security layers were designed by analyzing real CVEs disclosed against AI assistant frameworks, including OpenClaw and comparable systems. This document tracks specific CVE patterns, maps them to lobsec's mitigation layers, and documents residual risk.

The attack-class taxonomy in [`docs/threat-model/attack-class-taxonomy.md`](threat-model/attack-class-taxonomy.md) catalogues 37 vulnerabilities across 12 attack classes. This document selects representative CVE patterns from the three highest-impact categories and traces each through lobsec's defense-in-depth architecture.

---

## CVE Summary Table

The following table presents three illustrative CVE patterns drawn from the most critical attack classes. These represent categories of vulnerability, not necessarily individual CVE identifiers. Where specific CVE IDs are publicly disclosed, they are referenced in the detailed analysis below.

| Category | Vector | CVSS | lobsec Mitigation Layer |
|----------|--------|------|-------------------------|
| CVE-2026-25253: WebSocket RCE | Unauthenticated WebSocket connection to gateway leads to remote code execution | 8.8 | L1 (loopback binding), L2 (Caddy origin validation), L4 (gateway auth) |
| CVE-2026-25157: SSH Command Injection | Malicious input passed to shell execution via tool call | 8.8 | L4 (tool deny list), L6 (sandbox: no shell, RO fs, cap_drop ALL) |
| CVE-2026-24763: Docker Escape | Container breakout via privileged capabilities or volume mounts | 8.1 | L6 (rootless Docker, cap_drop ALL, no-new-privileges, seccomp whitelist, no Docker socket mount) |

---

## Detailed Analysis

### CVE-2026-25253: WebSocket RCE

**Vector**: An attacker establishes an unauthenticated WebSocket connection to the gateway (default `ws://0.0.0.0:18789`), exfiltrates session tokens or injects configuration changes via `config.patch` / `exec.approvals.set`, and chains this into arbitrary command execution on the host. In the worst case, a single malicious link opened in a browser on the same machine achieves full RCE via cross-origin WebSocket hijacking.

**CVSS**: 8.8

**Affected without lobsec**: OpenClaw's gateway binds to all interfaces by default and does not enforce origin validation or mandatory authentication on WebSocket connections. Any process on the local network -- or any browser tab on the same machine -- can connect and issue control-plane commands. The `config.patch` endpoint can disable the sandbox, inject setup commands, or weaken tool policies at runtime.

**lobsec mitigation**:
- **L1 (Network Perimeter)**: Gateway bound to `127.0.0.1` only; nftables default-deny blocks all inbound from non-loopback interfaces.
- **L2 (Reverse Proxy Gate)**: Caddy enforces Origin header validation, rejecting cross-origin WebSocket upgrade requests. TLS 1.3 terminates at Caddy.
- **L4 (Gateway Policy)**: Mandatory gateway auth token required on all WebSocket connections. `config.patch` endpoint blocked via read-only config mount and plugin-level interception. Config drift detection alerts on any runtime changes.
- **L9 (Audit)**: All WebSocket connection attempts and configuration change requests are logged with correlation IDs.

**Residual risk**: A compromised process running on `127.0.0.1` with access to the gateway auth token can still issue WebSocket commands. Mitigated by credential isolation (L7) and sandbox containment (L6), but a full host compromise bypasses all container-level controls.

**Reproduction**: [TODO - add reproduction steps]

---

### CVE-2026-25157: SSH Command Injection

**Vector**: Unsanitized user-controlled input is interpolated into shell command strings passed to `execSync`, `sh -lc`, or equivalent shell execution functions. An attacker crafts a tool call argument (or manipulates a configuration value such as `setupCommand`) containing shell metacharacters, achieving arbitrary command execution on the host with the privileges of the gateway process.

**CVSS**: 8.8

**Affected without lobsec**: OpenClaw's tool execution pipeline passes arguments through shell interpreters without adequate sanitization. The `setupCommand` configuration field runs `sh -lc` with unsanitized input. With sandbox mode disabled (the default), all commands execute directly on the host filesystem with full user privileges.

**lobsec mitigation**:
- **L4 (Gateway Policy)**: Tool deny list blocks dangerous command families (`group:automation`, `group:runtime`). Strict allowlist for permitted tools. `setupCommand` disabled in hardened configuration. `tools.elevated.enabled` set to `false`.
- **L6 (Execution Sandbox)**: All tool execution occurs inside a hardened Docker container with: read-only root filesystem, `cap_drop ALL` (no Linux capabilities), `no-new-privileges` flag, custom seccomp whitelist (minimal syscall surface), no shell available in container image, no network access (air-gapped Docker network).
- **L7 (Credential Broker)**: Even if command injection succeeds inside the sandbox, no real API keys or credentials are accessible -- they reside in HSM or in the proxy process outside the sandbox.
- **L9 (Audit)**: All tool calls logged before execution with full argument capture. Post-execution results scanned for credential patterns.

**Residual risk**: A novel shell injection vector that bypasses the tool deny list and executes within the sandbox container. Impact is limited to the sandbox environment (no network, no credentials, read-only filesystem), but data accessible within the bind-mounted workspace directory could be read or corrupted.

**Reproduction**: [TODO - add reproduction steps]

---

### CVE-2026-24763: Docker Escape

**Vector**: An attacker who has achieved code execution inside a Docker container escalates to the host by exploiting privileged capabilities, writable volume mounts, access to the Docker socket, or kernel vulnerabilities reachable through an overly permissive seccomp profile.

**CVSS**: 8.1

**Affected without lobsec**: OpenClaw's default sandbox configuration uses a standard Docker image (`openclaw-sandbox:bookworm-slim`) without capability restrictions, with the Docker socket potentially mounted for nested container operations, and without a custom seccomp profile. Default Docker configurations grant `CAP_NET_RAW`, `CAP_SYS_CHROOT`, and other capabilities that can be chained into escape vectors.

**lobsec mitigation**:
- **L6 (Execution Sandbox)**:
  - Rootless Docker: the Docker daemon itself runs without root privileges, so even a container escape lands in an unprivileged user namespace.
  - `cap_drop ALL`: zero Linux capabilities granted to the container.
  - `no-new-privileges`: prevents privilege escalation via setuid binaries or capability inheritance.
  - Custom seccomp whitelist: only explicitly permitted syscalls are allowed; all others return `EPERM`. Profile blocks `mount`, `ptrace`, `unshare`, `clone` (with namespace flags), `keyctl`, and other escape-relevant syscalls.
  - No Docker socket mount: the container cannot communicate with the Docker daemon to spawn sibling or child containers.
  - Read-only root filesystem with minimal tmpfs mounts.
  - Hardened container image (`lobsec-sandbox:hardened`, 74.8 MB) with no package manager, no shell, and minimal attack surface.
- **L1 (Network Perimeter)**: Sandbox container is on an air-gapped Docker network (`lobsec-sandbox`) with no route to the host network or the internet.
- **L9 (Audit)**: Container lifecycle events (start, stop, exec) are logged. Anomalous syscall patterns can be detected via seccomp audit mode.

**Residual risk**: Kernel vulnerabilities that bypass seccomp filtering (e.g., via allowed syscalls with unexpected side effects) or rootless Docker namespace escapes. These require kernel-level patches. LUKS/fscrypt encryption limits the value of data accessible after a hypothetical escape to the host filesystem.

**Reproduction**: [TODO - add reproduction steps]

---

## Cross-References

- [docs/THREAT_MODEL.md](THREAT_MODEL.md) -- Comprehensive threat model with attacker profiles, trust boundaries, and risk ratings.
- [docs/SECURITY_LAYERS.md](SECURITY_LAYERS.md) -- Detailed specification of all nine security layers (L1-L9) and their implementation.
- [docs/MITRE_MAPPING.md](MITRE_MAPPING.md) -- Mapping of lobsec controls to MITRE ATT&CK techniques and sub-techniques.
- [docs/threat-model/attack-class-taxonomy.md](threat-model/attack-class-taxonomy.md) -- Full enumeration of 37 vulnerabilities across 12 attack classes.
- [docs/DESIGN.md](DESIGN.md) -- Master design document with architecture overview and security layer cross-reference matrix.

---

## Disclaimer

This document tracks CVE patterns relevant to AI assistant frameworks generally. Specific CVE IDs are referenced where publicly disclosed. lobsec's mitigations are designed to address attack patterns, not specific CVE instances. The illustrative entries in this document represent categories of vulnerability observed across multiple AI assistant frameworks; individual CVE identifiers may correspond to different affected products or versions. Consult upstream security advisories for authoritative CVE details.
