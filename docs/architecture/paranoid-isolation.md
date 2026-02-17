# PARANOID-Level Structural Isolation Architecture

> **Date:** 2026-02-24
> **Status:** DESIGN DRAFT -- not yet implemented
> **Prerequisite:** All prior design artifacts in `docs/architecture/security-layers.md` and `docs/threat-model/`
> **Principle:** A compromised OpenClaw gateway process CANNOT escape containment.

---

## Table of Contents

1. [Part 1: Structural Isolation (Process/Container/Filesystem/Capability)](#part-1-structural-isolation)
2. [Part 2: Total Visibility Proxy](#part-2-total-visibility-proxy)
3. [Part 3: JIT/PAM Credential Architecture with HSM](#part-3-jitpam-credential-architecture-with-hsm)
4. [Part 4: Attack Class Mapping](#part-4-attack-class-mapping)
5. [Appendix A: docker-compose.yml](#appendix-a-docker-composeyml)
6. [Appendix B: nftables Rules](#appendix-b-nftables-rules)
7. [Appendix C: AppArmor Profile](#appendix-c-apparmor-profile)
8. [Appendix D: PKCS#11 Integration Code Sketch](#appendix-d-pkcs11-integration-code-sketch)

---

## Part 1: Structural Isolation

### 1.1 Process Model -- Six Isolation Domains

Six separate containers (or processes), each in its own security domain. No container trusts any other container. Communication is explicit, narrow, and audited.

```
                        INTERNET
                           |
                           X  (no open ports -- SSH/Tailscale only)
                           |
             +-------------+-------------+
             |      HOST (Ubuntu 24.04)  |
             |  nftables default-deny    |
             |  Docker rootless daemon   |
             |                           |
             |  +---------+  +--------+  |
             |  | lobsec  |  | audit  |  |
             |  |  -cli   |  | logger |  |
             |  +----+----+  +---+----+  |
             |       |           |        |
             |  Docker network: lobsec-internal (172.30.0.0/24)
             |       |           |        |
             |  +----+----+  +--+-----+  |
             |  |  caddy   |  | lobsec|  |
             |  |  (L2)    +--+ proxy |  |
             |  +----+----+  | (L5/L8)|  |
             |       |       +---+----+  |
             |  +----+----------------+  |
             |  | openclaw-gateway     |  |
             |  | (ISOLATED)           |  |
             |  +----------+-----------+  |
             |             |              |
             |  Docker network: lobsec-sandbox (172.30.1.0/24, ISOLATED)
             |             |              |
             |  +----------+-----------+  |
             |  | sandbox-exec         |  |
             |  | sandbox-browser      |  |
             |  +---------+------------+  |
             |            |               |
             |       NO INTERNET          |
             |                            |
             |  Docker network: lobsec-ollama (172.30.2.0/24)
             |       (or Jetson via LAN)  |
             |  +-------------------------+
             |  | ollama (Jetson Orin)    |
             |  +-------------------------+
             +----------------------------+
```

### 1.2 Container Inventory

| Container | Image | Network(s) | Purpose | Risk Level |
|-----------|-------|------------|---------|------------|
| **caddy** | `caddy:2-alpine` | `lobsec-internal` | L2 reverse proxy, TLS termination, origin validation, rate limiting | LOW -- no business logic |
| **lobsec-proxy** | `lobsec-proxy:local` | `lobsec-internal`, `lobsec-ollama` | L5 egress firewall + L8 LLM routing proxy. ALL outbound traffic from openclaw passes through here. | MEDIUM -- handles secrets transiently |
| **openclaw-gateway** | `openclaw:local` | `lobsec-internal` (restricted) | Main OpenClaw daemon. The UNTRUSTED component. | HIGH -- this is what we're containing |
| **sandbox-exec** | `openclaw-sandbox:bookworm-slim` | `lobsec-sandbox` (no egress) | Tool execution sandbox (exec, read, write, edit) | HIGH -- runs arbitrary user/LLM-directed commands |
| **sandbox-browser** | `openclaw-sandbox-browser:bookworm-slim` | `lobsec-sandbox` (no egress) | Playwright/Chromium sandbox for browser tool | HIGH -- parses untrusted web content |
| **lobsec-cli** | host process (not containerized) | host | Config generation, credential management, orchestration, audit | TRUSTED -- the only fully trusted component |

### 1.3 Network Isolation -- Three Docker Networks

Three isolated Docker bridge networks. No container connects to more than two networks. The gateway container has NO direct internet access.

**Network: `lobsec-internal`** (172.30.0.0/24)

Purpose: Communication between caddy, openclaw-gateway, and lobsec-proxy.

```
# docker network create
docker network create \
  --driver bridge \
  --subnet 172.30.0.0/24 \
  --gateway 172.30.0.1 \
  --opt com.docker.network.bridge.enable_icc=true \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  --internal \
  lobsec-internal
```

Key: `--internal` flag means NO outbound internet routing. Even if a container is compromised, it cannot reach the internet through this network. `enable_ip_masquerade=false` prevents NAT.

Permitted flows (enforced by container-level nftables in lobsec-proxy):
- `caddy` -> `openclaw-gateway:18789` (WebSocket/HTTP)
- `openclaw-gateway` -> `lobsec-proxy:8080` (all LLM API calls)
- `openclaw-gateway` -> `lobsec-proxy:8081` (all other outbound HTTP)
- `lobsec-proxy` -> external (via host NAT, allowlisted destinations only)

Blocked flows:
- `openclaw-gateway` -> ANY external IP (no route exists; `--internal` network)
- `openclaw-gateway` -> `caddy` (no reason for this direction)
- `sandbox-*` -> anything on this network

**Network: `lobsec-sandbox`** (172.30.1.0/24)

Purpose: Communication between openclaw-gateway and its sandbox containers.

```
docker network create \
  --driver bridge \
  --subnet 172.30.1.0/24 \
  --gateway 172.30.1.1 \
  --opt com.docker.network.bridge.enable_icc=true \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  --internal \
  lobsec-sandbox
```

Permitted flows:
- `openclaw-gateway` -> `sandbox-exec` (command execution)
- `openclaw-gateway` -> `sandbox-browser:9222` (Chrome DevTools Protocol)

Blocked flows:
- `sandbox-exec` -> ANY (no outbound; `network: none` on the container itself)
- `sandbox-browser` -> ANY external (no route; `--internal`)
- `sandbox-*` -> `lobsec-internal` network (physically separate)

**Network: `lobsec-ollama`** (172.30.2.0/24)

Purpose: Communication between lobsec-proxy and Ollama backends.

If Ollama runs on a Jetson Orin on the LAN (not in Docker), this network connects lobsec-proxy to the host network interface that can reach the Jetson. In production, the Jetson is behind Cloudflare Access (per existing config).

Permitted flows:
- `lobsec-proxy` -> Jetson Orin (LAN or WireGuard)
- `lobsec-proxy` -> Remote GPU (WireGuard)
- `lobsec-proxy` -> Cloud LLM APIs (allowlisted IPs/domains)

Blocked flows:
- Everything else. lobsec-proxy has an explicit outbound allowlist.

### 1.4 Filesystem Isolation

Every mount is explicit. No container gets implicit host filesystem access.

**openclaw-gateway container:**

| Mount | Type | Mode | Contents | Rationale |
|-------|------|------|----------|-----------|
| `/home/node/.openclaw/openclaw.json` | bind | **read-only** | Hardened config | Gateway cannot modify its own security config |
| `/home/node/.openclaw/workspace/` | bind | read-write | User workspace | Necessary for file operations; chroot-contained |
| `/run/lobsec/auth-profiles.json` | tmpfs bind | **read-only** | Decrypted API keys | Keys exist only in RAM; RO prevents tampering |
| `/home/node/.openclaw/agents/` | bind | read-write | Agent state, sessions | Required for operation; no secrets here post-hardening |
| `/home/node/.openclaw/logs/` | bind | append-only | Gateway logs | `chattr +a` on host |
| `/tmp` | tmpfs | read-write, noexec, nosuid | Temp files | Isolated, no persistent storage, no execution |

Explicitly NOT mounted:
- Host `/etc`, `/var`, `/root`, `/home` -- no access
- Docker socket -- NEVER (prevents container escape)
- Host credential storage (`/root/.lobsec/vault/`) -- only lobsec-cli reads this
- `/proc/kcore`, `/proc/sched_debug` -- masked

**sandbox-exec container:**

| Mount | Type | Mode | Contents | Rationale |
|-------|------|------|----------|-----------|
| `/home/sandbox/workspace/` | bind | read-write | Scoped subdirectory of workspace | Only the specific workspace subtree, not all of `~/.openclaw/` |
| `/tmp` | tmpfs | read-write, noexec, nosuid, size=256m | Temp files | Size-limited, no execution |

Explicitly NOT mounted:
- `openclaw.json` -- sandbox cannot read gateway config
- `auth-profiles.json` -- sandbox has zero credential access
- Docker socket -- NEVER
- `/home/node/.openclaw/` -- no OpenClaw config visible

**sandbox-browser container:**

Same as sandbox-exec, plus:
| Mount | Type | Mode | Contents | Rationale |
|-------|------|------|----------|-----------|
| `/home/sandbox/.cache/` | tmpfs | read-write, noexec, size=512m | Chromium cache | Ephemeral, gone on container restart |

**lobsec-proxy container:**

| Mount | Type | Mode | Contents | Rationale |
|-------|------|------|----------|-----------|
| `/run/lobsec/proxy-config.json` | bind | **read-only** | Routing config, allowlists | Cannot modify its own policy |
| `/run/lobsec/tls/` | bind | **read-only** | TLS certs for upstream mTLS | If needed for Ollama/Remote GPU |
| `/var/log/lobsec/` | bind | append-only | Proxy audit logs | `chattr +a` |

Explicitly NOT mounted:
- HSM/PKCS#11 socket -- only lobsec-cli process accesses this
- API keys -- injected as env vars, not files

**caddy container:**

| Mount | Type | Mode | Contents | Rationale |
|-------|------|------|----------|-----------|
| `/etc/caddy/Caddyfile` | bind | **read-only** | Reverse proxy config | Cannot modify its own config |
| `/data/caddy/` | volume | read-write | TLS cert storage (ACME) | Caddy manages its own certs |
| `/var/log/caddy/` | bind | append-only | Access logs | `chattr +a` |

### 1.5 Capability Dropping

Every container drops ALL Linux capabilities and adds back only what is strictly needed.

```yaml
# Base security context for ALL containers
security_opt:
  - no-new-privileges:true
  - seccomp:lobsec-seccomp.json
  - apparmor:lobsec-openclaw
cap_drop:
  - ALL
```

Per-container capability additions:

| Container | Added Capabilities | Justification |
|-----------|-------------------|---------------|
| **caddy** | `NET_BIND_SERVICE` | Bind to ports 80/443 (only if not using >1024) |
| **openclaw-gateway** | NONE | No capabilities needed. Runs as uid 1000, binds to >1024 |
| **sandbox-exec** | NONE | Absolutely no capabilities |
| **sandbox-browser** | `SYS_ADMIN` (Chromium namespaces) | Required by Chromium. Mitigated by seccomp + AppArmor. Alternative: `--no-sandbox` Chromium flag with extra seccomp restrictions |
| **lobsec-proxy** | NONE | Binds to >1024, no privileged ops |

### 1.6 Seccomp Profile

Custom seccomp profile that starts from Docker's default and removes additional dangerous syscalls.

File: `/root/lobsec/config/lobsec-seccomp.json`

Key restrictions beyond Docker default:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "comment": "lobsec paranoid seccomp -- allowlist model",
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "access", "arch_prctl", "bind", "brk",
        "clock_getres", "clock_gettime", "clone", "clone3", "close",
        "connect", "dup", "dup2", "dup3", "epoll_create", "epoll_create1",
        "epoll_ctl", "epoll_wait", "epoll_pwait", "eventfd", "eventfd2",
        "execve", "execveat", "exit", "exit_group", "faccessat", "faccessat2",
        "fadvise64", "fallocate", "fchmod", "fchmodat", "fchown", "fchownat",
        "fcntl", "fdatasync", "flock", "fstat", "fstatfs", "fsync",
        "ftruncate", "futex", "getcwd", "getdents64", "getegid", "geteuid",
        "getgid", "getgroups", "getpeername", "getpgid", "getpid", "getppid",
        "getpriority", "getrandom", "getrlimit", "getrusage", "getsockname",
        "getsockopt", "gettid", "gettimeofday", "getuid",
        "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch",
        "ioctl", "kill", "lchown", "lgetxattr", "link", "linkat",
        "listen", "lseek", "lstat", "madvise", "membarrier", "memfd_create",
        "mincore", "mkdir", "mkdirat", "mlock", "mlock2", "mmap",
        "mprotect", "mremap", "munlock", "munmap", "nanosleep",
        "newfstatat", "open", "openat", "openat2", "pipe", "pipe2",
        "poll", "ppoll", "prctl", "pread64", "preadv", "preadv2",
        "prlimit64", "pwrite64", "pwritev", "pwritev2",
        "read", "readahead", "readlink", "readlinkat", "readv",
        "recvfrom", "recvmmsg", "recvmsg", "rename", "renameat", "renameat2",
        "restart_syscall", "rmdir", "rseq",
        "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigreturn",
        "rt_sigtimedwait", "rt_tgsigqueueinfo",
        "sched_getaffinity", "sched_yield", "select",
        "sendfile", "sendmmsg", "sendmsg", "sendto",
        "set_robust_list", "set_tid_address", "setpgid", "setsockopt",
        "shutdown", "sigaltstack", "socket", "socketpair",
        "splice", "stat", "statfs", "statx", "symlink", "symlinkat",
        "sysinfo", "tgkill", "timerfd_create", "timerfd_gettime", "timerfd_settime",
        "tkill", "truncate", "umask", "uname", "unlink", "unlinkat",
        "utimensat", "wait4", "waitid", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "comment": "block: ptrace (debugging/injection), process_vm_readv/writev (cross-process memory)",
      "names": ["ptrace", "process_vm_readv", "process_vm_writev"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: kernel module loading",
      "names": ["init_module", "finit_module", "delete_module"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: mount/unmount (filesystem escape)",
      "names": ["mount", "umount2", "pivot_root"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: keyctl (kernel keyring manipulation)",
      "names": ["keyctl", "add_key", "request_key"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: userfaultfd (used in container escapes)",
      "names": ["userfaultfd"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: bpf (eBPF programs -- used in privilege escalation)",
      "names": ["bpf"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: perf_event_open (side-channel attacks)",
      "names": ["perf_event_open"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: kexec (replace running kernel)",
      "names": ["kexec_load", "kexec_file_load"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "comment": "block: reboot",
      "names": ["reboot"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

### 1.7 AppArmor Profile

File: `/root/lobsec/config/lobsec-openclaw-apparmor`

```
#include <tunables/global>

profile lobsec-openclaw flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Node.js runtime
  /usr/local/bin/node ix,
  /app/** r,
  /app/node_modules/** r,
  /app/dist/** r,

  # OpenClaw config (read-only)
  /home/node/.openclaw/openclaw.json r,
  /home/node/.openclaw/agents/** rw,
  /home/node/.openclaw/workspace/** rw,
  /home/node/.openclaw/logs/** w,
  /home/node/.openclaw/canvas/** rw,
  /home/node/.openclaw/cron/** rw,

  # Credential file on tmpfs (read-only)
  /run/lobsec/auth-profiles.json r,

  # Temp
  /tmp/** rw,

  # Network (controlled at Docker/nftables level, but defense-in-depth)
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Deny everything else
  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /root/** rwx,
  deny /home/node/.openclaw/openclaw.json w,
  deny /run/lobsec/** w,
  deny /proc/*/mem rw,
  deny /proc/kcore r,
  deny /sys/firmware/** r,
  deny /var/run/docker.sock rw,

  # No raw network (prevents packet crafting for SSRF bypass)
  deny network raw,
  deny network packet,

  # No ptrace
  deny ptrace,

  # No mount
  deny mount,
  deny umount,
  deny pivot_root,
}
```

### 1.8 User Namespacing

Docker rootless mode provides automatic user namespace remapping. Inside the container, processes run as `node` (uid 1000). On the host, this maps to a high unprivileged UID via `/etc/subuid` and `/etc/subgid`.

```
# /etc/subuid (example -- actual values set by rootless Docker setup)
lobsec:100000:65536

# /etc/subgid
lobsec:100000:65536
```

Container uid 0 (root) maps to host uid 100000 (unprivileged). Container uid 1000 (node) maps to host uid 101000. Even a full container escape lands in an unprivileged context on the host.

The `lobsec-cli` process runs as the actual host user (or a dedicated `lobsec` system user). It is the ONLY process that can:
- Access the HSM/SoftHSM2 PKCS#11 socket
- Write to `openclaw.json`
- Read the encrypted credential vault
- Manage Docker containers
- Modify nftables rules

### 1.9 Read-Only Root Filesystem

Every container runs with `read_only: true` on the root filesystem. Writable locations are explicitly mounted tmpfs volumes.

```yaml
# Applied to all containers
read_only: true
tmpfs:
  - /tmp:rw,noexec,nosuid,size=256m
  - /run:rw,noexec,nosuid,size=64m
```

This prevents an attacker who compromises OpenClaw from:
- Installing backdoor binaries
- Modifying Node.js source
- Writing cron jobs or startup scripts inside the container
- Persisting across container restarts

---

## Part 2: Total Visibility Proxy

### 2.1 Design Principle: Transparent Interposition

OpenClaw THINKS it has normal network, file, and execution access. In reality, every interaction passes through a lobsec-controlled choke point. This is achieved through four mechanisms:

1. **Network-level: no direct internet** -- The `lobsec-internal` Docker network is `--internal`. OpenClaw cannot reach the internet. Period.
2. **Proxy-level: all egress through lobsec-proxy** -- OpenClaw's LLM `baseUrl` points to lobsec-proxy. All other HTTP egress is transparently proxied.
3. **Config-level: OpenClaw's own security settings** -- `tools.deny`, sandbox mode, SSRF policy, etc.
4. **Plugin-level: lobsec-plugin hooks** -- Every tool call, message, LLM request, and LLM response passes through plugin hooks.

### 2.2 LLM Traffic Proxying

All LLM API calls from OpenClaw route through lobsec-proxy. OpenClaw never contacts Anthropic, OpenAI, or Ollama directly.

**Mechanism:** OpenClaw's `baseUrl` per-provider config points to lobsec-proxy.

```json5
// In openclaw.json (generated by lobsec-cli)
{
  "agents": {
    "defaults": {
      "model": "anthropic/claude-sonnet-4-5-20250929"
    }
  }
}
```

```json5
// In auth-profiles.json (generated to tmpfs by lobsec-cli)
{
  "version": 1,
  "profiles": {
    "anthropic:lobsec-proxy": {
      "type": "api_key",
      "provider": "anthropic",
      "key": "${LOBSEC_PROXY_TOKEN}",
      "baseUrl": "http://lobsec-proxy:8080/v1/anthropic"
    },
    "openai:lobsec-proxy": {
      "type": "api_key",
      "provider": "openai",
      "key": "${LOBSEC_PROXY_TOKEN}",
      "baseUrl": "http://lobsec-proxy:8080/v1/openai"
    }
  }
}
```

The `LOBSEC_PROXY_TOKEN` is an internal authentication token that lobsec-proxy validates. It is NOT the real API key. The real API keys live only inside lobsec-proxy's memory, injected at startup from the HSM/encrypted vault.

**lobsec-proxy flow:**

```
OpenClaw gateway
    |
    | HTTP POST to http://lobsec-proxy:8080/v1/anthropic/messages
    | Header: Authorization: Bearer <LOBSEC_PROXY_TOKEN>
    |
lobsec-proxy
    |
    +-- 1. Validate LOBSEC_PROXY_TOKEN
    +-- 2. Log request (L9): model, token count estimate, session ID
    +-- 3. Check session mode (sovereign vs public)
    +-- 4. If sovereign: route to Jetson/Remote GPU Ollama
    |      If public: route to cloud API
    +-- 5. Inject REAL API key from in-memory credential store
    +-- 6. Forward request to upstream
    +-- 7. Stream response back
    +-- 8. Log response metadata (L9): token counts, latency
    +-- 9. (Future) Output validation: scan for leaked credentials/PII
    |
    v
  Cloud API / Ollama
```

### 2.3 General Egress Proxying

For non-LLM outbound HTTP (webhook delivery, image fetching, web search, etc.), OpenClaw is configured to use lobsec-proxy as an HTTP proxy via `HTTP_PROXY` / `HTTPS_PROXY` environment variables.

```yaml
# In openclaw-gateway container env
environment:
  HTTP_PROXY: "http://lobsec-proxy:8081"
  HTTPS_PROXY: "http://lobsec-proxy:8081"
  NO_PROXY: "localhost,127.0.0.1,lobsec-proxy"
```

lobsec-proxy on port 8081 operates as a forward proxy with an explicit allowlist:

```typescript
// lobsec-proxy egress allowlist (conceptual -- real implementation in TypeScript)
const EGRESS_ALLOWLIST: EgressRule[] = [
  // Messaging platforms (webhook delivery)
  { host: "api.telegram.org", ports: [443] },
  { host: "slack.com", ports: [443] },
  { host: "discord.com", ports: [443] },
  { host: "graph.microsoft.com", ports: [443] },

  // LLM APIs (but these go through port 8080, not 8081)
  // Listed here as defense-in-depth
  { host: "api.anthropic.com", ports: [443] },
  { host: "api.openai.com", ports: [443] },

  // Web search (if enabled)
  { host: "*.googleapis.com", ports: [443] },

  // Package registries (for skill installation, if enabled)
  { host: "registry.npmjs.org", ports: [443] },
];

// DENY all of these regardless of allowlist
const EGRESS_DENYLIST: string[] = [
  // RFC 1918 private ranges
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  // Loopback
  "127.0.0.0/8",
  // Link-local
  "169.254.0.0/16",
  // Cloud metadata endpoints
  "169.254.169.254/32",
  // IPv4-mapped IPv6 (CVE bypass vector -- vuln #13)
  "::ffff:0.0.0.0/96",
  // IPv6 link-local
  "fe80::/10",
  // IPv6 unique local
  "fc00::/7",
  // AWS/GCP/Azure metadata via IPv6
  "fd00:ec2::254/128",
];
```

**Enforcement is at TWO levels:**

1. **Network level (nftables on host):** The `lobsec-internal` Docker network is `--internal`, so openclaw-gateway has no default route to the internet. Even if `HTTP_PROXY` is bypassed, there is no route.

2. **Proxy level (lobsec-proxy):** All CONNECT requests validated against allowlist. Denylist checked first, always wins.

### 2.4 Inbound Webhook Proxying

All inbound webhooks arrive via Caddy (L2), which performs:

1. **TLS termination** (if using external domain)
2. **Rate limiting** (per source IP)
3. **Request size cap** (10 MB body, addresses DoS vuln #29)
4. **Origin/Host header validation**

Then Caddy forwards to lobsec-proxy (or a dedicated webhook validation sidecar), which performs:

5. **Webhook signature verification** (L3) per channel:
   - Telegram: validates `X-Telegram-Bot-Api-Secret-Token` header
   - Slack: validates `X-Slack-Signature` HMAC-SHA256
   - Twilio: validates `X-Twilio-Signature` HMAC-SHA1
   - Discord: validates Ed25519 signature
6. **Replay protection** (reject timestamps older than 5 minutes)
7. **Structured logging** of webhook event metadata

Only after validation does the request reach openclaw-gateway.

```
Caddy Caddyfile snippet:

:443 {
    # TLS with auto HTTPS
    tls /etc/caddy/tls/cert.pem /etc/caddy/tls/key.pem

    # Rate limiting
    rate_limit {remote.ip} 60r/m

    # Request size limit (10 MB)
    request_body {
        max_size 10MB
    }

    # Security headers
    header {
        Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }

    # WebSocket: validate Origin header (CVE-2026-25253 primary mitigation)
    @ws_upgrade {
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @ws_upgrade {
        @bad_origin {
            not header Origin "https://expected-host.example.com"
            not header Origin ""
        }
        respond @bad_origin 403

        reverse_proxy openclaw-gateway:18789
    }

    # Webhook routes: forward to validation layer
    handle /webhook/* {
        reverse_proxy lobsec-proxy:8082
    }

    # Default: forward to gateway
    handle {
        reverse_proxy openclaw-gateway:18789
    }
}
```

### 2.5 File I/O Auditing

Four layers of file I/O control:

**Layer A: Container filesystem isolation** (Section 1.4)
- Read-only root filesystem
- Explicit bind mounts only
- Workspace is the ONLY writable persistent location for gateway

**Layer B: AppArmor profile** (Section 1.7)
- Denies access to paths outside explicit allowlist
- Even if an attacker finds a writable area, AppArmor blocks writing outside workspace

**Layer C: lobsec-plugin `before_tool_call` hook**
- Intercepts every `read`, `write`, `edit`, `exec` tool call
- Validates paths: `realpath()` canonicalization, reject if outside workspace root
- Blocks symlinks that resolve outside workspace
- Logs every file operation with full path, operation type, calling agent

```typescript
// lobsec-plugin: before_tool_call file validation (conceptual)
async function validateFileAccess(
  event: PluginHookBeforeToolCallEvent
): Promise<PluginHookBeforeToolCallResult> {
  const tool = event.toolName;
  if (!["read", "write", "edit", "exec"].includes(tool)) {
    return { action: "continue" };
  }

  const targetPath = event.params?.path || event.params?.file_path;
  if (!targetPath) return { action: "continue" };

  // Canonicalize path (resolve symlinks, .., etc)
  const resolved = await realpath(targetPath).catch(() => null);
  if (!resolved) {
    auditLog("deny", "file_access", { tool, path: targetPath, reason: "unresolvable" });
    return { action: "deny", reason: "Path does not resolve" };
  }

  const workspaceRoot = "/home/node/.openclaw/workspace";
  if (!resolved.startsWith(workspaceRoot + "/") && resolved !== workspaceRoot) {
    auditLog("deny", "file_access", { tool, path: targetPath, resolved, reason: "outside_workspace" });
    return { action: "deny", reason: "Access denied: outside workspace" };
  }

  auditLog("allow", "file_access", { tool, path: targetPath, resolved });
  return { action: "continue" };
}
```

**Layer D: inotify/fanotify monitoring (defense-in-depth)**
- Host-level `fanotify` watcher on the workspace bind mount
- Logs all filesystem events to the audit log
- Does not block (that is layers A-C's job) but provides forensic visibility

### 2.6 Tool Execution Logging

Every tool execution passes through the lobsec-plugin's hook chain:

```
Tool call arrives
    |
    v
[before_tool_call] -- lobsec-plugin validates, logs, may deny
    |
    v
OpenClaw executes tool (inside sandbox container)
    |
    v
[after_tool_call] -- lobsec-plugin logs result metadata
    |
    v
[tool_result_persist] -- lobsec-plugin redacts secrets from persisted result
    |
    v
Result returned to agent
```

Audit log entry for every tool call:

```json
{
  "ts": "2026-02-24T16:00:00.000Z",
  "layer": "L4",
  "event": "tool_call",
  "action": "allow",
  "tool": "exec",
  "params": {
    "command": "ls -la /home/sandbox/workspace/",
    "path_validated": true,
    "sandbox": "sandbox-exec-a1b2c3"
  },
  "agent_id": "main",
  "session_id": "sess_abc123",
  "trace_id": "tr_def456",
  "duration_ms": 142,
  "attack_classes": [1, 6],
  "prev_hash": "sha256:abc..."
}
```

---

## Part 3: JIT/PAM Credential Architecture with HSM

### 3.1 Architecture Overview

The user is correct that HSM-backed credential storage is the right approach. The previous ADR-2 (LUKS/SOPS/Age baseline, HSM optional) is superseded for this paranoid-level design.

**Tiered HSM strategy:**

| Environment | HSM Backend | PKCS#11 Module | Key Properties |
|-------------|-------------|----------------|----------------|
| **Development/CI** | SoftHSM2 | `libsofthsm2.so` | Software-only, same API surface, keys extractable (test only) |
| **Production** | YubiHSM2 | `libyubihsm_pkcs11.so` | Hardware-backed, keys non-extractable, tamper-evident |
| **Jetson Orin** | SoftHSM2 initially; TPM2-PKCS#11 when verified | `libsofthsm2.so` or `libtpm2_pkcs11.so` | `[NEEDS VERIFICATION]` TPM2 PKCS#11 on Jetson |

The PKCS#11 abstraction means lobsec-cli code is IDENTICAL regardless of backend. Only the module path and slot configuration change.

### 3.2 PKCS#11 Abstraction Layer

lobsec-cli talks exclusively through the PKCS#11 C_* API. The backend is configured via environment:

```bash
# Development (SoftHSM2)
export LOBSEC_PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export LOBSEC_PKCS11_SLOT=0
export LOBSEC_PKCS11_PIN_FILE="/run/lobsec/hsm-pin"  # or prompt

# Production (YubiHSM2)
export LOBSEC_PKCS11_MODULE="/usr/lib/x86_64-linux-gnu/libyubihsm_pkcs11.so"
export LOBSEC_PKCS11_SLOT=0
export LOBSEC_PKCS11_PIN_FILE="/run/lobsec/hsm-pin"  # connector URL in yubihsm_pkcs11.conf
```

Node.js integration via `graphene-pk11` (PKCS#11 binding for Node.js, real package on npm):

```typescript
// lobsec-cli/src/hsm/pkcs11-client.ts (conceptual -- verified graphene-pk11 exists)
import * as graphene from "graphene-pk11";

export class HsmClient {
  private module: graphene.Module;
  private session: graphene.Session;

  constructor(modulePath: string) {
    this.module = graphene.Module.load(modulePath);
    this.module.initialize();
  }

  openSession(slotIndex: number, pin: string): void {
    const slot = this.module.getSlots(slotIndex);
    this.session = slot.open(
      graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
    );
    this.session.login(graphene.UserType.USER, pin);
  }

  // Store a secret (API key) as a PKCS#11 secret key object
  storeSecret(label: string, value: Buffer): graphene.Key {
    return this.session.create({
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.GENERIC_SECRET,
      label: label,
      value: value,
      token: true,        // Persistent in HSM
      private: true,       // Requires login to access
      sensitive: true,     // Cannot be extracted in plaintext (YubiHSM2 enforces; SoftHSM2 honors)
      extractable: false,  // Non-extractable (YubiHSM2 enforces hardware)
    });
  }

  // Retrieve a secret -- for API keys that MUST be sent as HTTP headers
  // On YubiHSM2 with extractable=false, this will FAIL.
  // For API keys, we use extractable=true but sensitive=true (wrap-only extract).
  // See Section 3.5 for the API key exposure minimization strategy.
  retrieveSecret(label: string): Buffer {
    const obj = this.session.find({
      class: graphene.ObjectClass.SECRET_KEY,
      label: label,
    });
    if (!obj) throw new Error(`Secret not found: ${label}`);
    return obj.getAttribute({ value: true }).value as Buffer;
  }

  // Sign data using HSM-resident private key (key NEVER leaves HSM)
  sign(keyLabel: string, data: Buffer): Buffer {
    const key = this.session.find({
      class: graphene.ObjectClass.PRIVATE_KEY,
      label: keyLabel,
    });
    const sign = this.session.createSign(
      graphene.MechanismEnum.SHA256_RSA_PKCS,
      key
    );
    sign.update(data);
    return sign.final();
  }

  // Generate signing keypair inside HSM
  generateSigningKeypair(label: string): { publicKey: graphene.Key; privateKey: graphene.Key } {
    return this.session.generateKeyPair(
      graphene.MechanismEnum.RSA_PKCS_KEY_PAIR_GEN,
      {
        label: `${label}-pub`,
        modulusBits: 2048,
        publicExponent: Buffer.from([1, 0, 1]),
        token: true,
      },
      {
        label: `${label}-priv`,
        token: true,
        private: true,
        sensitive: true,
        extractable: false,  // Private key NEVER leaves HSM
        sign: true,
      }
    );
  }

  close(): void {
    if (this.session) this.session.logout();
    if (this.session) this.session.close();
    if (this.module) this.module.finalize();
  }
}
```

### 3.3 JIT Credential Flow

```
+------------+     +----------+     +---------+     +------------------+
| lobsec-cli | --> |  PKCS#11 | --> |  HSM    | --> | Credential Store |
|            |     |   API    |     | Backend |     | (token/slot)     |
+------+-----+     +----------+     +---------+     +------------------+
       |
       | 1. Startup: retrieve secrets from HSM
       | 2. Write auth-profiles.json to tmpfs
       | 3. Export env vars
       | 4. Start openclaw-gateway container with env + tmpfs mount
       v
+------------------+     +---------------+
| openclaw-gateway | --> | lobsec-proxy  |
| (reads env vars  |     | (holds real   |
|  and tmpfs auth) |     |  API keys in  |
+------------------+     |  memory only) |
                         +---------------+
                               |
                               | 5. Injects real API key per-request
                               | 6. Forwards to upstream
                               | 7. Clears key from request context
                               v
                         +-----------+
                         | Cloud API |
                         +-----------+
```

**Detailed startup sequence:**

```bash
#!/bin/bash
# lobsec-cli startup (conceptual)

set -euo pipefail

# Step 1: Authenticate to HSM
PKCS11_PIN=$(cat /run/lobsec/hsm-pin)  # Or prompt user

# Step 2: Retrieve credentials from HSM, write to tmpfs
lobsec-cli credential export \
  --format auth-profiles \
  --output /run/lobsec/auth-profiles.json \
  --pkcs11-module "$LOBSEC_PKCS11_MODULE" \
  --slot "$LOBSEC_PKCS11_SLOT" \
  --pin-file /run/lobsec/hsm-pin

# Step 3: Set restrictive permissions on tmpfs
chmod 0400 /run/lobsec/auth-profiles.json
# Ownership: the UID that maps to 'node' inside the container

# Step 4: Retrieve proxy-specific secrets
ANTHROPIC_KEY=$(lobsec-cli credential get --label anthropic-api-key)
OPENAI_KEY=$(lobsec-cli credential get --label openai-api-key)
GATEWAY_TOKEN=$(lobsec-cli credential get --label gateway-auth-token)
PROXY_INTERNAL_TOKEN=$(lobsec-cli credential get --label proxy-internal-token)

# Step 5: Start lobsec-proxy with real API keys (in memory only)
docker run -d \
  --name lobsec-proxy \
  --network lobsec-internal \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/root/lobsec/config/lobsec-seccomp.json \
  -e "ANTHROPIC_API_KEY=$ANTHROPIC_KEY" \
  -e "OPENAI_API_KEY=$OPENAI_KEY" \
  -e "PROXY_INTERNAL_TOKEN=$PROXY_INTERNAL_TOKEN" \
  -v /root/lobsec/config/proxy-config.json:/config/proxy-config.json:ro \
  -v /var/log/lobsec/:/var/log/lobsec/:rw \
  lobsec-proxy:local

# Step 6: Clear keys from shell environment immediately
unset ANTHROPIC_KEY OPENAI_KEY

# Step 7: Start OpenClaw gateway (NO real API keys -- only internal proxy token)
docker run -d \
  --name openclaw-gateway \
  --network lobsec-internal \
  --network lobsec-sandbox \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/root/lobsec/config/lobsec-seccomp.json \
  --security-opt apparmor=lobsec-openclaw \
  -v /root/.openclaw/openclaw.json:/home/node/.openclaw/openclaw.json:ro \
  -v /root/.openclaw/workspace/:/home/node/.openclaw/workspace/:rw \
  -v /root/.openclaw/agents/:/home/node/.openclaw/agents/:rw \
  -v /root/.openclaw/logs/:/home/node/.openclaw/logs/:rw \
  -v /run/lobsec/auth-profiles.json:/home/node/.openclaw/agents/main/agent/auth-profiles.json:ro \
  -e "OPENCLAW_GATEWAY_TOKEN=$GATEWAY_TOKEN" \
  -e "HTTP_PROXY=http://lobsec-proxy:8081" \
  -e "HTTPS_PROXY=http://lobsec-proxy:8081" \
  -e "NO_PROXY=localhost,127.0.0.1,lobsec-proxy" \
  openclaw:local \
  node dist/index.js gateway --bind loopback --port 18789

# Step 8: Clear remaining secrets from shell
unset GATEWAY_TOKEN PROXY_INTERNAL_TOKEN

# Step 9: Start Caddy
docker run -d \
  --name caddy \
  --network lobsec-internal \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  -v /root/lobsec/config/Caddyfile:/etc/caddy/Caddyfile:ro \
  -v caddy-data:/data/caddy:rw \
  -v /var/log/caddy/:/var/log/caddy/:rw \
  -p 127.0.0.1:443:443 \
  caddy:2-alpine

# Gateway token also cleared
unset GATEWAY_TOKEN
```

### 3.4 API Key Exposure Window Minimization

The practical problem: LLM API keys (e.g., `sk-ant-...`) must be sent as HTTP `Authorization` headers. The key MUST exist in process memory at some point. How do we minimize exposure?

**Strategy: Key exists in exactly ONE process (lobsec-proxy), for the minimum time.**

```
Timeline of API key exposure:

t=0  lobsec-cli retrieves key from HSM
     Key in lobsec-cli process memory: ~50ms

t=1  lobsec-cli passes key to lobsec-proxy via Docker env
     Key in Docker daemon memory: unavoidable, minimal
     Key in lobsec-proxy process memory: lifetime of proxy process

t=2  lobsec-cli unsets key from its own env
     Key NO LONGER in lobsec-cli

t=3  API request arrives from OpenClaw
     lobsec-proxy reads key from its in-memory map
     Key injected into outbound HTTP header
     Key in TLS write buffer: ~1ms
     Request sent, buffer freed

t=4  OpenClaw gateway process: NEVER has the real API key
     It only has LOBSEC_PROXY_TOKEN (internal auth)
```

**Key never exists in:**
- Filesystem (except tmpfs for auth-profiles.json, which contains proxy URLs, not real keys)
- OpenClaw's process memory (it has the internal proxy token, not real API keys)
- Sandbox containers (no credential access at all)
- Log files (lobsec-proxy redacts Authorization headers before logging)
- Shell history (lobsec-cli clears env vars immediately)

**Key exists in:**
- HSM (encrypted, non-extractable on YubiHSM2)
- lobsec-proxy process memory (one copy, lifetime of process)
- Kernel TLS buffer (milliseconds per request)

**Future hardening (not v1):**
- lobsec-proxy could use `mlock()` to pin the key page and `madvise(MADV_DONTDUMP)` to exclude from core dumps
- lobsec-proxy could use a dedicated `memfd_secret()` (Linux 5.14+) for key storage if kernel supports it
- After each request, overwrite the in-memory key buffer before GC (requires native module; V8 does not guarantee immediate zeroing)

### 3.5 Credential Storage Classes

Not all credentials are equal. Different storage strategies for different credential types:

| Credential Type | HSM Storage | Extractable? | Injection Method | Example |
|----------------|-------------|-------------|-----------------|---------|
| **LLM API keys** | `SECRET_KEY`, `sensitive=true` | Yes (must be sent as HTTP header) | lobsec-proxy env var at startup | `sk-ant-...`, `sk-...` |
| **Webhook signing secrets** | `SECRET_KEY`, `sensitive=true` | No -- HSM performs HMAC | lobsec-proxy calls HSM for verification | Telegram secret, Slack signing secret |
| **Audit log signing key** | `PRIVATE_KEY`, `extractable=false` | NEVER | HSM performs RSA/EC signing | lobsec log integrity key |
| **Gateway auth token** | `SECRET_KEY`, `sensitive=true` | Yes (injected as env var) | Container env var at startup | `OPENCLAW_GATEWAY_TOKEN` |
| **TLS private keys** | `PRIVATE_KEY`, `extractable=false` | NEVER | Caddy uses PKCS#11 engine | Caddy TLS cert key |

For webhook secrets where the HSM can perform the HMAC directly (key never leaves HSM):

```typescript
// Webhook verification using HSM-resident key
async function verifyWebhookSignature(
  hsm: HsmClient,
  secretLabel: string,
  payload: Buffer,
  receivedSignature: string,
  mechanism: "hmac-sha256" | "hmac-sha1"
): Promise<boolean> {
  // HSM computes HMAC internally -- secret key never leaves HSM
  const mechs = {
    "hmac-sha256": graphene.MechanismEnum.SHA256_HMAC,
    "hmac-sha1": graphene.MechanismEnum.SHA_1_HMAC,
  };

  const key = hsm.session.find({
    class: graphene.ObjectClass.SECRET_KEY,
    label: secretLabel,
  });

  const sign = hsm.session.createSign(mechs[mechanism], key);
  sign.update(payload);
  const computed = sign.final();

  return timingSafeEqual(
    computed,
    Buffer.from(receivedSignature, "hex")
  );
}
```

### 3.6 Credential Lifecycle

```
 1. PROVISIONING                 2. STORAGE                    3. RETRIEVAL
 +-----------------+             +-----------+                 +----------------+
 | lobsec-cli      |   PKCS#11  |   HSM     |   PKCS#11      | lobsec-cli     |
 | credential add  | ---------> | C_Create  | <-------------- | credential get |
 | --label foo     |            | Object    |                 | --label foo    |
 | --value <stdin> |            |           |                 +-------+--------+
 +-----------------+             +-----------+                         |
                                                                      | env var / tmpfs
 4. INJECTION                    5. USE                        +------v---------+
 +------------------+            +---------------+             | lobsec-proxy   |
 | Docker env or    | ---------> | HTTP header   | ---------> | or gateway     |
 | tmpfs mount      |            | (transient)   |            | container      |
 +------------------+            +---------------+             +----------------+

 6. ROTATION                     7. REVOCATION
 +------------------+            +------------------+
 | lobsec-cli       |            | lobsec-cli       |
 | credential       |            | credential       |
 | rotate           |            | revoke           |
 | --label foo      |            | --label foo      |
 |                  |            |                  |
 | 1. Generate new  |            | 1. HSM: destroy  |
 | 2. Update HSM    |            |    key object    |
 | 3. Restart proxy |            | 2. Restart proxy |
 | 4. Delete old    |            | 3. Rotate at     |
 |    from HSM      |            |    provider      |
 +------------------+            +------------------+
```

**Rotation automation:**

```bash
# lobsec-cli credential rotate --label anthropic-api-key
#
# 1. lobsec-cli generates new API key via Anthropic API (if supported)
#    OR prompts user to enter new key
# 2. New key stored in HSM with label "anthropic-api-key-v2"
# 3. lobsec-proxy gracefully restarted with new key
# 4. Old key "anthropic-api-key-v1" destroyed in HSM
# 5. Audit log: credential rotation event
```

**Revocation on compromise detection:**

If L9 audit log detects anomalous API usage, credential leakage patterns, or sandbox escape attempts:

1. lobsec-cli receives alert
2. Immediately destroys all API keys in HSM (`C_DestroyObject`)
3. Stops lobsec-proxy (keys gone from memory)
4. Stops openclaw-gateway
5. Logs revocation event with HSM-signed timestamp
6. Alerts operator

### 3.7 HSM-Signed Audit Trail

Every credential access is logged with an HSM-signed timestamp. Even if an attacker compromises the host, they cannot forge audit log entries retroactively (the signing key never leaves the HSM).

```typescript
// Audit entry for credential access
interface CredentialAuditEntry {
  ts: string;              // ISO 8601
  event: "retrieve" | "store" | "rotate" | "revoke" | "inject";
  label: string;           // Credential label (NOT value)
  target: string;          // "lobsec-proxy" | "openclaw-gateway" | "auth-profiles.json"
  requestor: string;       // "lobsec-cli" (always -- only trusted component)
  prev_hash: string;       // SHA-256 of previous entry (hash chain)
  hsm_signature: string;   // RSA/EC signature from HSM-resident signing key
}
```

The `hsm_signature` is computed by the HSM:

```typescript
const entryBytes = Buffer.from(JSON.stringify(entry));
const sha256 = crypto.createHash("sha256").update(entryBytes).digest();
entry.hsm_signature = hsm.sign("audit-signing-key", sha256).toString("hex");
```

On YubiHSM2, the `audit-signing-key` private key was generated inside the HSM and has `extractable=false`. There is no way to forge signatures even with full root access to the host.

---

## Part 4: Attack Class Mapping

For each of the 12 attack classes, here is exactly how the paranoid isolation architecture addresses it. Specific mechanisms, not vague "container isolation."

### Class 1: OS Command Injection (Vulns #2, #3, #19, #20)

**Attack:** Attacker injects shell metacharacters into command strings passed to `execSync`/`spawn`.

**Paranoid mitigation stack:**

1. **Sandbox container isolation (L6):** All `exec` tool calls run inside `sandbox-exec` container, NOT the gateway container. Even if command injection succeeds, the attacker is inside a container with:
   - Read-only root filesystem
   - No capabilities (`cap_drop: ALL`)
   - No network (`network: none` on sandbox container)
   - No access to OpenClaw config, credentials, or HSM
   - `no-new-privileges` flag
   - Custom seccomp blocking `ptrace`, `mount`, `bpf`, `kexec_load`

2. **AppArmor profile:** Sandbox AppArmor profile restricts file access to workspace subtree only.

3. **lobsec-plugin `before_tool_call`:** Validates command against allowlist. Rejects shell metacharacters in arguments. Logs every command.

4. **User namespacing:** Even if the attacker escapes the container (combining with another vulnerability), they land as an unprivileged host user (uid 101000).

5. **Docker rootless:** The Docker daemon itself runs unprivileged. Container escape + user namespace escape still lands unprivileged.

**Specific vuln #2 (PATH injection sandbox escape):** The sandbox container has a fixed, read-only `PATH`. An attacker cannot write to any directory in `PATH` (read-only root fs). Even if they could, `no-new-privileges` prevents SUID execution.

### Class 2: SSRF (Vulns #7, #10, #11, #13, #15, #28)

**Attack:** Attacker-controlled URLs cause the gateway to probe internal networks, cloud metadata, or localhost services.

**Paranoid mitigation stack:**

1. **No direct internet for gateway (Network isolation):** `lobsec-internal` Docker network is `--internal` with `enable_ip_masquerade=false`. The gateway container has NO default route to the internet. Even if the SSRF guard is completely bypassed, there is no route to `169.254.169.254` or any internal host.

2. **All egress through lobsec-proxy:** `HTTP_PROXY`/`HTTPS_PROXY` env vars force all outbound through lobsec-proxy. The proxy enforces:
   - Denylist: RFC 1918, link-local, metadata endpoints, IPv4-mapped IPv6 (vuln #13)
   - Allowlist: only permitted destinations
   - DNS resolution happens in lobsec-proxy, not gateway, preventing DNS rebinding

3. **OpenClaw SSRF policy:** `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: false` as defense-in-depth.

4. **nftables on host:** Even if an attacker compromises lobsec-proxy, host nftables blocks traffic to RFC 1918 ranges from Docker containers.

**Specific vuln #13 (IPv4-mapped IPv6 bypass):** lobsec-proxy's denylist explicitly includes `::ffff:0.0.0.0/96`. The proxy resolves DNS and checks the resolved IP against the denylist AFTER resolution, preventing DNS-based bypass.

**Specific vuln #28 (Cron webhook SSRF):** Cron webhook delivery goes through `HTTPS_PROXY`. lobsec-proxy validates the destination URL before forwarding.

### Class 3: Webhook Authentication Bypass (Vulns #6, #8, #12)

**Attack:** Forged webhook requests reach OpenClaw because signature verification is missing or broken.

**Paranoid mitigation stack:**

1. **Caddy rate limiting and request size caps (L2):** Reduces attack surface for automated webhook forgery.

2. **lobsec-proxy webhook validation (L3):** All webhook traffic routes through lobsec-proxy port 8082. The proxy performs cryptographic signature verification BEFORE forwarding to OpenClaw:
   - Telegram: `X-Telegram-Bot-Api-Secret-Token` comparison (secret in HSM, compared via `timingSafeEqual`)
   - Twilio: HMAC-SHA1 computed by HSM (`C_Sign` with `CKM_SHA_1_HMAC`)
   - Slack: HMAC-SHA256 computed by HSM
   - Discord: Ed25519 verification with HSM-resident public key

3. **HSM-backed verification:** Webhook signing secrets stored in HSM. The HSM performs the HMAC/signature computation. The secret never enters lobsec-proxy process memory for platforms where HSM can perform the operation directly.

4. **Startup gate:** lobsec-cli refuses to start if any enabled channel lacks a configured webhook secret in the HSM.

5. **Replay protection:** Timestamp validation on webhook payloads. Reject events older than 5 minutes. Nonce tracking for platforms that provide it.

### Class 4: Path Traversal / File Access (Vulns #5, #9, #23, #30)

**Attack:** `../` sequences, symlinks, or uncanonicalized paths allow reading/writing outside the workspace.

**Paranoid mitigation stack:**

1. **Container filesystem isolation:** The gateway container ONLY has these writable locations:
   - `/home/node/.openclaw/workspace/` (bind mount)
   - `/home/node/.openclaw/agents/` (bind mount)
   - `/home/node/.openclaw/logs/` (bind mount, append-only on host)
   - `/tmp` (tmpfs)

   There is physically NO path from inside the container to the host filesystem outside these mounts. `../../../etc/passwd` resolves to the container's read-only `/etc/passwd`.

2. **Sandbox container narrower scope:** `sandbox-exec` only mounts a SUBDIRECTORY of workspace. Even traversal within the container filesystem cannot reach OpenClaw config.

3. **lobsec-plugin `before_tool_call` path validation:**
   - `realpath()` canonicalization
   - Verify resolved path starts with workspace prefix
   - Reject paths containing symlinks that resolve outside workspace (vuln #30)
   - Block `file://` URLs in any tool parameter (vuln #15)

4. **AppArmor profile:** Denies read/write outside explicitly listed paths.

**Specific vuln #30 (symlink following in skill packages):** Skill installation happens in a temporary sandbox container. lobsec-plugin validates the extracted package: scans for symlinks, rejects any that target outside the skill directory. The check runs BEFORE the skill is moved to the real skill directory.

### Class 5: WebSocket / Gateway Protocol Abuse (Vulns #1, #4)

**Attack:** Attacker connects to the WebSocket, exfiltrates tokens, or injects malicious config changes.

**Paranoid mitigation stack (triple-primary: L1 + L2 + L4):**

1. **L1 -- Network perimeter:**
   - Gateway binds to `127.0.0.1:18789` ONLY (enforced by config + CLI flag)
   - nftables blocks port 18789 on all non-loopback interfaces
   - Even if binding is changed, no external access

2. **L2 -- Caddy reverse proxy:**
   - Origin header validation on WebSocket upgrade requests
   - Only explicitly allowed Origin values pass (CVE-2026-25253 primary mitigation)
   - Mandatory authentication before forwarding
   - WebSocket frame size limits

3. **L4 -- Gateway policy enforcer:**
   - `tools.deny: ["gateway"]` prevents the agent from calling config modification tools
   - `openclaw.json` mounted read-only into the container -- even if `config.patch` WebSocket message passes through, the filesystem write fails
   - lobsec-plugin can filter WebSocket frames if needed (via `before_tool_call` hook for the `gateway` tool)

4. **Config lock triple-defense:**
   - Config file: read-only bind mount (filesystem-level)
   - Tool deny: `["gateway"]` (OpenClaw policy level)
   - WebSocket: Caddy can strip/block `config.patch` method frames (proxy level)

**Specific vuln #1 (CVE-2026-25253, 1-Click RCE):** The attack chain requires: (a) victim visits malicious page, (b) JavaScript connects to `ws://localhost:18789`, (c) exfiltrates auth token. Our defense: Caddy validates Origin header, blocking cross-origin WebSocket connections. Gateway binds to loopback, so only local processes can connect. Even if Origin is spoofed, mandatory auth token is required.

### Class 6: Sandbox / Execution Policy Bypass (Vulns #14, #21, #24, #27)

**Attack:** Circumvent tool execution restrictions through command aliasing, config injection, hash collisions, or mismatch between declared and actual commands.

**Paranoid mitigation stack:**

1. **Independent command validation in lobsec-plugin:** The `before_tool_call` hook receives the ACTUAL command parameters. lobsec-plugin validates the actual command string, not a declared alias. This directly addresses vuln #14 (rawCommand/command[] mismatch).

2. **Deterministic sandbox config:** The sandbox container image and configuration are fixed by lobsec-cli at startup. The gateway cannot modify sandbox parameters because:
   - `tools.deny: ["gateway"]` blocks config changes
   - `openclaw.json` is read-only
   - Docker socket is not mounted (gateway cannot create/modify containers directly)

3. **Container immutability:** Read-only root filesystem means even if an attacker gains code execution inside the sandbox, they cannot modify the sandbox configuration or install persistence.

4. **Workspace path sanitization (vuln #27):** lobsec-plugin validates workspace paths before they are used in prompts. Paths are canonicalized and stripped of prompt injection payloads.

**Specific vuln #24 (hash collision):** This is an upstream bug in sandbox config hashing (using a weak hash to detect config changes). Since lobsec-cli generates and owns the sandbox config, and the config file is read-only, an attacker cannot trigger a config-hash-based sandbox recreation. The hash is a non-issue when the config is immutable.

### Class 7: Information Disclosure / Credential Leakage (Vulns #17, #25, #26, #34)

**Attack:** Secrets appear in logs, error messages, API responses, or are stored in plaintext.

**Paranoid mitigation stack:**

1. **HSM-backed storage (L7):** Credentials stored in SoftHSM2/YubiHSM2. Never on filesystem in plaintext. `auth-profiles.json` on tmpfs, destroyed on shutdown.

2. **Real API keys only in lobsec-proxy:** OpenClaw gateway never holds real LLM API keys. It holds only the internal `LOBSEC_PROXY_TOKEN`. If the gateway is compromised and all its memory dumped, no real API keys are exposed.

3. **Log redaction (dual layer):**
   - lobsec-plugin `tool_result_persist` and `before_message_write` hooks: regex-based redaction of credential patterns (`sk-ant-*`, `sk-*`, `xoxb-*`, `ghp_*`, bearer tokens, etc.)
   - OpenClaw native: `logging.redactSensitive: true`
   - lobsec-proxy: strips `Authorization` headers from access logs

4. **Session isolation (vuln #25):** `session.dmScope: "per-channel-peer"`. OpenClaw's own session scoping prevents cross-session transcript access. lobsec-plugin additionally validates session boundaries on `read` operations.

5. **skills.status secrets (vuln #17):** lobsec-plugin hooks the skills status endpoint response and strips credential fields.

6. **Telegram bot token leakage (vuln #26):** Telegram bot token stored in HSM, injected via env var. lobsec-proxy strips it from error messages and redirects. Log redaction catches token patterns.

### Class 8: XSS / Client-Side Injection (Vulns #16, #22)

**Attack:** Unsanitized data rendered in Control UI or deep-link dialogs.

**Paranoid mitigation stack (limited -- mostly upstream):**

1. **CSP headers via Caddy (L2):**
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'
   ```
   This blocks inline script execution and frames, mitigating stored XSS (vuln #22) even if OpenClaw's output encoding is broken.

2. **X-Frame-Options: DENY** prevents clickjacking.

3. **Control UI access restricted:** Only accessible via SSH tunnel / Tailscale. Attacker must already have network access.

4. **Residual risk acknowledged.** Deep link truncation (vuln #16) is a macOS client bug outside lobsec's scope.

### Class 9: Network Discovery Poisoning (Vuln #18)

**Attack:** Spoofed mDNS/DNS-SD announcements on shared LANs.

**Paranoid mitigation stack:**

1. **mDNS disabled:** `discovery.mdns.mode: "off"` in hardened config.

2. **No open ports:** Gateway binds to loopback only. Even if mDNS somehow announces the service, there is nothing to connect to from the LAN.

3. **nftables blocks UDP 5353:** Defense-in-depth in case OpenClaw ignores the config setting.
   ```
   # nftables rule
   chain input {
       udp dport 5353 drop comment "block mDNS"
   }
   ```

4. **VPN-only access:** All legitimate remote access via SSH/Tailscale/WireGuard. Service discovery is unnecessary.

### Class 10: Supply Chain Poisoning -- ClawHub Skills (Vuln #37)

**Attack:** Malicious skills from ClawHub marketplace execute arbitrary code, exfiltrate data, or install backdoors (824+ confirmed malicious).

**Paranoid mitigation stack:**

1. **Skill allowlist (L4):** Only explicitly approved skills may be installed. lobsec-cli maintains a signed allowlist. The lobsec-plugin `before_tool_call` hook blocks skill installation commands not on the allowlist.

2. **Sandboxed skill installation (L6):** Skill packages are extracted in a temporary sandbox container with no network and read-only root filesystem. lobsec-plugin validates the extracted contents:
   - No symlinks pointing outside skill directory (vuln #30)
   - No path traversal in filenames (vuln #23)
   - Static analysis: scan for `exec`, `spawn`, `fetch`, `XMLHttpRequest`, filesystem access patterns
   - Manifest validation: declared permissions match actual code

3. **Skill runtime isolation:** Skills execute within the agent's sandbox container. Since the sandbox has no network, a malicious skill cannot exfiltrate data. Since the filesystem is read-only (except workspace), it cannot install persistence.

4. **Integrity verification:** lobsec-cli can sign approved skill packages. lobsec-plugin verifies the signature before loading. The signing key is in the HSM (`extractable: false`).

5. **HEARTBEAT.md and Cron monitoring (L4):** lobsec-plugin monitors changes to `HEARTBEAT.md` and cron configurations. Alerts on unauthorized persistence mechanisms.

### Class 11: Insecure Defaults / Architectural Misdesign (Vulns #33, #35, #36)

**Attack:** System ships with insecure configurations: LAN binding, no auth, plaintext secrets, exposed databases.

**Paranoid mitigation stack (this is lobsec's CORE MISSION):**

1. **lobsec-cli generates hardened config:** Every insecure default is overridden:
   ```json5
   {
     "gateway.bind": "loopback",           // was: "lan"
     "gateway.auth.mode": "token",         // was: "none"
     "sandbox.mode": "all",                // was: "off"
     "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork": false,  // was: true
     "discovery.mdns.mode": "off",         // was: "minimal"
     "tools.deny": ["gateway", "sessions_spawn", "sessions_send"],
     "logging.redactSensitive": true,
     "gateway.controlUi.dangerouslyDisableDeviceAuth": false,  // was: true in user config
   }
   ```

2. **Config drift detection (L4):** lobsec-plugin periodically hashes the running config and compares against the hardened template. Any drift triggers an alert and (optionally) auto-remediation.

3. **Startup security audit:** lobsec-cli runs `openclaw security audit --json` at startup. Parses results. Blocks startup if critical findings remain.

4. **Config file read-only mount:** Even if an attacker achieves code execution in the gateway, they cannot weaken the config because it is a read-only bind mount.

5. **Dangerous flag blocking:** lobsec-cli startup REFUSES to proceed if any `dangerously*` flag is enabled. These flags are never set in the generated config.

**Specific vuln #36 ("The Terrifying Five" structural LLM risks):** These are inherent to LLM agents. lobsec addresses each:
- Tool use: allowlists + sandbox (L4, L6)
- Memory: session isolation, workspace containment
- Planning: human-in-the-loop for destructive actions
- Identity: server-side identity verification (L3)
- Persistence: HEARTBEAT/cron monitoring (L4)

### Class 12: Prompt Injection / Identity Spoofing (Vulns #27, #31, #32)

**Attack:** Attacker-controlled content (channel metadata, messages, workspace paths) manipulates LLM behavior.

**Paranoid mitigation stack (defense-in-depth; no perfect solution exists):**

1. **Structural separation (L8):** lobsec-plugin enforces clear boundaries between system prompts (trusted) and user content (untrusted). User content is wrapped in explicit delimiters that the LLM is instructed to treat as untrusted data.

2. **Output validation (L8):** lobsec-plugin `message_sending` hook scans outbound messages for:
   - Credential patterns (leaked API keys)
   - System prompt content (prompt extraction)
   - Execution of commands not in the conversation context

3. **Tool execution gating (L4):** Even if prompt injection succeeds in manipulating the LLM's intent, the tool execution still passes through `before_tool_call`. A prompt injection that says "run rm -rf /" still hits the command allowlist.

4. **Identity verification (L3, vuln #31):** Discord moderation actions require server-side role verification, not just message content claiming to be a moderator.

5. **Channel metadata sanitization (vuln #32):** Slack channel names, topics, and descriptions are sanitized before inclusion in prompts. HTML entities decoded, control characters stripped, length limited.

6. **Workspace path validation (vuln #27):** Workspace paths are canonicalized and validated before appearing in any prompt context.

7. **Sandbox containment as backstop:** Even if prompt injection achieves arbitrary tool execution, the sandbox limits the blast radius: no network, read-only fs, no credentials.

---

## Appendix A: docker-compose.yml

```yaml
# /root/lobsec/config/docker-compose.yml
# PARANOID-level isolation for lobsec + OpenClaw

version: "3.8"

networks:
  lobsec-internal:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: "false"

  lobsec-sandbox:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.30.1.0/24
          gateway: 172.30.1.1
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: "false"

  lobsec-egress:
    # lobsec-proxy needs actual internet access (for LLM APIs, webhooks)
    # This network is NOT internal -- it allows egress
    # Only lobsec-proxy connects to this network
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.2.0/24
          gateway: 172.30.2.1

services:
  caddy:
    image: caddy:2-alpine
    container_name: lobsec-caddy
    networks:
      lobsec-internal:
        ipv4_address: 172.30.0.10
    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:80:80"
    volumes:
      - /root/lobsec/config/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - /var/log/caddy/:/var/log/caddy/:rw
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=32m
      - /config:rw,noexec,nosuid,size=8m
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "caddy", "validate", "--config", "/etc/caddy/Caddyfile"]
      interval: 30s
      timeout: 5s
      retries: 3

  lobsec-proxy:
    image: lobsec-proxy:local
    container_name: lobsec-proxy
    networks:
      lobsec-internal:
        ipv4_address: 172.30.0.20
      lobsec-egress:
        ipv4_address: 172.30.2.20
    environment:
      # Real API keys injected at runtime by lobsec-cli
      # These placeholders are replaced by the startup script
      ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"
      OPENAI_API_KEY: "${OPENAI_API_KEY}"
      PROXY_INTERNAL_TOKEN: "${PROXY_INTERNAL_TOKEN}"
      OLLAMA_JETSON_URL: "${OLLAMA_JETSON_URL:-http://<jetson-host>:11434}"
      OLLAMA_SOVEREIGN_URL: "${OLLAMA_SOVEREIGN_URL}"
    volumes:
      - /root/lobsec/config/proxy-config.json:/config/proxy-config.json:ro
      - /var/log/lobsec/:/var/log/lobsec/:rw
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
      - /run:rw,noexec,nosuid,size=16m
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
      - seccomp:/root/lobsec/config/lobsec-seccomp.json
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://localhost:8080/health').then(r => process.exit(r.ok ? 0 : 1))"]
      interval: 15s
      timeout: 5s
      retries: 3

  openclaw-gateway:
    image: openclaw:local
    container_name: openclaw-gateway
    networks:
      lobsec-internal:
        ipv4_address: 172.30.0.30
      lobsec-sandbox:
        ipv4_address: 172.30.1.30
    environment:
      HOME: /home/node
      TERM: xterm-256color
      OPENCLAW_GATEWAY_TOKEN: "${OPENCLAW_GATEWAY_TOKEN}"
      HTTP_PROXY: "http://172.30.0.20:8081"
      HTTPS_PROXY: "http://172.30.0.20:8081"
      NO_PROXY: "localhost,127.0.0.1,172.30.0.20,172.30.1.0/24"
      # No real API keys here -- only internal proxy token
    volumes:
      # Config: READ-ONLY
      - /root/.openclaw/openclaw.json:/home/node/.openclaw/openclaw.json:ro
      # Credentials on tmpfs: READ-ONLY
      - /run/lobsec/auth-profiles.json:/home/node/.openclaw/agents/main/agent/auth-profiles.json:ro
      # Workspace: read-write (the working directory)
      - /root/.openclaw/workspace/:/home/node/.openclaw/workspace/:rw
      # Agent state: read-write
      - /root/.openclaw/agents/:/home/node/.openclaw/agents/:rw
      # Logs: append-only on host
      - /root/.openclaw/logs/:/home/node/.openclaw/logs/:rw
      # Canvas, cron: read-write
      - /root/.openclaw/canvas/:/home/node/.openclaw/canvas/:rw
      - /root/.openclaw/cron/:/home/node/.openclaw/cron/:rw
      # Plugin directory: read-only (lobsec-plugin installed here)
      - /root/lobsec/dist/plugin/:/home/node/.openclaw/plugins/lobsec/:ro
      # NO Docker socket mount -- EVER
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=256m
      - /run:rw,noexec,nosuid,size=64m
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
      - seccomp:/root/lobsec/config/lobsec-seccomp.json
      - apparmor:lobsec-openclaw
    init: true
    restart: unless-stopped
    command:
      [
        "node",
        "dist/index.js",
        "gateway",
        "--bind",
        "loopback",
        "--port",
        "18789",
      ]
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:18789/health').then(r => process.exit(r.ok ? 0 : 1))"]
      interval: 15s
      timeout: 5s
      retries: 3
    depends_on:
      lobsec-proxy:
        condition: service_healthy

volumes:
  caddy-data:
```

Note: Sandbox containers (sandbox-exec, sandbox-browser) are NOT in this compose file because OpenClaw manages them dynamically. lobsec-cli configures OpenClaw's sandbox settings in `openclaw.json` to ensure they are created with the correct security parameters. lobsec-cli also pre-pulls the sandbox images.

---

## Appendix B: nftables Rules

File: `/root/lobsec/config/lobsec.nft`

```
#!/usr/sbin/nft -f
# lobsec paranoid nftables ruleset
# Applied to the HOST, not inside containers

flush ruleset

table inet lobsec {

    # ========================================
    # INPUT CHAIN: What can reach this host
    # ========================================
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback: allow
        iif "lo" accept

        # Established/related: allow
        ct state established,related accept

        # SSH: allow (primary access method)
        tcp dport 22 accept

        # Tailscale/WireGuard: allow
        # Tailscale uses UDP 41641 by default
        udp dport 41641 accept
        # WireGuard
        udp dport 51820 accept

        # Block mDNS (Class 9 mitigation)
        udp dport 5353 drop comment "block mDNS"

        # Block OpenClaw gateway port from ALL non-loopback
        tcp dport 18789 drop comment "block direct gateway access"
        tcp dport 18790 drop comment "block direct bridge access"

        # ICMP: allow essential
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply, destination-unreachable, time-exceeded, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept

        # Log and drop everything else
        log prefix "lobsec-input-drop: " counter drop
    }

    # ========================================
    # FORWARD CHAIN: Docker container traffic
    # ========================================
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Established/related: allow
        ct state established,related accept

        # lobsec-internal -> lobsec-internal: allow (inter-container)
        # Docker handles this via bridge rules, but explicit for clarity
        iifname "br-lobsec-internal" oifname "br-lobsec-internal" accept

        # lobsec-sandbox -> lobsec-sandbox: allow (gateway <-> sandbox)
        iifname "br-lobsec-sandbox" oifname "br-lobsec-sandbox" accept

        # lobsec-egress -> internet: allow (ONLY lobsec-proxy)
        # The egress network only has lobsec-proxy on it
        iifname "br-lobsec-egress" oifname != "br-lobsec-*" accept

        # Block lobsec-internal -> internet (defense-in-depth; --internal already blocks this)
        iifname "br-lobsec-internal" oifname != "br-lobsec-*" log prefix "lobsec-internal-escape: " drop

        # Block sandbox -> internet
        iifname "br-lobsec-sandbox" oifname != "br-lobsec-*" log prefix "lobsec-sandbox-escape: " drop

        # Block cross-network traffic (internal <-> sandbox <-> egress)
        iifname "br-lobsec-internal" oifname "br-lobsec-sandbox" drop
        iifname "br-lobsec-sandbox" oifname "br-lobsec-internal" drop
        iifname "br-lobsec-sandbox" oifname "br-lobsec-egress" drop
        iifname "br-lobsec-egress" oifname "br-lobsec-sandbox" drop

        # Log and drop everything else
        log prefix "lobsec-forward-drop: " counter drop
    }

    # ========================================
    # OUTPUT CHAIN: What the host can send
    # ========================================
    chain output {
        type filter hook output priority 0; policy accept;

        # Block outbound to cloud metadata from host
        ip daddr 169.254.169.254 log prefix "lobsec-metadata-block: " drop
        ip6 daddr fd00:ec2::254 drop

        # Allow everything else from host (host is trusted)
    }

    # ========================================
    # EGRESS CONTROLS for lobsec-proxy
    # Applied via DOCKER-USER chain integration
    # ========================================
    chain docker-user {
        type filter hook forward priority -1; policy accept;

        # Block RFC 1918 from egress network (SSRF defense-in-depth)
        iifname "br-lobsec-egress" ip daddr 10.0.0.0/8 log prefix "lobsec-ssrf-block: " drop
        iifname "br-lobsec-egress" ip daddr 172.16.0.0/12 log prefix "lobsec-ssrf-block: " drop
        iifname "br-lobsec-egress" ip daddr 192.168.0.0/16 log prefix "lobsec-ssrf-block: " drop
        iifname "br-lobsec-egress" ip daddr 169.254.0.0/16 log prefix "lobsec-ssrf-block: " drop

        # Allow Jetson Orin (specific LAN IP exception)
        # This is the ONLY RFC 1918 address allowed from egress
        iifname "br-lobsec-egress" ip daddr <jetson-host> tcp dport 11434 accept comment "Jetson Ollama"

        # Block IPv4-mapped IPv6 (vuln #13)
        iifname "br-lobsec-egress" ip6 daddr ::ffff:0.0.0.0/96 log prefix "lobsec-ipv6map-block: " drop

        # Block IPv6 link-local and unique-local
        iifname "br-lobsec-egress" ip6 daddr fe80::/10 drop
        iifname "br-lobsec-egress" ip6 daddr fc00::/7 drop
    }
}
```

---

## Appendix C: SoftHSM2 Setup

```bash
#!/bin/bash
# /root/lobsec/scripts/setup-softhsm2.sh
# Development/testing HSM setup using SoftHSM2

set -euo pipefail

# Install SoftHSM2
apt-get install -y softhsm2 libsofthsm2

# Create token store directory
mkdir -p /root/.lobsec/softhsm2/tokens
chmod 700 /root/.lobsec/softhsm2

# Configure SoftHSM2
cat > /root/.lobsec/softhsm2/softhsm2.conf << 'CONF'
directories.tokendir = /root/.lobsec/softhsm2/tokens
objectstore.backend = file
log.level = INFO
CONF

export SOFTHSM2_CONF=/root/.lobsec/softhsm2/softhsm2.conf

# Initialize token slot
softhsm2-util --init-token \
  --slot 0 \
  --label "lobsec" \
  --pin "CHANGE-ME-dev-pin" \
  --so-pin "CHANGE-ME-dev-so-pin"

echo "SoftHSM2 initialized. Token slot 0 ready."
echo "Module path: /usr/lib/softhsm/libsofthsm2.so"
echo ""
echo "Store credentials:"
echo "  lobsec-cli credential add --label anthropic-api-key --value-stdin"
echo ""
echo "IMPORTANT: Change default PINs before storing real credentials."
```

---

## Appendix D: PKCS#11 Integration Code Sketch

```typescript
// /root/lobsec/src/hsm/credential-store.ts
// PKCS#11-based credential store -- backend-agnostic (SoftHSM2 or YubiHSM2)
//
// Dependencies: graphene-pk11 (npm package, verified real)
// PKCS#11 module: configured via LOBSEC_PKCS11_MODULE env var

import * as graphene from "graphene-pk11";
import { createHash } from "node:crypto";
import { timingSafeEqual } from "node:crypto";

export interface CredentialStoreConfig {
  modulePath: string;   // e.g., /usr/lib/softhsm/libsofthsm2.so
  slotIndex: number;    // typically 0
  pin: string;          // HSM user PIN
}

export class CredentialStore {
  private mod: graphene.Module;
  private session: graphene.Session;
  private initialized = false;

  /**
   * Open PKCS#11 session. Must be called before any operations.
   */
  open(config: CredentialStoreConfig): void {
    this.mod = graphene.Module.load(config.modulePath);
    this.mod.initialize();

    const slots = this.mod.getSlots(true); // Only slots with tokens
    if (slots.length <= config.slotIndex) {
      throw new Error(`PKCS#11 slot ${config.slotIndex} not found. Available: ${slots.length}`);
    }

    const slot = slots.items(config.slotIndex);
    this.session = slot.open(
      graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
    );
    this.session.login(graphene.UserType.USER, config.pin);
    this.initialized = true;
  }

  /**
   * Store an API key or secret in the HSM.
   * For API keys: sensitive=true, extractable=true (must be retrieved for HTTP headers)
   * For signing keys: sensitive=true, extractable=false (HSM performs operation)
   */
  storeApiKey(label: string, keyValue: string): void {
    this.ensureInitialized();

    // Delete existing key with same label if present
    this.deleteIfExists(label);

    this.session.create({
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.GENERIC_SECRET,
      label: label,
      id: Buffer.from(createHash("sha256").update(label).digest().subarray(0, 8)),
      value: Buffer.from(keyValue, "utf-8"),
      token: true,          // Persistent in HSM token
      private: true,         // Requires login
      sensitive: true,       // Marked sensitive
      extractable: true,     // Must be extractable for API key use
      modifiable: false,     // Immutable after creation
    });
  }

  /**
   * Store a webhook signing secret (non-extractable -- HSM performs HMAC).
   */
  storeWebhookSecret(label: string, secretValue: string): void {
    this.ensureInitialized();
    this.deleteIfExists(label);

    this.session.create({
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.GENERIC_SECRET,
      label: label,
      id: Buffer.from(createHash("sha256").update(label).digest().subarray(0, 8)),
      value: Buffer.from(secretValue, "utf-8"),
      token: true,
      private: true,
      sensitive: true,
      extractable: false,    // NEVER leaves HSM
      modifiable: false,
      sign: true,            // Can be used for HMAC
      verify: true,
    });
  }

  /**
   * Retrieve an API key value. Only works for extractable keys.
   * Returns the key as a string. Caller MUST clear the string after use.
   */
  retrieveApiKey(label: string): string {
    this.ensureInitialized();

    const objects = this.session.find({ label: label });
    const iter = objects[Symbol.iterator]();
    const first = iter.next();
    if (first.done) {
      throw new Error(`Credential not found: ${label}`);
    }

    const key = first.value;
    const attrs = key.getAttribute({ value: true });
    return (attrs.value as Buffer).toString("utf-8");
  }

  /**
   * Compute HMAC-SHA256 using HSM-resident key (key never leaves HSM).
   */
  hmacSha256(keyLabel: string, data: Buffer): Buffer {
    this.ensureInitialized();

    const objects = this.session.find({ label: keyLabel });
    const iter = objects[Symbol.iterator]();
    const first = iter.next();
    if (first.done) {
      throw new Error(`Signing key not found: ${keyLabel}`);
    }

    const key = first.value;
    const sign = this.session.createSign(
      { name: "SHA256_HMAC", params: null } as any,
      key
    );
    sign.update(data);
    return sign.final() as Buffer;
  }

  /**
   * Verify HMAC-SHA256 in constant time.
   */
  verifyHmacSha256(keyLabel: string, data: Buffer, signature: Buffer): boolean {
    const computed = this.hmacSha256(keyLabel, data);
    if (computed.length !== signature.length) return false;
    return timingSafeEqual(computed, signature);
  }

  /**
   * Generate an RSA-2048 signing keypair inside the HSM.
   * Private key is non-extractable.
   */
  generateSigningKeypair(label: string): void {
    this.ensureInitialized();

    this.session.generateKeyPair(
      graphene.MechanismEnum.RSA_PKCS_KEY_PAIR_GEN,
      {
        label: `${label}-pub`,
        modulusBits: 2048,
        publicExponent: Buffer.from([1, 0, 1]),
        token: true,
        verify: true,
      },
      {
        label: `${label}-priv`,
        token: true,
        private: true,
        sensitive: true,
        extractable: false,
        sign: true,
      }
    );
  }

  /**
   * Sign data with HSM-resident RSA private key.
   */
  rsaSign(keyLabel: string, data: Buffer): Buffer {
    this.ensureInitialized();

    const objects = this.session.find({ label: `${keyLabel}-priv` });
    const iter = objects[Symbol.iterator]();
    const first = iter.next();
    if (first.done) {
      throw new Error(`Signing key not found: ${keyLabel}-priv`);
    }

    const key = first.value;
    const sign = this.session.createSign(
      graphene.MechanismEnum.SHA256_RSA_PKCS,
      key
    );
    sign.update(data);
    return sign.final() as Buffer;
  }

  /**
   * Destroy a credential in the HSM.
   */
  destroy(label: string): void {
    this.ensureInitialized();
    this.deleteIfExists(label);
  }

  /**
   * List all credential labels (no values).
   */
  list(): string[] {
    this.ensureInitialized();
    const labels: string[] = [];

    const objects = this.session.find({});
    for (const obj of objects) {
      const attrs = obj.getAttribute({ label: true });
      if (attrs.label) {
        labels.push(attrs.label as string);
      }
    }
    return labels;
  }

  close(): void {
    if (this.session) {
      try { this.session.logout(); } catch { /* already logged out */ }
      try { this.session.close(); } catch { /* already closed */ }
    }
    if (this.mod) {
      try { this.mod.finalize(); } catch { /* already finalized */ }
    }
    this.initialized = false;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error("CredentialStore not initialized. Call open() first.");
    }
  }

  private deleteIfExists(label: string): void {
    const objects = this.session.find({ label: label });
    for (const obj of objects) {
      obj.destroy();
    }
  }
}
```

---

## Design Verification Checklist

Before implementation, each of these MUST be verified against the running system:

| # | Item | Status |
|---|------|--------|
| 1 | `graphene-pk11` npm package: install, open SoftHSM2 session, store/retrieve key | `[NEEDS VERIFICATION]` |
| 2 | SoftHSM2 `apt install softhsm2` on Ubuntu 24.04 | Available (confirmed via `apt-cache search`) |
| 3 | Docker `--internal` network blocks all egress | `[NEEDS VERIFICATION]` -- test with `curl` from inside container |
| 4 | Docker rootless + custom seccomp profile | `[NEEDS VERIFICATION]` |
| 5 | AppArmor profile loads and confines Node.js process | `[NEEDS VERIFICATION]` -- AppArmor is active on this host (confirmed) |
| 6 | OpenClaw respects `HTTP_PROXY`/`HTTPS_PROXY` for all outbound | `[NEEDS VERIFICATION]` |
| 7 | OpenClaw reads `auth-profiles.json` from symlinked/mounted path | Likely yes, but `[NEEDS VERIFICATION]` |
| 8 | nftables rules compatible with Docker rootless bridge networking | `[NEEDS VERIFICATION]` |
| 9 | `read_only: true` + explicit tmpfs mounts -- OpenClaw starts and runs | `[NEEDS VERIFICATION]` |
| 10 | lobsec-plugin hooks fire for ALL tool calls including exec/read/write | Verified in source (hooks.ts) |

---

## Superseded Decisions

This document supersedes the following ADRs from STATUS.md:

| ADR | Previous Decision | New Decision | Rationale |
|-----|------------------|-------------|-----------|
| ADR-2 | LUKS/SOPS/Age baseline, HSM optional | HSM (SoftHSM2/YubiHSM2) via PKCS#11 as primary | Paranoid level demands HSM. SoftHSM2 is free and available. Same PKCS#11 API for both dev and prod. |
| ADR-3 | Per-deployment rotation only | Per-deployment rotation + HSM-backed instant revocation | HSM enables `C_DestroyObject` for immediate credential destruction |

All other ADRs remain valid and are incorporated into this design.
