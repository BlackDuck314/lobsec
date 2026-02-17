# Verification Item Resolution

> Resolved 2026-02-24 against running OpenClaw v2026.2.24
> Source: `/root/.openclaw/` config files + `/root/openclaw/src/` source code

---

## V1: Can `config.patch` override security settings at runtime?

**ANSWER: YES -- CRITICAL**

`config.patch` via WebSocket RPC can override ANY config setting as long as the patch passes Zod schema validation. Located at `/root/openclaw/src/gateway/server-methods/config.ts:284-360`.

- Uses JSON5 merge-patch with optimistic locking (baseHash)
- Full schema validation runs after merge, but ALL valid config is accepted
- No security-specific guards preventing weakening of tools.deny, sandbox.mode, etc.

**lobsec impact:** This is the most critical finding. An attacker on the WebSocket (or a compromised agent using the `gateway` tool) can:
- Relax `tools.deny` to re-enable dangerous tools
- Change `sandbox.mode` from `"all"` to `"off"`
- Modify `gateway.bind` from `"loopback"` to `"lan"`
- Disable `logging.redactSensitive`

**lobsec mitigation (three layers):**
1. **L4:** `tools.deny: ["gateway"]` -- prevents agent from invoking config changes
2. **L2:** WebSocket frame filtering at proxy to block `config.patch`/`config.apply` methods
3. **L4:** Filesystem permissions -- make `openclaw.json` read-only to OpenClaw process (requires running OpenClaw as different user than lobsec)

---

## V2: `auth-profiles.json` full schema

**ANSWER: FULLY RESOLVED**

**Path:** `~/.openclaw/agents/<agentId>/agent/auth-profiles.json`

**Schema:**
```json
{
  "version": 1,
  "profiles": {
    "provider:name": {
      "type": "api_key",
      "provider": "anthropic",
      "key": "sk-ant-..."
    }
  },
  "lastGood": {
    "anthropic": "anthropic:default"
  },
  "usageStats": {
    "provider:name": {
      "lastUsed": 1700000000000,
      "errorCount": 0
    }
  }
}
```

**Also found:** `~/.openclaw/agents/<agentId>/agent/auth.json` (simpler format, same keys)

**Env var support:** YES, but only via `${VAR_NAME}` substitution in config.json5, NOT in auth-profiles.json directly. Config substitution is in `/root/openclaw/src/config/env-substitution.ts`.

**lobsec L7 strategy:**
- Option A (preferred): Define auth profiles in `openclaw.json` using `${VAR_NAME}` substitution, inject env vars at startup from encrypted storage
- Option B: Generate `auth-profiles.json` from encrypted storage at startup, write to tmpfs, point OpenClaw at it
- Either way: never leave plaintext keys on persistent disk

---

## V3: Which channels use webhooks vs persistent connections?

**ANSWER: PARTIAL -- needs per-channel verification**

From sessions.json and OpenClaw docs:
- **WebChat:** WebSocket persistent connection (confirmed: current session uses webchat)
- **WhatsApp/Baileys:** Persistent connection (Baileys is unofficial client library)
- **Signal/signal-cli:** Persistent connection (signal-cli daemon)
- **Telegram:** Supports both webhook (HTTP POST) and long-polling
- **Slack/Bolt:** WebSocket (Socket Mode) or HTTP webhook
- **Discord/discord.js:** WebSocket gateway connection
- **BlueBubbles:** HTTP polling or webhook
- **Google Chat:** Webhook or Pub/Sub
- **Microsoft Teams:** Webhook (Activity handler)

**lobsec L3 impact:** Webhook authentication (L3) primarily applies to: Telegram (webhook mode), Slack (HTTP mode), Google Chat, Microsoft Teams, and any HTTP-based channel. Persistent-connection channels (WhatsApp, Signal, Discord) authenticate differently.

---

## V4: LLM backend routing

**ANSWER: RESOLVED -- no native content-based routing**

OpenClaw's auth profiles support:
- Per-agent model/provider assignment via config
- Provider failover via `auth.order` preference lists
- `${VAR_NAME}` env substitution for API keys in config

**NOT supported natively:** Content-based routing (RED/AMBER/GREEN -> different backends). OpenClaw routes by agent/session, not by message content.

**lobsec L8 strategy:**
- Option A: LLM proxy -- lobsec runs a local HTTP server that OpenClaw treats as a model backend. The proxy classifies content and routes to Jetson (local) or cloud (remote)
- Option B: Custom Ollama backend -- configure Ollama as a separate auth profile; lobsec pre-processes messages and switches the active profile based on classification
- Either requires more investigation into OpenClaw's runtime model selection

---

## V5: Docker rootless + NVIDIA Container Toolkit on Jetson Orin

**ANSWER: NOT YET RESOLVED** -- requires Jetson hardware

---

## V6: Full list of security-relevant config keys

**ANSWER: FULLY RESOLVED**

### Network/Perimeter
| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `gateway.bind` | `"loopback" \| "lan" \| string` | `"lan"` | **DEFAULT IS INSECURE** |
| `gateway.auth.mode` | `"none" \| "token" \| "password"` | `"none"` | **DEFAULT IS INSECURE** |
| `gateway.auth.token` | string | -- | Plaintext in config |
| `gateway.trustedProxies` | string[] | `["127.0.0.1", "::1"]` | OK default |
| `gateway.controlUi.allowedOrigins` | string[] | -- | Must be explicitly set |
| `gateway.controlUi.dangerouslyDisableDeviceAuth` | boolean | `false` | **Currently TRUE in user config** |
| `discovery.mdns.mode` | `"off" \| "minimal" \| "full"` | `"minimal"` | Leaks service info |
| `discovery.wideArea.enabled` | boolean | `false` | OK default |

### Tool Execution
| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `tools.profile` | `"minimal" \| "coding" \| "messaging" \| "full"` | -- | Profile-based tool selection |
| `tools.allow` | string[] | -- | Explicit allowlist |
| `tools.alsoAllow` | string[] | -- | Additive to profile |
| `tools.deny` | string[] | -- | Deny wins over allow |
| `tools.exec.security` | `"deny" \| "allowlist" \| "full"` | `"deny"` | OK default |
| `tools.exec.host` | `"sandbox" \| "gateway" \| "node"` | `"sandbox"` | OK default |
| `tools.exec.ask` | `"off" \| "on-miss" \| "always"` | `"on-miss"` | Approval behavior |
| `tools.exec.safeBins` | string[] | -- | stdin-only binaries |

### Sandbox
| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `agents[*].sandbox.mode` | `"off" \| "non-main" \| "all"` | `"off"` | **DEFAULT IS INSECURE** |
| `agents[*].sandbox.scope` | `"session" \| "agent"` | `"session"` | Container lifecycle |
| `agents[*].sandbox.workspaceAccess` | `"none" \| "ro" \| "rw"` | `"rw"` | Workspace in container |
| `agents[*].sandbox.docker.readOnlyRoot` | boolean | -- | Not default |
| `agents[*].sandbox.docker.network` | string | -- | Blocks "host" at validation |
| `agents[*].sandbox.docker.seccompProfile` | string | -- | Blocks "unconfined" |
| `agents[*].sandbox.docker.apparmorProfile` | string | -- | Blocks "unconfined" |
| `agents[*].sandbox.docker.capDrop` | string[] | -- | Linux capabilities |
| `agents[*].sandbox.docker.memory` | string/number | -- | Memory limit |
| `agents[*].sandbox.docker.cpus` | number | -- | CPU limit |

### Browser/SSRF
| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` | boolean | `true` | **DEFAULT IS INSECURE** |
| `browser.ssrfPolicy.hostnameAllowlist` | string[] | -- | Pattern-based |

### Logging
| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `logging.redactSensitive` | boolean | -- | Should be true |

### DM Policy
| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `channels.<name>.dmPolicy` | `"pairing" \| "allowlist" \| "open"` | `"pairing"` | OK default |
| `channels.<name>.allowFrom` | string[] | -- | Per-channel allowlist |

### Dangerous Flags (must always be blocked)
- `agents[*].sandbox.docker.dangerouslyAllowReservedContainerTargets`
- `agents[*].sandbox.docker.dangerouslyAllowExternalBindSources`
- `gateway.controlUi.dangerouslyDisableDeviceAuth`
- `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`

---

## V7: `openclaw security audit` output format

**ANSWER: FULLY RESOLVED**

**CLI:** `openclaw security audit [--deep] [--fix] [--json]`

**Output format:**
```json
{
  "ts": 1700000000000,
  "summary": { "critical": 2, "warn": 5, "info": 3 },
  "findings": [
    {
      "checkId": "sandbox-mode-off",
      "severity": "critical",
      "title": "Sandbox is disabled",
      "detail": "...",
      "remediation": "Set agents[*].sandbox.mode to 'all'"
    }
  ],
  "deep": {
    "gateway": { "attempted": true, "url": "...", "ok": true, "error": null }
  }
}
```

**Check categories:** channels, attack surface, gateway HTTP, hooks, include files, sandbox (3 checks), tools (3 checks), model security, secrets in config, plugins/skills code safety, filesystem permissions, multi-user detection.

**`--fix` flag:** Auto-applies safe defaults for OpenClaw-specific settings (does NOT touch OS firewall/SSH).

**lobsec L9 integration:** Parse JSON output, map findings to attack classes, log as L4 events.

---

## Current Config Security Assessment

**User's running `openclaw.json` has these issues:**

| Setting | Current Value | lobsec Target | Severity |
|---------|--------------|---------------|----------|
| `gateway.bind` | `"lan"` | `"loopback"` | CRITICAL |
| `gateway.controlUi.dangerouslyDisableDeviceAuth` | `true` | `false` or removed | CRITICAL |
| `sandbox.mode` | `"off"` (default) | `"all"` | CRITICAL |
| `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` | `true` (default) | `false` | HIGH |
| `discovery.mdns.mode` | `"minimal"` (default) | `"off"` | MEDIUM |
| `tools.deny` | not set | `["gateway", "sessions_spawn", "sessions_send"]` | HIGH |
| `logging.redactSensitive` | not set | `true` | MEDIUM |
| Auth token in config | plaintext | encrypted/env injection | HIGH |
| API key in auth-profiles.json | plaintext on disk | encrypted/tmpfs | HIGH |

---

## New Findings Not Previously Anticipated

1. **OpenClaw's trust model is explicitly single-user, trusted-operator.** SECURITY.md states: session IDs are routing controls, not authorization boundaries. This means lobsec's L4 (policy enforcer) is even more critical -- OpenClaw itself does NOT enforce security between sessions.

2. **`exec` defaults to host execution when sandbox is off.** The current config runs `exec` on the host with full access. This is the #1 immediate risk.

3. **Skills are prompt injections by design.** They're loaded into the system prompt. A malicious skill = a malicious system prompt. lobsec L10 (supply chain) must vet skills before they enter the prompt.

4. **Heartbeat/Cron persistence means compromise survives sessions.** A prompt injection that writes to `HEARTBEAT.md` or creates a cron job persists across restarts.

5. **`openclaw security audit --fix`** can auto-fix some settings. lobsec could run this as part of Phase 1.

6. **Config audit log already exists.** `config-audit.jsonl` tracks all config writes with hashes. lobsec L9 can consume this.

7. **Default `tools.exec.security` is already `"deny"`.** Good default, but doesn't help if an allowlist is overly permissive.

8. **`setupCommand` in sandbox config runs `sh -lc` unsanitized.** Combined with `config.patch` RPC access, this is an RCE vector. lobsec blocks via read-only config mount + tool deny.

9. **Auto-update is a remote code execution path.** `openclaw update --yes` fetches and installs from npm. Must disable: `update.auto.enabled: false` or `OPENCLAW_NIX_MODE=1`.

10. **Plugin allowlist is OPEN by default.** `plugins.allow: []` causes all discovered non-bundled plugins to auto-load. Warn-only code scanner does not block malicious plugins. lobsec must enforce a closed allowlist.

11. **Browser sandbox exposes CDP (9222), VNC (5900), noVNC (6080) ports** on host-assigned ephemeral ports. These are per-container, only when browser sandbox is active.

12. **Memory system uses SQLite with `sqlite-vec`** at `~/.openclaw/memory/`. Additional PII-containing data store. Covered by fscrypt directory encryption.

13. **10+ env vars override module loading paths** (`OPENCLAW_BROWSER_CONTROL_MODULE`, `OPENCLAW_BUNDLED_PLUGINS_DIR`, `OPENCLAW_BUNDLED_SKILLS_DIR`, `OPENCLAW_BUNDLED_HOOKS_DIR`, `OPENCLAW_LIVE_CLI_BACKEND`). These allow arbitrary code injection if attacker controls container environment. lobsec must strip these.

14. **Config file rewritten at startup** during legacy migration and plugin auto-enable. A read-only mount prevents this; lobsec must verify config integrity after startup.

15. **Gateway logs written to `/tmp` in plaintext.** Includes operational data. lobsec redirects to encrypted log directory.

16. **Ollama API key visible in `/proc`** -- passed as command-line env var, readable by any process on host.

17. **Remote Ollama at `http://<remote-gpu-host>:11435`** -- all inference traffic over plain HTTP, no TLS. lobsec-proxy provides TLS + cert pinning for this connection.
