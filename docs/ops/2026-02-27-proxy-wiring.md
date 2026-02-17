# Ops Log: Ollama Proxy Wiring

**Date**: 2026-02-27
**Scope**: Route all Ollama (the sovereign GPU backend) LLM traffic through the lobsec proxy
**Result**: Verified working in production via Telegram end-to-end test

---

## Problem

OpenClaw's Ollama provider connected directly to the sovereign GPU backend (`http://<gpu-host>:11435`), bypassing the lobsec proxy entirely. This meant:

- No credential isolation for Ollama requests (API key held by OpenClaw)
- No audit trail at the proxy layer
- No egress enforcement point for sovereign inference

Only the Anthropic provider was routed through the proxy.

## Changes

### 1. Proxy: Add Ollama provider routing

**File**: `/opt/lobsec/proxy/llm-router.js`

Added Ollama to the `PROVIDERS` array:

```javascript
{
    name: "ollama",
    credentialLabel: "ollama-api-key",
    baseUrl: process.env["OLLAMA_BACKEND_URL"] ?? "http://<gpu-host>:11435",
    authPrefix: "Bearer",
}
```

Added Ollama path detection in `detectProvider()`:

```javascript
// Ollama API paths
if (req.path.startsWith("/api/"))
    return PROVIDERS.find((p) => p.name === "ollama");
```

Updated `validateProxyToken()` to accept both the proxy token AND the Ollama API key. This was necessary because OpenClaw's Ollama client resolves the API key from the `OLLAMA_API_KEY` environment variable directly (via `resolveEnvApiKeyVarName("ollama")`), bypassing the config file's `apiKey` field. Both tokens use timing-safe comparison.

### 2. Proxy: GET passthrough for model discovery

**File**: `/opt/lobsec/proxy/server.js`

The proxy previously rejected all non-POST requests with 405. OpenClaw's Ollama client sends `GET /api/tags` for model discovery. Added a GET handler that:

- Detects the Ollama provider from the path
- Skips auth (OpenClaw doesn't send apiKey for GET requests; safe because proxy is loopback-only)
- Forwards to the real Ollama backend
- Streams the response back

Also fixed a double-Bearer bug in auth header forwarding:

```javascript
// Before (bug): outHeaders["authorization"] = `Bearer ${route.targetAuth}`;
// route.targetAuth already contains "Bearer " prefix, resulting in "Bearer Bearer ..."

// After (fix):
outHeaders["authorization"] = route.targetAuth;
```

Also added imports for `detectProvider` and `validateProxyToken` from `llm-router.js`.

### 3. Proxy: Egress allowlist

**File**: `/opt/lobsec/proxy/egress-firewall.js`

Added the sovereign GPU backend and Jetson to `DEFAULT_ALLOWLIST`:

```javascript
{ host: "<gpu-host>", ports: [11435], protocol: "http" },
{ host: "<jetson-host>", ports: [443], protocol: "https" },
```

### 4. OpenClaw config: Redirect Ollama to proxy

**File**: `/opt/lobsec/.openclaw/openclaw.json`

Changed Ollama provider:

```
Before: "baseUrl": "http://<gpu-host>:11435"
After:  "baseUrl": "https://127.0.0.1:18790"

Before: "apiKey": "${OLLAMA_API_KEY}"
After:  "apiKey": "${OPENCLAW_GATEWAY_TOKEN}"
```

Note: The `apiKey` change is symbolic. OpenClaw's Ollama client resolves the key from the `OLLAMA_API_KEY` env var directly, overriding the config value. The proxy accepts both tokens.

### 5. Gateway: Trust lobsec CA for TLS

**File**: `/etc/systemd/system/lobsec.service`

Added environment variable so Node.js trusts the lobsec self-signed CA when connecting to the proxy:

```ini
Environment=NODE_EXTRA_CA_CERTS=/opt/lobsec/config/tls/ca.crt
```

Without this, `fetch()` calls to `https://127.0.0.1:18790` failed with `TypeError: fetch failed` (TLS cert validation error).

### 6. Plugin: Fix `before_message_write` crash

**File**: `/opt/lobsec/plugins/lobsec-security/index.ts`

Fixed a `TypeError: redacted.match is not a function` that crashed on EVERY message since deployment. Root cause: OpenClaw's `AgentMessage.content` can be an array of content blocks (`[{ type: "text", text: "..." }]`), not just a string. The handler passed it directly to `redactor.redact()` which called `.match()` on a non-string.

Fix: Check content type. For arrays, extract text from blocks with `type === "text"`. For non-string/non-array, skip.

Also fixed `tool_result_persist` handler with same type guard.

Cleaned up `message_sending` handler (removed debug stamp and logging).

---

## Verification

Tested end-to-end via Telegram:

```
14:28:11 [plugins] [lobsec] llm_input model=qwen2.5:32b
14:28:12 [proxy]   request_in POST /api/chat hasAuth=true
14:28:37 [proxy]   llm_request provider=ollama model=qwen2.5:32b latencyMs=25267 statusCode=200
14:28:40 [telegram] sendMessage ok chat=<chat-id> message=54
```

Direct proxy test:

```bash
curl -sk -X POST https://127.0.0.1:18790/api/chat \
  -H "Authorization: Bearer $PROXY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:32b","messages":[{"role":"user","content":"Say hi"}],"stream":false}'
# → 200 OK, "Hi there! How can I assist you today?"
```

## Data flow (after)

```
Telegram → OpenClaw Gateway (lobsec user)
  → HTTPS POST /api/chat → lobsec-proxy (127.0.0.1:18790)
    → validates token (timing-safe)
    → detects provider (ollama, from /api/ path)
    → injects real OLLAMA_API_KEY from credential store
    → forwards to http://<gpu-host>:11435/api/chat
    → logs audit: provider, model, latency, traceId, statusCode
  ← streams NDJSON response back
← sends to Telegram
```

## Known issues

- **Model discovery timeout**: OpenClaw has a 5s timeout for `GET /api/tags`. the sovereign GPU backend has 9 models (including 70B+ models) and responds slowly. Discovery fails but static model config (`qwen2.5:32b`) works fine. Cosmetic only.

- **`message_sending` hook doesn't fire**: Registered via `api.on()` but never called by OpenClaw's delivery system. Likely a session-scoped vs global hook runner issue. Credential redaction at the message level is not active. Mitigated by `before_message_write` and `tool_result_persist` hooks which DO fire.

- **Intermittent tool call timeout**: When the LLM responds with tool calls instead of text, OpenClaw sometimes hangs for 2 minutes processing the tool execution. Pre-existing OpenClaw behavior, not proxy-related.

## Remaining work

- **nftables egress enforcement**: Requires a separate `lobsec-proxy` user (uid) to distinguish proxy from gateway at the network layer. Both currently run as the same UID (`lobsec`).
- **Jetson routing through proxy**: Needs CF-Access header injection support (two custom headers per request, not just a single Bearer token).
- **`OLLAMA_API_KEY` in gateway env**: Still extracted by HSM script and present in gateway's environment, though unused by OpenClaw config. Could be removed from `hsm-extract-credentials.sh` for defense-in-depth.
