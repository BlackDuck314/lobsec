# Security Acid Tests

Destructive validation tests that intentionally break each security mechanism
to prove it is enforcing, not decorative.

**Last executed**: 2026-02-25 ~05:30-06:30 UTC
**Server**: `<hostname>` (Ubuntu 24.04+)
**OpenClaw**: v2026.2.24
**Service**: lobsec.service (systemd)

## Results Summary

| ID | Component | Method | Result |
|----|-----------|--------|--------|
| A1 | HSM credential extraction | Delete .env, restart | **PASS** |
| A2 | Credential wipe on stop | Stop service, check disk | **PASS** |
| A3 | HSM PIN enforcement | Wrong PIN, restart | **PASS** |
| A4 | Loopback binding | curl from LAN IP | **PASS** |
| A5 | Gateway auth | WS connect without token | **PASS** |
| A6 | Sandbox enforcement | Agent reads /etc/shadow | **PASS** |
| A7 | Ollama API key | Wrong/no key | **PASS** |
| A8 | CF-Access headers | Missing/wrong headers | **PASS** |
| A9 | Anthropic API key | Wrong/no key | **PASS** |
| A10 | systemd ProtectHome | Access /root from service | **PASS** |
| A11 | systemd ProtectSystem | Write to /etc, /usr, /var | **PASS** |
| A12 | File permission isolation | Read secrets as www-data | **PASS** |

**Score: 12/12 PASS**

---

## Test Details

### A1: HSM Credential Extraction

**Claim**: Credentials are extracted from SoftHSM2 at startup, not stored on disk.

**Method**:
1. Delete `/opt/lobsec/.openclaw/.env`
2. Restart service
3. Verify `.env` is recreated with all 4 keys

**Result**: PASS
- `.env` was missing before start
- `ExecStartPre` ran `hsm-extract-credentials.sh`
- `.env` recreated with `TELEGRAM_BOT_TOKEN`, `OPENCLAW_GATEWAY_TOKEN`, `OLLAMA_API_KEY`, `ANTHROPIC_API_KEY`
- CF-Access headers injected into `openclaw.json` from HSM

**How to reproduce**:
```bash
systemctl stop lobsec
rm /opt/lobsec/.openclaw/.env
systemctl start lobsec
ls -la /opt/lobsec/.openclaw/.env  # should exist, mode 600
grep -c 'TOKEN\|KEY' /opt/lobsec/.openclaw/.env  # should be 4
```

---

### A2: Credential Wipe on Stop

**Claim**: All runtime secrets are wiped from disk when the service stops.

**Method**:
1. Verify `.env` exists and config has real CF-Access headers while running
2. Stop service
3. Verify `.env` deleted and config headers replaced with placeholders

**Result**: PASS
- Before stop: `.env` exists (660 bytes), CF-Access-Client-Secret = real value
- After stop: `.env` gone, CF-Access-Client-Secret = "HSM-INJECTED-AT-STARTUP"

**How to reproduce**:
```bash
# While running:
cat /opt/lobsec/.openclaw/.env         # real credentials
grep CF-Access /opt/lobsec/.openclaw/openclaw.json  # real values

systemctl stop lobsec

cat /opt/lobsec/.openclaw/.env         # "No such file or directory"
grep CF-Access /opt/lobsec/.openclaw/openclaw.json  # "HSM-INJECTED-AT-STARTUP"
```

---

### A3: HSM PIN Enforcement

**Claim**: Without the correct HSM PIN, the service cannot start.

**Method**:
1. Replace PIN in `pin.env` with wrong value
2. Restart service
3. Verify service fails at ExecStartPre

**Result**: PASS
- `pkcs11-tool` failed: `EVP_DecryptFinal failed`
- Service exited with status 1 (FAILURE)
- Service entered restart loop, never reached gateway start
- Wipe script ran on each failed attempt (defense in depth)

**How to reproduce**:
```bash
cp /opt/lobsec/hsm/pin.env /opt/lobsec/hsm/pin.env.backup
echo 'LOBSEC_HSM_PIN=999999' > /opt/lobsec/hsm/pin.env
chown lobsec:lobsec /opt/lobsec/hsm/pin.env
chmod 600 /opt/lobsec/hsm/pin.env
systemctl restart lobsec  # will fail
journalctl -u lobsec -n 5  # "EVP_DecryptFinal failed"

# RESTORE:
cp /opt/lobsec/hsm/pin.env.backup /opt/lobsec/hsm/pin.env
chown lobsec:lobsec /opt/lobsec/hsm/pin.env
chmod 600 /opt/lobsec/hsm/pin.env
systemctl restart lobsec
```

---

### A4: Loopback Binding

**Claim**: Gateway is only reachable from 127.0.0.1, not the network.

**Method**:
1. curl gateway from 127.0.0.1 (should succeed)
2. curl gateway from LAN IP <server-host> (should fail)

**Result**: PASS
- `127.0.0.1:18789` -> HTTP 200
- `<server-host>:18789` -> HTTP 000, exit code 7 (connection refused)

**How to reproduce**:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18789/__openclaw__/health      # 200
curl -s -o /dev/null -w "%{http_code}\n" http://<server-host>:18789/__openclaw__/health    # 000
```

---

### A5: Gateway Auth (Challenge-Response)

**Claim**: Unauthenticated clients cannot issue commands through the gateway.

**Initial finding**: WebSocket TCP connections succeed from loopback without a token.

**Deeper investigation**: OpenClaw uses a 2-layer auth model:
1. **Network layer**: Loopback binding restricts who can connect (A4)
2. **Protocol layer**: After WS connects, gateway sends `connect.challenge` with a nonce.
   Client must complete challenge-response with valid auth token.
   Sending any other message -> code 1008 "invalid request frame" -> disconnected.

**Design rationale** (confirmed in source, `gateway-cli-BgGtcRFQ.js:15330`):
Auth is only _required_ when binding to non-loopback addresses. On loopback,
the binding itself is the trust boundary. Protocol-level challenge-response
still enforces auth after connection.

**Result**: PASS (2-layer auth confirmed)

**How to reproduce**:
```javascript
// node -e (from /opt/lobsec/openclaw)
const WebSocket = require('./node_modules/ws');
const c = new WebSocket('ws://127.0.0.1:18789/');
c.on('open', () => {
  c.send(JSON.stringify({ type: 'agent.run', payload: { message: 'test' } }));
});
c.on('message', (d) => console.log('recv:', d.toString().substring(0,200)));
// Output: connect.challenge nonce, then code=1008 disconnect
c.on('close', (code, reason) => console.log('closed:', code, reason.toString()));
```

---

### A6: Sandbox Enforcement

**Claim**: Agent executes in a sandboxed workspace, not the host filesystem.

**Method**:
1. Ask agent to read `/etc/shadow` via exec tool
2. Verify sandbox metadata in response

**Result**: PASS
- `sandbox: { "mode": "all", "sandboxed": true }`
- `workspaceDir: /opt/lobsec/.openclaw/sandboxes/agent-main-<hash>`
- Sandbox directory contains only workspace files (AGENTS.md, SOUL.md, etc.)
- No `/etc/shadow` exists in sandbox
- Agent workspace is isolated copy, not the host filesystem

**How to reproduce**:
```bash
ls /opt/lobsec/.openclaw/sandboxes/agent-main-*/etc/shadow  # "No such file or directory"
ls /opt/lobsec/.openclaw/sandboxes/agent-main-*/              # Only workspace files
```

---

### A7: Ollama API Key Invalidation

**Claim**: Remote GPU Ollama rejects requests with wrong/missing API key.

**Method**: curl Ollama `/api/version` with correct key, wrong key, no key.

**Result**: PASS
- Correct key: HTTP 200
- Wrong key: HTTP 401 `{"error": "Unauthorized"}`
- No key: HTTP 401 `{"error": "Unauthorized"}`

**How to reproduce**:
```bash
curl -H "Authorization: Bearer WRONG" http://<remote-gpu-host>:11435/api/version  # 401
curl http://<remote-gpu-host>:11435/api/version  # 401
```

---

### A8: CF-Access Header Removal

**Claim**: Jetson is unreachable without valid Cloudflare Access service token.

**Method**: curl Jetson with correct headers, wrong headers, no headers.

**Result**: PASS
- Correct headers: HTTP 200
- Wrong headers: HTTP 403 `"Forbidden. You don't have permission to view this."`
- No headers: HTTP 403 `"Forbidden. You don't have permission to view this."`

**How to reproduce**:
```bash
curl https://llm.<your-domain>/api/version  # 403
curl -H "CF-Access-Client-Id: FAKE" -H "CF-Access-Client-Secret: FAKE" \
  https://llm.<your-domain>/api/version  # 403
```

---

### A9: Anthropic API Key Invalidation

**Claim**: Claude API rejects requests with wrong/missing API key.

**Method**: POST to `/v1/messages` with correct key, wrong key, no key.

**Result**: PASS
- Correct key: HTTP 200
- Wrong key: HTTP 401 `"invalid x-api-key"`
- No key: HTTP 401 `"x-api-key header is required"`

**How to reproduce**:
```bash
curl -H "x-api-key: WRONG" -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-haiku-4-5-20251001","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}' \
  https://api.anthropic.com/v1/messages  # 401
```

---

### A10: systemd ProtectHome

**Claim**: Service process cannot access /root or /home.

**Method**: Use `nsenter` to enter the service mount namespace and list /root.

**Result**: PASS
- `/root/` is an empty `d---------` directory (permissions: no access)
- `/home/` is an empty `d---------` directory
- `/root/.openclaw/` does not exist in the service namespace

**How to reproduce**:
```bash
PID=$(systemctl show lobsec -p MainPID --value)
nsenter -t $PID -m -- ls -la /root/      # Empty, d---------
nsenter -t $PID -m -- ls /root/.openclaw  # "No such file or directory"
```

---

### A11: systemd ProtectSystem=strict

**Claim**: Service can only write to explicitly allowed paths.

**Method**: From service namespace, attempt to write to /etc, /usr, /var, and allowed paths.

**Result**: PASS

| Path | Write | Result |
|------|-------|--------|
| /etc | Blocked | "Read-only file system" |
| /usr | Blocked | "Read-only file system" |
| /var | Blocked | "Read-only file system" |
| /opt/lobsec/.openclaw | Allowed | Write succeeded |
| /tmp/openclaw-&lt;uid&gt; | Allowed | Write succeeded |

**How to reproduce**:
```bash
PID=$(systemctl show lobsec -p MainPID --value)
nsenter -t $PID -m -- sh -c 'touch /etc/test 2>&1'   # "Read-only file system"
nsenter -t $PID -m -- sh -c 'touch /opt/lobsec/.openclaw/test && rm /opt/lobsec/.openclaw/test && echo ok'  # ok
```

---

### A12: File Permission Isolation

**Claim**: Other system users cannot read lobsec secrets.

**Method**: Attempt to read all secret files as `www-data` and `nobody`.

**Result**: PASS

| File | www-data | nobody |
|------|----------|--------|
| .env | Permission denied | Permission denied |
| pin.env | Permission denied | Permission denied |
| openclaw.json | Permission denied | Permission denied |
| hsm/tokens/ | Permission denied | Permission denied |
| /opt/lobsec/ (listing) | Permission denied | Permission denied |

**How to reproduce**:
```bash
sudo -u www-data cat /opt/lobsec/.openclaw/.env   # Permission denied
sudo -u nobody ls /opt/lobsec/                      # Permission denied
```

---

## Security Architecture Validated

```
Internet
    |
    | (only SSH:22 exposed)
    v
[Cloudflare Tunnel] --- port 3000 (if needed)
    |
    v
[lobsec systemd service]
    |  User: lobsec (dedicated UID, no shell)
    |  ProtectHome=true (/root invisible)
    |  ProtectSystem=strict (/etc,/usr,/var read-only)
    |  CapabilityBoundingSet= (empty)
    |  NoNewPrivileges=true
    |
    +-- ExecStartPre: HSM extract -> .env + config injection
    |
    +-- [OpenClaw Gateway] ws://127.0.0.1:18789
    |       |  bind=loopback (A4: unreachable from LAN)
    |       |  challenge-response auth (A5: protocol enforcement)
    |       |  sandbox=all (A6: agent isolation)
    |       |
    |       +-- Telegram (@your_bot, long-polling)
    |       +-- Remote GPU (sovereign, API key auth: A7)
    |       +-- Jetson (sovereign, CF-Access: A8)
    |       +-- Claude (public cloud, API key: A9)
    |
    +-- ExecStopPost: wipe .env + config headers (A2)

HSM: SoftHSM2 PKCS#11 (A1: extraction, A3: PIN enforcement)
Files: mode 600, lobsec:lobsec (A12: user isolation)
```

## Re-running These Tests

All tests can be re-run independently. The destructive tests (A1-A3) require
service restarts but are self-restoring. Tests A4-A12 are non-destructive
and can run while the service is active.

**Recommended cadence**: After any configuration change, service upgrade,
or OpenClaw version update.
