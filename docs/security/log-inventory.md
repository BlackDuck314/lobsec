# Log Inventory

Complete inventory of all log sources in the lobsec deployment.

**Server**: `<hostname>` (Ubuntu 24.04+)
**Last audited**: 2026-02-25

## Log Sources

### 1. HSM Access Log

| | |
|---|---|
| **Path** | `/opt/lobsec/logs/hsm-access.log` |
| **Format** | JSON lines (one object per line) |
| **Written by** | `hsm-extract-credentials.sh`, `hsm-wipe-credentials.sh` |
| **Rotation** | Weekly, 52 weeks retention, compressed |
| **Permissions** | `0640 lobsec:lobsec` |

Tracks every credential extraction and wipe event. No secrets are logged — only labels and byte counts.

**Schema**:
```json
{
  "ts": "2026-02-25T10:07:55+00:00",
  "level": "INFO",
  "event": "extract_ok",
  "label": "telegram-bot-token",
  "detail": "bytes=46"
}
```

**Events**:
| Event | Meaning |
|-------|---------|
| `extraction_start` | HSM extraction script started (includes PID) |
| `extract_ok` | Single credential extracted successfully (includes label, byte count) |
| `extract_fail` | Single credential extraction failed (includes label, exit code) |
| `extraction_complete` | All credentials written to .env and config patched |
| `wipe_start` | Wipe script started (includes PID) |
| `wipe_complete` | .env deleted, config headers replaced with placeholders |

**Typical restart cycle** (10 lines):
```
wipe_start → wipe_complete → extraction_start → 6x extract_ok → extraction_complete
```

---

### 2. OpenClaw Gateway Log

| | |
|---|---|
| **Path** | `/opt/lobsec/logs/gateway/openclaw-YYYY-MM-DD.log` |
| **Symlink** | `/tmp/openclaw-<uid>` → `/opt/lobsec/logs/gateway/` |
| **Format** | JSON lines (OpenClaw internal format) |
| **Written by** | OpenClaw gateway process |
| **Rotation** | Daily, 30 days retention, compressed |
| **Permissions** | `0640 lobsec:lobsec` |

Primary operational log. Captures gateway startup, WebSocket connections, agent runs,
model provider calls, Telegram events, and errors.

**Schema**:
```json
{
  "0": "{\"subsystem\":\"gateway\"}",
  "1": "listening on ws://127.0.0.1:18789",
  "_meta": {
    "runtime": "node",
    "runtimeVersion": "22.22.0",
    "date": "2026-02-25T09:41:09.133Z",
    "logLevelId": 3,
    "logLevelName": "INFO",
    "path": {
      "filePath": "dist/entry.js",
      "fileLine": "2313"
    }
  },
  "time": "2026-02-25T09:41:09.134Z"
}
```

**Key fields**:
- `"0"` — Subsystem (`gateway`, `agents/model-providers`, `channels/telegram`, etc.)
- `"1"` — Human-readable message
- `_meta.logLevelName` — `INFO`, `WARN`, `ERROR`, `FATAL`
- `_meta.date` / `time` — ISO 8601 timestamps
- `_meta.path` — Source code location

**Note**: OpenClaw creates a new file per day and auto-prunes files older than 24 hours.
The logrotate config handles anything OpenClaw misses.

---

### 3. Config Audit Log

| | |
|---|---|
| **Path** | `/opt/lobsec/.openclaw/logs/config-audit.jsonl` |
| **Format** | JSON lines |
| **Written by** | OpenClaw config-io subsystem |
| **Rotation** | Weekly, 52 weeks retention, compressed (copytruncate) |
| **Permissions** | `0640 lobsec:lobsec` |

Records every configuration file write with before/after hashes for tamper detection.

**Schema**:
```json
{
  "ts": "2026-02-24T14:37:31.107Z",
  "source": "config-io",
  "event": "config.write",
  "configPath": "/opt/lobsec/.openclaw/openclaw.json",
  "pid": 368926,
  "ppid": 368917,
  "previousHash": "e3b0c44...",
  "nextHash": "ba6b827...",
  "previousBytes": null,
  "nextBytes": 354,
  "suspicious": [],
  "result": "rename"
}
```

**Key fields**:
- `previousHash` / `nextHash` — SHA-256 of config before and after (tamper detection)
- `pid` / `ppid` — Process lineage (who made the change)
- `argv` — Full command line of the process
- `suspicious` — Array of flagged changes (empty = clean)

---

### 4. systemd Journal

| | |
|---|---|
| **Access** | `journalctl -u lobsec` |
| **Format** | systemd structured journal |
| **Written by** | All service stdout/stderr |
| **Rotation** | 500 MB max, 30-day retention (`/etc/systemd/journald.conf.d/lobsec.conf`) |
| **Size** | ~16 MB (after vacuum policy applied) |

Captures everything the service prints to stdout/stderr, including:
- HSM extraction script output
- Gateway startup messages
- Node.js runtime errors
- Service lifecycle events (start, stop, restart, crash)

**Filter examples**:
```bash
# Last 50 lines
journalctl -u lobsec -n 50 --no-pager

# Since last boot
journalctl -u lobsec -b

# Errors only
journalctl -u lobsec -p err

# Time range
journalctl -u lobsec --since "2026-02-25 09:00" --until "2026-02-25 10:00"
```

---

### 5. System Auth Log

| | |
|---|---|
| **Path** | `/var/log/auth.log` |
| **Format** | Syslog text |
| **Written by** | PAM, sshd, sudo |
| **Rotation** | System default (logrotate) |
| **Size** | ~204 KB |

Records SSH logins, sudo usage, and PAM authentication events.
Not lobsec-specific but relevant for auditing who accessed the server.

---

### 6. System Syslog

| | |
|---|---|
| **Path** | `/var/log/syslog` |
| **Format** | Syslog text |
| **Written by** | All system services |
| **Rotation** | System default (logrotate) |
| **Size** | ~456 KB |

General system log. Includes lobsec service events forwarded from the journal.

---

## Log Flow

```
                    lobsec systemd service
                           |
          +----------------+----------------+
          |                |                |
    ExecStartPre     Main Process     ExecStopPost
   (HSM extract)    (OpenClaw GW)    (HSM wipe)
          |                |                |
          v                v                v
   hsm-access.log   gateway log      hsm-access.log
   (JSON lines)     (JSON lines)     (JSON lines)
          |                |                |
          |                +---> config-audit.jsonl
          |                |     (config changes)
          |                |
          +-------+--------+
                  |
                  v
          systemd journal
          (all stdout/stderr)
                  |
                  v
            /var/log/syslog
```

## Retention Summary

| Log | Rotation | Retention | Storage |
|-----|----------|-----------|---------|
| HSM access | Weekly | 52 weeks | `/opt/lobsec/logs/` |
| Gateway | Daily | 30 days | `/opt/lobsec/logs/gateway/` |
| Config audit | Weekly | 52 weeks | `/opt/lobsec/.openclaw/logs/` |
| systemd journal | By disk/age | 500 MB / 30 days | `/var/log/journal/` |
| auth.log | System | System default | `/var/log/` |
| syslog | System | System default | `/var/log/` |

## Querying Logs

**"When was the last HSM extraction?"**
```bash
grep extract_ok /opt/lobsec/logs/hsm-access.log | tail -6
```

**"Did any extraction fail?"**
```bash
grep extract_fail /opt/lobsec/logs/hsm-access.log
```

**"What did the gateway do in the last hour?"**
```bash
journalctl -u lobsec --since "1 hour ago" --no-pager
```

**"Was the config tampered with?"**
```bash
cat /opt/lobsec/.openclaw/logs/config-audit.jsonl | jq 'select(.suspicious | length > 0)'
```

**"Which models were called?"**
```bash
grep model-providers /opt/lobsec/logs/gateway/openclaw-$(date +%Y-%m-%d).log | jq -r '."1"'
```

**"Who SSH'd into the server?"**
```bash
grep sshd /var/log/auth.log | grep Accepted
```
