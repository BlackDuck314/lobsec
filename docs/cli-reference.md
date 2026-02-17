# lobsec CLI Reference

## Commands

### `lobsec init`

Initialize lobsec configuration in a directory.

```bash
lobsec init [--dir /etc/lobsec] [--force]
```

Options:
- `--dir <path>` — Base directory (default: `/etc/lobsec`)
- `--force` — Overwrite existing configuration

Creates: `config/lobsec.json`, `config/auth-profiles/`, directory structure.

### `lobsec start`

Start lobsec security hardening.

```bash
lobsec start [--dir /etc/lobsec] [--skip-firewall] [--dry-run]
```

Startup sequence:
1. Load and validate config
2. Check for configuration drift
3. Generate nftables rules
4. Start audit logger
5. Save running state

Options:
- `--dir <path>` — Base directory (default: `/etc/lobsec`)
- `--skip-firewall` — Skip nftables rule application
- `--dry-run` — Show what would be done without applying

### `lobsec stop`

Stop lobsec and clean up.

```bash
lobsec stop [--dir /etc/lobsec]
```

Shutdown sequence:
1. Stop containers (gateway → proxy → caddy)
2. Destroy tmpfs credentials
3. Lock fscrypt directories
4. Close HSM session
5. Update state file

### `lobsec status`

Show current system status.

```bash
lobsec status [--dir /etc/lobsec] [--json]
```

### `lobsec logs`

View and manage audit logs.

```bash
lobsec logs [--dir /etc/lobsec] [--level INFO] [--follow] [--verify] [--export <path>]
```

Options:
- `--level <level>` — Minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL)
- `--follow` — Follow new log entries
- `--verify` — Verify hash chain integrity
- `--export <path>` — Export logs to file

## Routing Commands

### `/sovereign`

Switch session to sovereign mode. All LLM requests go to local inference only.

### `/public`

Switch session to public mode. LLM requests go to cloud APIs with sovereign fallback.

## Global Options

- `--json` — Output in JSON format
- `--verbose` — Enable verbose logging
