# Phase 6 Plan 03 Summary: Deployment & Integration

**Status**: ⚠️ CHECKPOINT — Awaiting human verification
**Date**: 2026-03-11
**Phase**: 06-foundation-infrastructure
**Plan**: 03 (Deployment & Integration)

## Objective

Wire the OpenClaw plugin, create CLI for systemd orchestrator, deploy to production with fscrypt encryption and Python venv.

## Tasks Completed

### Task 1: Create OpenClaw plugin entry point and CLI orchestrator ✅

**Files Modified**:
- `packages/uae-re/src/index.ts` — Added plugin registration with `uae_collection_status` tool
- `packages/uae-re/src/cli.ts` — Created CLI with run-all, run-frequency, run-one, check-deps, init-db commands
- `packages/uae-re/package.json` — Added bin entry and cli script

**Plugin Entry Point**:
- Exports default object with `id: 'lobsec-uae-re'` and `register(api: PluginApi)` function
- Initializes database with `initDatabase(dataDir)`
- Creates `CollectorRegistry` and `IntelligenceCache` instances
- Registers `uae_collection_status` tool:
  - Queries `collection_log` table for all registered collectors
  - Formats status as text table (source, frequency, priority, last run, row count, duration, errors)
  - Returns helpful message when no collectors registered yet (Phase 7+)

**CLI Orchestrator**:
- Commands: `run-all`, `run-frequency <freq>`, `run-one <source>`, `check-deps`, `init-db`
- Exit code 0/1 based on success/failure
- Proper error handling with try/catch and stderr output
- Shebang preserved in compiled output: `#!/usr/bin/env node`

**Commit**: `eb8f105` — feat(uae-re): add OpenClaw plugin entry point and CLI orchestrator

### Task 2: Deploy to production ✅

**1. fscrypt encryption on /opt/lobsec/data/**:
- Created empty directory `/opt/lobsec/data`
- Encrypted with `fscrypt encrypt --key=/opt/lobsec/boot/fscrypt-key.bin --source=raw_key --name=lobsec-data`
- Policy: `b5edf2d44dd7785f8462786d0963af15`
- Options: `padding:32 contents:AES-256-XTS filenames:AES_256_CTS policy_version:2`
- Protector: `50ad3dee3205c11a` (raw key protector "lobsec-data")
- Status: Unlocked and ready for use
- Created subdirectory: `/opt/lobsec/data/raw/` for collector outputs

**2. Python 3.13 venv at /opt/lobsec/analytics-venv/**:
- Created venv: `python3 -m venv /opt/lobsec/analytics-venv`
- Upgraded pip to 26.0.1
- Installed all packages from `requirements.txt`:
  - pandas==2.2.3
  - statsmodels==0.14.6 (corrected from 0.15.0 which doesn't exist)
  - scipy==1.15.0
  - numpy==2.2.1
  - pdfplumber==0.11.4
  - vaderSentiment==3.3.2
  - praw==7.8.1
  - pytrends==4.9.2
  - pytest==8.3.0
- All packages verified importable

**3. Plugin deployed at /opt/lobsec/plugins/lobsec-uae-re/**:
- Copied dist/, python/, package.json from source
- Installed node_modules with `npm install` (after fixing workspace: protocol to file: protocol)
- Rebuilt better-sqlite3 native addon with `npm rebuild better-sqlite3`
- Copied @lobsec/shared package to `/opt/lobsec/plugins/lobsec-shared/` (dependency)
- Created `openclaw.plugin.json` manifest:
  ```json
  {
    "id": "lobsec-uae-re",
    "name": "UAE Real Estate Intelligence",
    "description": "Data collection, normalization, statistical analysis, and intelligence products for UAE real estate market monitoring.",
    "version": "0.1.0",
    "configSchema": { "type": "object", "additionalProperties": false, "properties": {} }
  }
  ```
- Created root-level `index.js` that re-exports from `./dist/index.js` (OpenClaw convention)
- Set ownership: `chown -R lobsec:lobsec /opt/lobsec/plugins/lobsec-uae-re/`

**4. CLI tested successfully**:
- `check-deps`: ✅ Python 3.13.3 OK, all packages OK
- `init-db`: ✅ Database created at `/opt/lobsec/data/uae-re.db`
- Database verified:
  - WAL mode enabled
  - 4 tables: `raw_sources`, `normalized_monthly`, `intelligence_cache`, `collection_log`

**5. systemd service created**:
- `/etc/systemd/system/lobsec-uae-collector.service`:
  - Type: oneshot
  - ExecStart: `/usr/bin/node /opt/lobsec/plugins/lobsec-uae-re/dist/cli.js run-all`
  - TimeoutStartSec: 900s (15 minutes)
  - Sandboxing: ProtectSystem=strict, ProtectHome=yes, NoNewPrivileges=yes
  - ReadWritePaths: /opt/lobsec/data, /opt/lobsec/logs
- `/etc/systemd/system/lobsec-uae-collector.timer`:
  - Placeholder schedule: `OnCalendar=Mon *-*-* 02:00:00 Asia/Dubai`
  - Note: Actual frequencies will be configured in Phase 8
- Service tested: Runs successfully with 0 collectors (expected)

**6. HSM verified accessible**:
- Token directory exists: `/opt/lobsec/hsm/tokens/c45aed04-c3b7-3b55-82f8-d123f02c2e72/`
- SoftHSM config correct at `/opt/lobsec/boot/softhsm2.conf`
- Pattern established for future credential storage (no new keys in Phase 6)

**7. lobsec gateway operational**:
- Gateway restarted successfully
- Plugin deployment complete but **NOT yet registered in config** (see Checkpoint below)

**Commit**: `bcc2e8a` — fix(uae-re): correct statsmodels version in requirements.txt

## ⚠️ Checkpoint: Human Verification Required

**Status**: Plan marked `autonomous: false` with checkpoint at Task 3.

**What's Deployed**:
1. ✅ fscrypt encryption on /opt/lobsec/data/ (AES-256-XTS)
2. ✅ SQLite database with WAL mode and 4 tables
3. ✅ Python 3.13 venv with all analytics packages
4. ✅ Plugin deployed at /opt/lobsec/plugins/lobsec-uae-re/ with correct structure
5. ✅ CLI orchestrator working (check-deps, init-db, run-all tested)
6. ✅ systemd service created and functional
7. ⚠️  Gateway running but plugin NOT registered in config

**Why Plugin Not Registered**:
OpenClaw validates config on startup and rejects invalid configs. When I added lobsec-uae-re to `plugins.allow` and `plugins.entries`, OpenClaw validation failed with "plugin not found" because the plugin directory wasn't scanned yet (chicken-and-egg problem). The gateway would not start with the invalid config.

**Solution — Manual Config Update Required**:
The plugin files are deployed and verified to load correctly (`node -e "import('/opt/lobsec/plugins/lobsec-uae-re/index.js')"` succeeds). The config must be updated manually:

1. Edit `/opt/lobsec/.openclaw/openclaw.json` as lobsec user (or use `openclaw doctor`):
   - Add `"lobsec-uae-re"` to `plugins.allow` array
   - Add entry to `plugins.entries`:
     ```json
     "lobsec-uae-re": {
       "enabled": true
     }
     ```
   - Add `"uae_collection_status"` to `tools.sandbox.tools.allow` array

2. Restart gateway:
   ```bash
   sudo systemctl restart lobsec
   ```

3. Verify plugin loads:
   ```bash
   sudo journalctl -u lobsec --since "1 min ago" | grep "lobsec-uae-re"
   # Should show: [lobsec-uae-re] registered 1 tool: uae_collection_status
   ```

4. Test tool via Telegram:
   ```
   @lobsec_bot show collection status
   ```
   Should respond: "No collectors registered yet. Collectors will be added in Phase 7+."

**Verification Commands**:
```bash
# 1. Check fscrypt
fscrypt status /opt/lobsec/data
# Expected: "encrypted with fscrypt", policy shows AES_256_XTS

# 2. Check database
sudo -u lobsec sqlite3 /opt/lobsec/data/uae-re.db ".tables"
# Expected: collection_log  intelligence_cache  normalized_monthly  raw_sources

sudo -u lobsec sqlite3 /opt/lobsec/data/uae-re.db "PRAGMA journal_mode;"
# Expected: wal

# 3. Check Python venv
sudo -u lobsec /opt/lobsec/analytics-venv/bin/python3 --version
# Expected: Python 3.13.3

sudo -u lobsec /opt/lobsec/analytics-venv/bin/python3 -c "import pandas, statsmodels, scipy, numpy, pdfplumber, vaderSentiment, praw, pytrends; print('All packages OK')"
# Expected: All packages OK

# 4. Check CLI
sudo -u lobsec /usr/bin/node /opt/lobsec/plugins/lobsec-uae-re/dist/cli.js check-deps
# Expected: Python: OK (Python 3.13.3) ... All dependencies satisfied.

# 5. Check systemd service
systemctl status lobsec-uae-collector.service
# Expected: inactive (dead) with recent "Ran 0 collectors" message

# 6. Check gateway
sudo systemctl status lobsec
# Expected: active (running)
```

## Files Created/Modified

**Source Files** (committed to git):
- packages/uae-re/src/index.ts (plugin entry point)
- packages/uae-re/src/cli.ts (CLI orchestrator)
- packages/uae-re/package.json (added bin + cli script)
- packages/uae-re/python/requirements.txt (fixed statsmodels version)

**Production Files** (deployed, not in git):
- /opt/lobsec/data/ (encrypted directory with raw/ subdirectory and uae-re.db)
- /opt/lobsec/analytics-venv/ (Python venv with 9 packages)
- /opt/lobsec/plugins/lobsec-uae-re/ (plugin deployment)
- /opt/lobsec/plugins/lobsec-shared/ (shared package dependency)
- /etc/systemd/system/lobsec-uae-collector.service
- /etc/systemd/system/lobsec-uae-collector.timer

**Config Files** (to be manually updated):
- /opt/lobsec/.openclaw/openclaw.json (needs plugin registration — see Checkpoint)

## Key Decisions

1. **fscrypt raw key protector**: Used same pattern as existing encrypted dirs (hsm, config, logs, .openclaw) with key at `/opt/lobsec/boot/fscrypt-key.bin`.

2. **statsmodels 0.14.6**: Version 0.15.0 doesn't exist; used latest available 0.14.6 instead.

3. **npm install with file: protocol**: pnpm workspace: protocol doesn't work in production; converted @lobsec/shared dependency to `file:../lobsec-shared`.

4. **Rebuilt better-sqlite3**: Native addon must be compiled for deployment environment; `npm rebuild better-sqlite3` after install.

5. **Root-level index.js**: OpenClaw plugin convention requires index.js at plugin root that re-exports from dist/ (same pattern as lobsec-tools and lobsec-security).

6. **openclaw.plugin.json**: Required manifest file for plugin discovery (wasn't documented in plan but discovered by checking existing plugins).

7. **Plugin not in config**: Left plugin out of config due to validation chicken-and-egg problem; requires manual registration (documented in checkpoint).

## Next Steps

1. **Human verification**: User updates OpenClaw config to register plugin and tests tool via Telegram.

2. **Phase 6 remaining plans**: Continue with any additional plans in Phase 6 (check ROADMAP.md).

3. **Phase 7 MVP Collection**: Once foundation verified, implement Tier A collectors (DLD, REIDIN, Property Finder, Bayut, Dubizzle, + DEWA).

## Lessons Learned

- OpenClaw validates config before loading plugins, creating a chicken-and-egg problem for new plugin registration.
- Plugin manifest (`openclaw.plugin.json`) is required but not explicitly documented in OpenClaw plugin docs.
- Native Node.js addons (like better-sqlite3) must be rebuilt in deployment environment even when copying node_modules.
- pnpm workspace protocol doesn't work outside workspace; must use file: protocol or npm pack/install for production deployment.
