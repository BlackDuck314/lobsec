# Phase 8 Deployment Artifacts

This file tracks deployment artifacts created outside the git repository.

## Created Files

### /opt/lobsec/bin/collect.sh
**Created:** 2026-03-13 (Plan 08-03 Task 2)
**Owner:** lobsec:lobsec
**Permissions:** 755 (executable)
**Purpose:** Standalone orchestrator script for UAE RE collection
**Usage:** `collect.sh weekly|monthly|quarterly|{source-name}`

**Features:**
- Sources /opt/lobsec/.env for environment variables
- Verifies Ninja Scraper is running (curl http://127.0.0.1:18791/health)
- Calls Node.js CLI: `node /opt/lobsec/plugins/lobsec-uae-re/dist/cli.js run-frequency $FREQUENCY` or `run-one $SOURCE`
- Logs start/end timestamps to /opt/lobsec/logs/collection.log
- Returns exit code from Node CLI (0=success, 1=failure)

**Trigger chain:** systemd timer → collect.sh → Node CLI → CollectorRegistry → Ninja Scraper → Python normalization → Telegram summary
