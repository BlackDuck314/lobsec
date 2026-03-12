#!/bin/bash
# deploy.sh — Deploy Ninja Scraper to production
# Run as root from the lobsec repository root.
#
# Steps:
#   1. Create Python venv at /opt/lobsec/scraper-venv/
#   2. Install dependencies (crawlee, patchright, fastapi, etc.)
#   3. Install Patchright Chromium browser
#   4. Deploy package code to /opt/lobsec/scraper/
#   5. Generate and store auth token in HSM (if not already present)
#   6. Create systemd unit file
#   7. Start and verify
#
# Prerequisites:
#   - Python 3.13 installed
#   - SoftHSM2 configured at /opt/lobsec/boot/softhsm2.conf
#   - HSM PIN at /opt/lobsec/boot/pin.env
#   - System deps: libgbm1 libasound2t64 libatk-bridge2.0-0 libdrm2 libxkbcommon0
#                  libxcomposite1 libxdamage1 libxrandr2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SCRAPER_VENV=/opt/lobsec/scraper-venv
SCRAPER_DIR=/opt/lobsec/scraper
BROWSERS_DIR=$SCRAPER_VENV/browsers
ENV_FILE=/opt/lobsec/.env
SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so
HSM_CONF=/opt/lobsec/boot/softhsm2.conf
HSM_PIN=$(grep LOBSEC_HSM_PIN /opt/lobsec/boot/pin.env | cut -d= -f2)

echo "=== Ninja Scraper Deployment ==="

# Step 1: Create Python venv
if [ ! -d "$SCRAPER_VENV" ]; then
    echo "Step 1: Creating Python venv..."
    sudo -u lobsec python3.13 -m venv "$SCRAPER_VENV"
    sudo -u lobsec "$SCRAPER_VENV/bin/pip" install --upgrade pip
else
    echo "Step 1: Python venv already exists, skipping."
fi

# Step 2: Install dependencies
echo "Step 2: Installing dependencies..."
sudo -u lobsec "$SCRAPER_VENV/bin/pip" install --quiet \
    'crawlee[playwright]' patchright fastapi 'uvicorn[standard]' \
    pyyaml httpx tenacity structlog 'pydantic>=2.0'

# Step 3: Install Patchright Chromium
if [ ! -d "$BROWSERS_DIR"/chromium-* ]; then
    echo "Step 3: Installing Patchright Chromium..."
    sudo -u lobsec mkdir -p "$BROWSERS_DIR"
    PLAYWRIGHT_BROWSERS_PATH="$BROWSERS_DIR" sudo -u lobsec -E \
        "$SCRAPER_VENV/bin/patchright" install chromium
else
    echo "Step 3: Patchright Chromium already installed, skipping."
fi

# Step 4: Deploy package code
echo "Step 4: Deploying package code..."
sudo mkdir -p "$SCRAPER_DIR"
sudo cp -r "$REPO_ROOT/packages/scraper/src/ninja_scraper" "$SCRAPER_DIR/"
sudo cp -r "$REPO_ROOT/packages/scraper/missions" "$SCRAPER_DIR/"
sudo chown -R lobsec:lobsec "$SCRAPER_DIR"

# Step 5: Generate and store auth token in HSM
if ! SOFTHSM2_CONF="$HSM_CONF" pkcs11-tool --module "$SOFTHSM_LIB" \
    --token-label lobsec --pin "$HSM_PIN" \
    --list-objects --type data 2>/dev/null | grep -q "scraper-auth-token"; then
    echo "Step 5: Generating and storing auth token in HSM..."
    SCRAPER_TOKEN=$(openssl rand -hex 32)
    echo -n "$SCRAPER_TOKEN" > /tmp/scraper-token.bin
    SOFTHSM2_CONF="$HSM_CONF" pkcs11-tool --module "$SOFTHSM_LIB" \
        --token-label lobsec --pin "$HSM_PIN" \
        --write-object /tmp/scraper-token.bin \
        --type data --label scraper-auth-token --id 0E
    rm -f /tmp/scraper-token.bin
    chown -R lobsec:lobsec /opt/lobsec/hsm/tokens/
    grep -q '^SCRAPER_AUTH_TOKEN=' "$ENV_FILE" 2>/dev/null \
        || echo "SCRAPER_AUTH_TOKEN=$SCRAPER_TOKEN" >> "$ENV_FILE"
else
    echo "Step 5: Auth token already in HSM, skipping."
fi

# Step 6: Create systemd unit (always overwrite to pick up changes)
echo "Step 6: Creating systemd unit..."
cat > /etc/systemd/system/lobsec-scraper.service <<'UNIT'
[Unit]
Description=Ninja Scraper - lobsec web scraping engine
After=network.target lobsec.service
Wants=lobsec.service

[Service]
Type=simple
User=lobsec
Group=lobsec
WorkingDirectory=/opt/lobsec/scraper

# Source .env for auth token, then start uvicorn
ExecStart=/bin/bash -c 'set -a; source /opt/lobsec/.env; set +a; exec /opt/lobsec/scraper-venv/bin/uvicorn ninja_scraper.api.main:app --host 127.0.0.1 --port 18791'

Restart=on-failure
RestartSec=10

# Environment
Environment=PYTHONPATH=/opt/lobsec/scraper
Environment=MISSIONS_DIR=/opt/lobsec/scraper/missions
Environment=PLAYWRIGHT_BROWSERS_PATH=/opt/lobsec/scraper-venv/browsers
Environment=CRAWLEE_STORAGE_DIR=/opt/lobsec/data/raw/crawlee-storage
Environment=SOFTHSM2_CONF=/opt/lobsec/boot/softhsm2.conf

# Hardening (same as other lobsec services)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/lobsec/data /opt/lobsec/scraper-venv /opt/lobsec/logs
PrivateTmp=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT

# Step 7: Start and verify
echo "Step 7: Starting and verifying..."
systemctl daemon-reload
systemctl enable lobsec-scraper
systemctl restart lobsec-scraper
sleep 3

# Ensure raw data output directories exist
sudo -u lobsec mkdir -p /opt/lobsec/data/raw/{dld-sales,ejari-rentals,building-permits,adrec-abu-dhabi,bayut-listings,propertyfinder-listings,dewa-connections,crawlee-storage}

# Health check
if curl -sf http://127.0.0.1:18791/health | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['status'] == 'ok' and d['missions_loaded'] == 7
print(f'Scraper healthy: {d}')
"; then
    echo "=== Deployment successful ==="
else
    echo "=== Deployment FAILED — check journalctl -u lobsec-scraper ==="
    exit 1
fi
