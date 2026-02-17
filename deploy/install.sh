#!/usr/bin/env bash
# lobsec install script for Ubuntu 24.04
# Usage: sudo bash deploy/install.sh
set -euo pipefail

echo "=== lobsec installer ==="
echo "Target: Ubuntu 24.04 ($(uname -m))"

# Validate prerequisites
if ! grep -q "Ubuntu 24.04" /etc/os-release 2>/dev/null; then
  echo "WARNING: This script is designed for Ubuntu 24.04"
fi

# Install system dependencies
echo "--- Installing system dependencies ---"
apt-get update -qq
apt-get install -y -qq \
  curl \
  gnupg \
  softhsm2 \
  fscrypt \
  cryptsetup \
  nftables \
  age

# Install Node.js 22
if ! command -v node &>/dev/null || ! node --version | grep -q "v22"; then
  echo "--- Installing Node.js 22 ---"
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi

# Install pnpm
if ! command -v pnpm &>/dev/null; then
  echo "--- Installing pnpm ---"
  npm install -g pnpm@9
fi

# Install Docker (rootless)
if ! command -v docker &>/dev/null; then
  echo "--- Installing Docker ---"
  curl -fsSL https://get.docker.com | sh
  echo "NOTE: Configure Docker rootless mode manually:"
  echo "  dockerd-rootless-setuptool.sh install"
fi

# Initialize SoftHSM2
echo "--- Initializing SoftHSM2 ---"
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "lobsec"; then
  HSM_PIN=$(openssl rand -hex 16)
  HSM_SO_PIN=$(openssl rand -hex 16)
  softhsm2-util --init-token --slot 0 --label "lobsec" --pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"
  echo ""
  echo "============================================================"
  echo "  SoftHSM2 initialized with RANDOM PINs"
  echo "  PIN:    $HSM_PIN"
  echo "  SO-PIN: $HSM_SO_PIN"
  echo ""
  echo "  RECORD THESE NOW. They will not be shown again."
  echo "  Store the PIN in /opt/lobsec/boot/pin.env as:"
  echo "    LOBSEC_HSM_PIN=$HSM_PIN"
  echo "============================================================"
  echo ""
fi

# Create lobsec directories
echo "--- Creating directory structure ---"
mkdir -p /etc/lobsec/{config,logs/audit,tmp}
chmod 700 /etc/lobsec
chmod 700 /etc/lobsec/tmp

# Build lobsec
echo "--- Building lobsec ---"
cd "$(dirname "$0")/.."
pnpm install --frozen-lockfile
pnpm build

echo ""
echo "=== Installation complete ==="
echo "Next steps:"
echo "  1. Set environment variables (see docs/setup.md)"
echo "  2. Run: lobsec init --dir /etc/lobsec"
echo "  3. Run: lobsec start --dir /etc/lobsec"
