# lobsec Setup Guide

## Prerequisites

- Ubuntu 24.04 LTS (x86_64 or ARM64 for Jetson Orin)
- Node.js 22 LTS
- pnpm 9+
- Docker (rootless mode)
- SoftHSM2 (dev) or YubiHSM2 (prod)

## Quick Start

```bash
# Clone
git clone https://github.com/BlackDuck314/lobsec.git
cd lobsec

# Install dependencies
pnpm install

# Build
pnpm build

# Run tests
pnpm test

# Initialize
lobsec init --dir /etc/lobsec

# Start
lobsec start --dir /etc/lobsec
```

## HSM Setup

### SoftHSM2 (Development)

```bash
apt install softhsm2
HSM_PIN=$(openssl rand -hex 16)
HSM_SO_PIN=$(openssl rand -hex 16)
softhsm2-util --init-token --slot 0 --label "lobsec" --pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"
echo "Record these PINs — they will not be shown again."

export LOBSEC_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export LOBSEC_HSM_PIN=$HSM_PIN  # save to /opt/lobsec/boot/pin.env for systemd
```

### YubiHSM2 (Production)

```bash
apt install yubihsm-shell
# Configure via yubihsm-connector
export LOBSEC_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
export LOBSEC_HSM_PIN=<production-pin>
```

## Encryption Setup

### LUKS2

```bash
# Create encrypted volume
cryptsetup luksFormat --type luks2 \
  --cipher aes-xts-plain64 --key-size 512 \
  --hash sha256 --pbkdf argon2id \
  --pbkdf-memory 1048576 /dev/sdX

cryptsetup luksOpen /dev/sdX lobsec-data
```

### fscrypt

```bash
fscrypt setup /mnt/lobsec-data
fscrypt encrypt /mnt/lobsec-data/workspace
fscrypt encrypt /mnt/lobsec-data/agents
fscrypt encrypt /mnt/lobsec-data/logs
fscrypt encrypt /mnt/lobsec-data/canvas
```

## Docker Rootless Setup

```bash
dockerd-rootless-setuptool.sh install
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock
```

## Jetson Orin Setup

Additional steps for NVIDIA Jetson Orin:
- Install NVIDIA Container Toolkit
- Configure Ollama with GPU access
- Set up Cloudflare Access tunnel for remote management

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `LOBSEC_PKCS11_MODULE` | Path to PKCS#11 shared library | Yes |
| `LOBSEC_HSM_PIN` | HSM PIN | Yes |
| `LOBSEC_PROXY_TOKEN` | Internal proxy authentication token | Yes |
| `ANTHROPIC_API_KEY` | Anthropic API key (cloud mode) | For cloud |
| `OPENAI_API_KEY` | OpenAI API key (cloud mode) | For cloud |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | For Telegram |
| `TELEGRAM_WEBHOOK_SECRET` | Telegram webhook secret | For Telegram |
