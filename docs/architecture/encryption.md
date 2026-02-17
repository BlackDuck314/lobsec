# Encryption Architecture -- lobsec

> **Date:** 2026-02-24
> **Status:** DESIGN DRAFT
> **Principle:** Every byte at rest is encrypted. Every byte in transit is encrypted. No exceptions.
> **Prerequisite:** `paranoid-isolation.md`, `security-layers.md`

---

## Table of Contents

1. [Encryption Posture Summary](#encryption-posture-summary)
2. [Part 1: At-Rest Encryption](#part-1-at-rest-encryption)
3. [Part 2: In-Transit Encryption](#part-2-in-transit-encryption)
4. [Part 3: Certificate Management](#part-3-certificate-management)
5. [Part 4: Key Hierarchy](#part-4-key-hierarchy)
6. [Appendix A: LUKS Setup](#appendix-a-luks-setup)
7. [Appendix B: fscrypt Setup](#appendix-b-fscrypt-setup)
8. [Appendix C: Internal CA Generation](#appendix-c-internal-ca-generation)
9. [Appendix D: Caddyfile with TLS Modes](#appendix-d-caddyfile-with-tls-modes)

---

## Encryption Posture Summary

### Before lobsec (current OpenClaw)

| What | Encrypted? | Notes |
|------|-----------|-------|
| API keys on disk | NO | Plaintext `auth-profiles.json` |
| Session transcripts | NO | Plaintext `.jsonl` files |
| Workspace files | NO | User documents in plaintext |
| Audit logs | NO | Plaintext, unsigned |
| Config file | NO | Plaintext, contains auth tokens |
| Gateway ↔ Client | PARTIAL | Only if user configures TLS |
| Gateway ↔ LLM APIs | YES | HTTPS to cloud APIs |
| Gateway ↔ Ollama | NO | HTTP to local Ollama |

### After lobsec

| What | Encrypted? | Mechanism | Key Location |
|------|-----------|-----------|-------------|
| API keys | YES | HSM (PKCS#11) | HSM token (SoftHSM2/YubiHSM2) |
| Session transcripts | YES | fscrypt (file-level) | HSM-derived key |
| Workspace files | YES | fscrypt (file-level) | HSM-derived key |
| Audit logs | YES | fscrypt + HSM-signed | HSM-derived key + signing key |
| Config file | N/A | No secrets in config | Secrets in HSM, injected via env |
| Host disk | YES | LUKS2 (full-disk) | Passphrase or TPM2-sealed |
| Client ↔ Caddy | YES | TLS 1.3 | HSM or filesystem cert |
| Caddy ↔ Gateway | YES | mTLS | Internal CA in HSM |
| Gateway ↔ Proxy | YES | mTLS | Internal CA in HSM |
| Proxy ↔ Cloud APIs | YES | TLS 1.3 | Cloud CA (public PKI) |
| Proxy ↔ Jetson Ollama | YES | TLS or WireGuard | Pinned cert or WG key |
| Proxy ↔ Remote GPU | YES | WireGuard | WG key |

---

## Part 1: At-Rest Encryption

### 1.1 Layer 0: Full-Disk Encryption (LUKS2)

The foundation. If someone physically steals the disk, VM image, or Jetson Orin, they get nothing.

**LUKS2 configuration:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Cipher | `aes-xts-plain64` | Standard, hardware-accelerated (AES-NI on x86, ARMv8 CE on Jetson) |
| Key size | 512 bits (256 for AES-XTS) | Maximum for XTS mode |
| Hash | `argon2id` | LUKS2 default, memory-hard KDF |
| Argon2id memory | 1 GiB | Resist GPU cracking |
| Argon2id iterations | 4 | Balance security/boot time |
| Integrity | `hmac-sha256` | Optional authenticated encryption (dm-integrity) |

**Unlock strategies by environment:**

| Environment | Strategy | Notes |
|-------------|----------|-------|
| **Development** | Passphrase on boot | Manual entry, simplest |
| **Production (x86)** | TPM2-sealed + passphrase fallback | `systemd-cryptenroll --tpm2-device=auto` |
| **Jetson Orin** | Passphrase or TPM2 if available | `[NEEDS VERIFICATION]` Jetson TPM2 support |
| **VPS/Cloud** | Passphrase via SSH (dropbear-initramfs) | Remote unlock over SSH before boot completes |
| **Headless** | Tang/Clevis (network-bound) | Auto-unlock when on trusted network |

**What LUKS covers:**
- Everything on the encrypted partition: OpenClaw data, session transcripts, workspace, logs, lobsec config
- Does NOT protect against a running attacker (data is decrypted while system is up)
- Protects against: disk theft, improper disposal, cold-boot after power-off

**What LUKS does NOT cover (hence fscrypt below):**
- Running system compromise: all files are decrypted after boot
- Process with filesystem access can read everything
- Need additional layer for defense-in-depth

### 1.2 Layer 1: File-Level Encryption (fscrypt)

fscrypt provides per-directory encryption on ext4/f2fs. It encrypts filenames and file contents with a per-directory key. Even on a running system, directories are only decrypted when explicitly unlocked.

**Why fscrypt over alternatives:**

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| fscrypt (Linux native) | Kernel-level, no FUSE overhead, per-directory keys, works with ext4 | Requires ext4/f2fs, Linux 5.4+ | **Selected** |
| eCryptfs | Stacked filesystem, flexible | FUSE overhead, deprecated upstream, mount issues | Rejected |
| gocryptfs | Fast FUSE, well-audited | FUSE overhead, extra dependency | Backup option |
| Application-level (per-file AES) | Full control | Must implement correctly, performance overhead, breaks tools that need raw access | Rejected for workspace |

**fscrypt directory layout:**

```
/root/.openclaw/                    # Mount point (ext4 with encrypt feature)
├── openclaw.json                   # NOT encrypted (no secrets, needed at startup)
├── workspace/                      # fscrypt-encrypted directory
│   ├── AGENTS.md                   #   decrypted only when openclaw-gateway runs
│   ├── SOUL.md                     #   ...
│   └── ...                         #
├── agents/                         # fscrypt-encrypted directory
│   └── main/
│       └── sessions/               # Session transcripts (PII risk)
│           ├── sessions.json       #   encrypted at rest
│           └── *.jsonl             #   encrypted at rest
├── logs/                           # fscrypt-encrypted directory
│   ├── config-audit.jsonl          #   encrypted + HSM-signed
│   └── lobsec-audit.jsonl          #   encrypted + HSM-signed
└── canvas/                         # fscrypt-encrypted directory
```

**Key derivation:**

fscrypt supports multiple "protectors" (key sources). lobsec uses an HSM-backed protector:

```
HSM (SoftHSM2/YubiHSM2)
    |
    | PKCS#11 C_DeriveKey or C_GetAttributeValue
    |
    v
fscrypt master key (256-bit)
    |
    | fscrypt KDF (per-directory)
    |
    v
Per-directory encryption key (AES-256-XTS for contents, AES-256-CTS for filenames)
```

**lobsec-cli fscrypt integration:**

```bash
# At startup (after LUKS unlock):

# 1. Retrieve fscrypt master key from HSM
FSCRYPT_KEY=$(lobsec-cli credential get --label fscrypt-master-key --raw)

# 2. Unlock encrypted directories
echo "$FSCRYPT_KEY" | fscrypt unlock /root/.openclaw/workspace/
echo "$FSCRYPT_KEY" | fscrypt unlock /root/.openclaw/agents/
echo "$FSCRYPT_KEY" | fscrypt unlock /root/.openclaw/logs/
echo "$FSCRYPT_KEY" | fscrypt unlock /root/.openclaw/canvas/

# 3. Clear key from memory
unset FSCRYPT_KEY

# 4. Start OpenClaw (directories are now decrypted)
# ...

# At shutdown:
# 5. Lock directories (re-encrypts, clears kernel key)
fscrypt lock /root/.openclaw/workspace/
fscrypt lock /root/.openclaw/agents/
fscrypt lock /root/.openclaw/logs/
fscrypt lock /root/.openclaw/canvas/
```

**Defense-in-depth benefit:** If an attacker gets a shell on the host WHILE the system is running, the encrypted directories are unlocked (accessible). But if the attacker only gets filesystem access (e.g., backup, snapshot, container escape to host filesystem), and lobsec has locked the directories after shutdown, the data is encrypted.

**For the Docker container:** The openclaw-gateway container bind-mounts these directories. From the container's perspective, the files are normal (decrypted by the kernel). The container never handles encryption keys -- the host kernel does it transparently via fscrypt.

### 1.3 Audit Log Encryption + Integrity

Audit logs get BOTH encryption (fscrypt) and integrity (HSM signatures):

```
Audit event occurs
    |
    v
lobsec-plugin formats JSON entry
    |
    v
Hash chain: SHA-256(previous_entry_hash + current_entry)
    |
    v
HSM signs: RSA-2048 signature over (entry_hash + timestamp)
    |
    v
Entry written to /root/.openclaw/logs/lobsec-audit.jsonl
    |
    (directory encrypted by fscrypt -- transparent to writer)
    |
    (disk encrypted by LUKS -- transparent to all)
```

Three layers of protection:
1. **Confidentiality**: fscrypt (file-level) + LUKS (disk-level)
2. **Integrity**: HSM-signed hash chain (tamper-evident)
3. **Non-repudiation**: HSM signing key is non-extractable (cannot forge entries even with root)

### 1.4 Credential Encryption (HSM)

Already designed in `paranoid-isolation.md` Part 3. Summary:

| Credential | Storage | Encryption |
|------------|---------|------------|
| LLM API keys | HSM PKCS#11 object | AES-256 inside HSM token |
| Webhook signing secrets | HSM PKCS#11 object | AES-256 inside HSM token, non-extractable |
| Gateway auth token | HSM PKCS#11 object | AES-256 inside HSM token |
| TLS private keys | HSM PKCS#11 object | Non-extractable, HSM performs crypto ops |
| Audit signing key | HSM RSA-2048 keypair | Private key never leaves HSM |
| fscrypt master key | HSM PKCS#11 object | AES-256 inside HSM token |
| Internal CA private key | HSM RSA-2048/EC-P256 | Non-extractable |

**SoftHSM2 token encryption:** SoftHSM2 stores PKCS#11 objects encrypted with a token-level key derived from the user PIN via PBKDF2. The token file itself (on disk) is encrypted. On YubiHSM2, the key material is in tamper-resistant hardware.

---

## Part 2: In-Transit Encryption

### 2.1 External TLS (Client ↔ Caddy)

All external connections terminate at Caddy with TLS 1.3.

**TLS configuration:**

```
TLS 1.3 ONLY (no 1.2, no 1.1, no 1.0)
Cipher suites:
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_GCM_SHA256
HSTS: max-age=63072000; includeSubDomains; preload
OCSP stapling: enabled (for public CA certs)
Certificate transparency: enabled (for public CA certs)
```

Certificate source depends on deployment mode (see Part 3).

### 2.2 Internal mTLS (Container ↔ Container)

Every connection between Docker containers on `lobsec-internal` uses mutual TLS. Both sides present certificates and verify the peer.

**Why mTLS on internal networks:**
- Defense-in-depth: if an attacker escapes a sandbox container and reaches `lobsec-internal`, they cannot impersonate another container
- Prevents traffic sniffing on the Docker bridge (attacker would need to compromise the bridge itself)
- Credential material (proxy tokens, auth data) is encrypted even on the internal network
- Audit trail: TLS handshake logs show which container connected to which

**Internal CA:**
- Self-signed CA, private key stored in HSM (non-extractable)
- CA cert distributed to all containers via read-only bind mount
- Per-container certificates issued by lobsec-cli at startup
- Short-lived: 24-hour validity, re-issued on every restart
- CN (Common Name) matches container name for verification

**Certificate inventory:**

| Container | CN | SANs | Usage |
|-----------|-----|------|-------|
| caddy | `lobsec-caddy` | `DNS:caddy`, `IP:172.30.0.10` | Server (accepts gateway connections), Client (connects to proxy for webhook validation) |
| lobsec-proxy | `lobsec-proxy` | `DNS:lobsec-proxy`, `IP:172.30.0.20` | Server (LLM proxy :8080, egress proxy :8081, webhook :8082), Client (connects to cloud APIs, Ollama) |
| openclaw-gateway | `openclaw-gateway` | `DNS:openclaw-gateway`, `IP:172.30.0.30`, `IP:172.30.1.30` | Client (connects to proxy), Server (accepts sandbox connections on sandbox network) |

**mTLS flow (gateway → proxy example):**

```
openclaw-gateway                           lobsec-proxy
    |                                          |
    |--- ClientHello (TLS 1.3) --------------->|
    |                                          |
    |<-- ServerHello + proxy cert -------------|
    |    (signed by internal CA)               |
    |                                          |
    |--- gateway cert ------------------------>|
    |    (signed by internal CA)               |
    |                                          |
    |    Both sides verify:                    |
    |    1. Cert signed by internal CA? ✓      |
    |    2. Cert not expired (< 24h)? ✓        |
    |    3. CN matches expected peer? ✓        |
    |                                          |
    |<========= Encrypted channel ============>|
    |    (AES-256-GCM or ChaCha20)             |
```

**Certificate injection into containers:**

```yaml
# docker-compose.yml additions for mTLS
services:
  openclaw-gateway:
    volumes:
      # Internal CA cert (for verifying peers)
      - /run/lobsec/internal-ca.crt:/etc/lobsec/tls/ca.crt:ro
      # Container's own cert + key
      - /run/lobsec/certs/gateway.crt:/etc/lobsec/tls/server.crt:ro
      - /run/lobsec/certs/gateway.key:/etc/lobsec/tls/server.key:ro
    environment:
      # Tell OpenClaw to use HTTPS for proxy
      HTTP_PROXY: "https://lobsec-proxy:8081"
      HTTPS_PROXY: "https://lobsec-proxy:8081"
      # CA cert for proxy verification
      NODE_EXTRA_CA_CERTS: "/etc/lobsec/tls/ca.crt"

  lobsec-proxy:
    volumes:
      - /run/lobsec/internal-ca.crt:/etc/lobsec/tls/ca.crt:ro
      - /run/lobsec/certs/proxy.crt:/etc/lobsec/tls/server.crt:ro
      - /run/lobsec/certs/proxy.key:/etc/lobsec/tls/server.key:ro

  caddy:
    volumes:
      - /run/lobsec/internal-ca.crt:/etc/lobsec/tls/ca.crt:ro
      - /run/lobsec/certs/caddy.crt:/etc/lobsec/tls/server.crt:ro
      - /run/lobsec/certs/caddy.key:/etc/lobsec/tls/server.key:ro
```

All certificate files are on tmpfs (`/run/lobsec/`). They exist only in RAM and are destroyed on shutdown.

### 2.3 Proxy ↔ Ollama Backends

**Jetson Orin (LAN):**

Two options depending on network topology:

| Scenario | Encryption | Implementation |
|----------|-----------|----------------|
| Jetson on same LAN, no hostile network | TLS with pinned certificate | Ollama TLS + lobsec-proxy cert pinning |
| Jetson on shared/untrusted LAN | WireGuard tunnel | Point-to-point encrypted tunnel |
| Jetson via Cloudflare Access | HTTPS (Cloudflare TLS) | Already encrypted, Cloudflare terminates TLS |

**Ollama TLS configuration (on Jetson):**

```bash
# Generate Ollama TLS cert (signed by lobsec internal CA)
# This cert is generated by lobsec-cli and deployed to Jetson

# On the Jetson:
export OLLAMA_HOST=0.0.0.0:11434
export OLLAMA_TLS_CERT=/etc/ollama/tls/server.crt
export OLLAMA_TLS_KEY=/etc/ollama/tls/server.key

# In lobsec-proxy config:
{
  "ollama_backends": [
    {
      "name": "jetson-orin",
      "url": "https://<jetson-host>:11434",
      "tls": {
        "ca": "/etc/lobsec/tls/ca.crt",
        "verify": true,
        "pin_sha256": "base64-encoded-sha256-of-cert-public-key"
      }
    }
  ]
}
```

**Certificate pinning:** lobsec-proxy pins the Jetson's TLS certificate by its public key hash (HPKP-style, but enforced in code, not headers). Even if a CA is compromised, only the pinned cert is accepted.

**Remote GPU (WireGuard):**

Already encrypted at the network layer. Ollama runs on `localhost` inside the WireGuard network. lobsec-proxy connects to the WireGuard peer IP.

```
lobsec-proxy → WireGuard interface (wg0) → encrypted tunnel → Remote GPU → localhost:11434
```

Optionally, Ollama on remote GPU can also run TLS for defense-in-depth (encrypted inside the encrypted tunnel). This is recommended:

```
lobsec-proxy → TLS → WireGuard → TLS → Ollama (remote GPU)
```

### 2.4 Encryption Protocol Summary

```
EXTERNAL                                INTERNAL (Docker)                         BACKENDS
=========                               ====================                      ========

Client                                  lobsec-internal network
  |                                     (--internal, no internet)
  | TLS 1.3
  | (Let's Encrypt /                    caddy ←——mTLS——→ openclaw-gateway
  |  self-signed /                         |                    |
  |  custom CA)                            |                    |
  v                                     mTLS                 mTLS
Caddy (:443)                               |                    |
                                           v                    v
                                     lobsec-proxy ←——mTLS——→ (webhook validation)
                                           |
                              +————————————+————————————+
                              |            |            |
                           TLS 1.3     TLS+pin      WireGuard
                              |            |         (+TLS opt)
                              v            v            v
                          Cloud APIs   Jetson Orin   Remote GPU
                         (Anthropic,   (Ollama)      (Ollama)
                          OpenAI)
```

Every arrow is encrypted. No plaintext network traffic anywhere in the system.

---

## Part 3: Certificate Management

### 3.1 Certificate Tiers

lobsec supports three certificate tiers for external TLS. The user selects a tier in lobsec configuration:

```json5
// lobsec-config.json5
{
  "tls": {
    // "self-signed" | "acme" | "custom"
    "mode": "self-signed",

    // ACME settings (mode: "acme")
    "acme": {
      "provider": "letsencrypt",       // "letsencrypt" | "zerossl" | "buypass" | "custom"
      "email": "admin@example.com",
      "challenge": "http-01",          // "http-01" | "dns-01" | "tls-alpn-01"
      "dns_provider": null,            // For dns-01: "cloudflare" | "route53" | ...
      "ca_url": null                   // Custom ACME CA URL (for "custom" provider)
    },

    // Custom CA settings (mode: "custom")
    "custom": {
      "cert_path": "/etc/lobsec/tls/external/cert.pem",
      "key_path": "/etc/lobsec/tls/external/key.pem",       // Or PKCS#11 URI
      "chain_path": "/etc/lobsec/tls/external/chain.pem",   // Intermediate CA chain
      "key_in_hsm": false              // If true, key_path is a PKCS#11 URI
    },

    // Domain (required for acme and custom)
    "domain": null,                    // e.g., "lobsec.example.com"

    // Internal mTLS (always enabled, not configurable)
    "internal": {
      "ca_key_in_hsm": true,           // Internal CA private key in HSM
      "cert_lifetime_hours": 24,       // Short-lived internal certs
      "key_algorithm": "EC-P256"       // EC-P256 (fast) or RSA-2048 (compatible)
    }
  }
}
```

### 3.2 Tier 1: Self-Signed (Default)

**When to use:** Development, local-only access, SSH tunnel / Tailscale access.

**How it works:**

1. lobsec-cli generates a self-signed CA at first run (private key in HSM)
2. Issues a server certificate for Caddy signed by this CA
3. The CA cert can be installed on client devices for browser trust

```bash
# lobsec-cli tls init --mode self-signed

# Step 1: Generate CA keypair in HSM
lobsec-cli hsm generate-keypair \
  --label "lobsec-external-ca" \
  --algorithm EC-P256 \
  --non-extractable

# Step 2: Create self-signed CA certificate
lobsec-cli tls create-ca \
  --cn "lobsec Self-Signed CA" \
  --validity-days 3650 \
  --key-label "lobsec-external-ca" \
  --output /run/lobsec/tls/external-ca.crt

# Step 3: Issue server certificate
lobsec-cli tls issue-cert \
  --ca-cert /run/lobsec/tls/external-ca.crt \
  --ca-key-label "lobsec-external-ca" \
  --cn "localhost" \
  --san "DNS:localhost,IP:127.0.0.1,IP:::1" \
  --validity-days 365 \
  --output-cert /run/lobsec/tls/external/server.crt \
  --output-key /run/lobsec/tls/external/server.key

# Step 4: Configure Caddy
# Caddy uses the issued cert (static, no ACME)
```

**Caddy configuration for self-signed:**

```caddyfile
{
    # Disable automatic HTTPS (we manage certs ourselves)
    auto_https off
}

:443 {
    tls /etc/lobsec/tls/external/server.crt /etc/lobsec/tls/external/server.key {
        protocols tls1.3
        ciphers TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256
    }

    # ... reverse proxy config ...
}
```

**Client trust:** Users can install the CA cert on their devices:
```bash
# Export CA cert for client installation
lobsec-cli tls export-ca --output lobsec-ca.crt

# macOS: add to keychain
# Linux: copy to /usr/local/share/ca-certificates/ && update-ca-certificates
# Browser: import in certificate settings
```

### 3.3 Tier 2: ACME / Let's Encrypt (Public Default)

**When to use:** Production with a public domain name.

**Supported ACME providers:**

| Provider | CA URL | Free? | Rate Limits | Notes |
|----------|--------|-------|-------------|-------|
| **Let's Encrypt** (default) | `acme-v02.api.letsencrypt.org` | Yes | 50 certs/week/domain | Most widely trusted |
| ZeroSSL | `acme.zerossl.com` | Yes (free tier) | Varies | Alternative to LE |
| Buypass | `api.buypass.com/acme` | Yes (Go SSL) | Varies | European CA |
| Custom | User-provided | Varies | Varies | Any ACME-compatible CA |

**Challenge types:**

| Challenge | Requires | Best For |
|-----------|----------|----------|
| HTTP-01 | Port 80 accessible from internet | Standard public servers |
| DNS-01 | DNS API access (Cloudflare, Route53, etc.) | Servers behind firewalls, wildcard certs |
| TLS-ALPN-01 | Port 443 accessible from internet | When port 80 is not available |

**For lobsec's "zero public attack surface" goal:** DNS-01 is strongly preferred. It does not require ANY open ports. Caddy supports DNS-01 with dozens of DNS providers via plugins.

```bash
# lobsec-cli tls init --mode acme \
#   --provider letsencrypt \
#   --email admin@example.com \
#   --domain lobsec.example.com \
#   --challenge dns-01 \
#   --dns-provider cloudflare \
#   --dns-api-token <from-hsm>
```

**Caddy configuration for ACME:**

```caddyfile
{
    email admin@example.com

    # ACME CA (Let's Encrypt by default)
    acme_ca https://acme-v02.api.letsencrypt.org/directory

    # DNS-01 challenge (no open ports needed)
    acme_dns cloudflare {
        api_token {env.CLOUDFLARE_API_TOKEN}
    }
}

lobsec.example.com {
    tls {
        protocols tls1.3
        ciphers TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256

        # OCSP stapling (automatic with Caddy)
        # Certificate transparency (automatic with public CAs)
    }

    # ... reverse proxy config ...
}
```

**ACME and HSM:** Caddy generates and manages its own ACME account key and certificate private keys. For paranoid-level, we can configure Caddy to store its private key in the HSM via PKCS#11, but this requires a Caddy plugin (`caddy-pkcs11`) which `[NEEDS VERIFICATION]`.

**Fallback:** If ACME renewal fails (DNS API down, rate limit), lobsec-cli alerts the operator and falls back to the most recent valid certificate. Caddy handles this automatically.

### 3.4 Tier 3: Custom CA

**When to use:** Enterprise environments with their own CA, or specific compliance requirements.

**How it works:**

1. User provides cert + key + chain files (or key in HSM via PKCS#11 URI)
2. lobsec-cli validates the certificate chain
3. Caddy uses the provided cert directly

```bash
# lobsec-cli tls init --mode custom \
#   --cert /path/to/cert.pem \
#   --key /path/to/key.pem \
#   --chain /path/to/chain.pem \
#   --domain lobsec.example.com

# Or with HSM-stored private key:
# lobsec-cli tls init --mode custom \
#   --cert /path/to/cert.pem \
#   --key-hsm-label "external-tls-key" \
#   --chain /path/to/chain.pem
```

**Certificate renewal:** User's responsibility. lobsec-cli monitors certificate expiry and alerts at 30, 14, 7, and 1 day(s) before expiration.

### 3.5 Internal CA (Always Active)

The internal CA is always self-signed and always uses HSM-backed keys. This is NOT configurable -- it is always on.

**Internal CA lifecycle:**

```
First run (lobsec-cli init):
    |
    v
Generate EC-P256 keypair in HSM
    label: "lobsec-internal-ca"
    extractable: false
    |
    v
Create self-signed CA cert
    CN: "lobsec Internal CA"
    validity: 10 years
    basic_constraints: CA:TRUE, pathlen:0
    key_usage: keyCertSign, cRLSign
    |
    v
Store CA cert at /run/lobsec/internal-ca.crt

Every startup (lobsec-cli start):
    |
    v
Issue per-container certs (24h validity)
    signed by internal CA
    CN: container name
    SANs: container DNS + IP
    key_usage: digitalSignature, keyEncipherment
    extended_key_usage: serverAuth, clientAuth
    |
    v
Write certs to /run/lobsec/certs/{container}.crt
Write keys to /run/lobsec/certs/{container}.key
    (tmpfs -- RAM only, destroyed on shutdown)

Every 12 hours (cron or lobsec-cli rotate-certs):
    |
    v
Re-issue all container certs
    Graceful reload of containers to pick up new certs
```

**Per-container certificate generation (in lobsec-cli):**

```typescript
// lobsec-cli/src/tls/internal-ca.ts (conceptual)
import { X509Certificate } from "node:crypto";

interface ContainerCertConfig {
  cn: string;
  sans: string[];  // "DNS:caddy", "IP:172.30.0.10"
  validityHours: number;
}

const CONTAINER_CERTS: ContainerCertConfig[] = [
  {
    cn: "lobsec-caddy",
    sans: ["DNS:caddy", "DNS:lobsec-caddy", "IP:172.30.0.10"],
    validityHours: 24,
  },
  {
    cn: "lobsec-proxy",
    sans: ["DNS:lobsec-proxy", "IP:172.30.0.20", "IP:172.30.2.20"],
    validityHours: 24,
  },
  {
    cn: "openclaw-gateway",
    sans: ["DNS:openclaw-gateway", "IP:172.30.0.30", "IP:172.30.1.30"],
    validityHours: 24,
  },
];

// lobsec-cli generates these at every startup using the HSM-resident CA key
// The CA key never leaves the HSM -- CSR signing happens via PKCS#11
```

### 3.6 Certificate Rotation Summary

| Certificate Type | Rotation | Mechanism | Downtime |
|-----------------|----------|-----------|----------|
| External (self-signed) | Yearly | `lobsec-cli tls rotate` | Zero (Caddy graceful reload) |
| External (ACME) | Every 60-90 days | Caddy automatic | Zero (automatic) |
| External (custom) | User-managed | User replaces files, `lobsec-cli tls reload` | Zero (Caddy graceful reload) |
| Internal container certs | Every 12 hours | `lobsec-cli` cron or startup | Zero (graceful reload) |
| Internal CA | Every 10 years | `lobsec-cli tls rotate-ca` | Brief (all container certs re-issued) |
| Ollama backend cert | Yearly | `lobsec-cli tls rotate` | Brief (Ollama restart on Jetson) |

---

## Part 4: Key Hierarchy

All cryptographic keys in lobsec form a hierarchy rooted in the HSM:

```
HSM (SoftHSM2 / YubiHSM2)
├── Token PIN (user-provided, protects HSM access)
│
├── lobsec-internal-ca (EC-P256, non-extractable)
│   │   Internal CA for container mTLS
│   ├── caddy.crt (24h, server+client)
│   ├── lobsec-proxy.crt (24h, server+client)
│   ├── openclaw-gateway.crt (24h, server+client)
│   └── jetson-ollama.crt (365d, server)
│
├── lobsec-external-ca (EC-P256, non-extractable)  [self-signed mode only]
│   │   External CA for client-facing TLS
│   └── caddy-external.crt (365d, server)
│
├── audit-signing-key (RSA-2048, non-extractable)
│   │   Signs audit log entries (hash chain)
│   └── Signatures in lobsec-audit.jsonl
│
├── skill-signing-key (EC-P256, non-extractable)
│   │   Signs approved skill packages
│   └── Signatures in skill manifest
│
├── fscrypt-master-key (AES-256, extractable=true, sensitive=true)
│   │   Protector for fscrypt directories
│   ├── /root/.openclaw/workspace/ (per-dir derived key)
│   ├── /root/.openclaw/agents/ (per-dir derived key)
│   ├── /root/.openclaw/logs/ (per-dir derived key)
│   └── /root/.openclaw/canvas/ (per-dir derived key)
│
├── anthropic-api-key (GENERIC_SECRET, extractable=true, sensitive=true)
│   └── Injected into lobsec-proxy env at startup
│
├── openai-api-key (GENERIC_SECRET, extractable=true, sensitive=true)
│   └── Injected into lobsec-proxy env at startup
│
├── gateway-auth-token (GENERIC_SECRET, extractable=true, sensitive=true)
│   └── Injected into openclaw-gateway env at startup
│
├── proxy-internal-token (GENERIC_SECRET, extractable=true, sensitive=true)
│   └── Injected into both proxy + gateway env at startup
│
├── telegram-webhook-secret (GENERIC_SECRET, non-extractable)
│   └── HSM performs HMAC verification (key never leaves HSM)
│
├── slack-signing-secret (GENERIC_SECRET, non-extractable)
│   └── HSM performs HMAC-SHA256 verification
│
└── ... (additional webhook secrets per channel)
```

**Key properties by type:**

| Key Purpose | Algorithm | Extractable | Sensitive | Exportable | Lifetime |
|-------------|-----------|-------------|-----------|------------|----------|
| Internal CA | EC-P256 | NO | YES | NEVER | 10 years |
| External CA (self-signed) | EC-P256 | NO | YES | NEVER | 10 years |
| Audit signing | RSA-2048 | NO | YES | NEVER | 5 years |
| Skill signing | EC-P256 | NO | YES | NEVER | 5 years |
| fscrypt master | AES-256 | YES (needed by kernel) | YES | Wrap-only | 5 years, rotate with re-encryption |
| API keys | Generic | YES (needed as HTTP header) | YES | NEVER | Per-rotation (30-90 days) |
| Webhook secrets | Generic | NO (HSM does HMAC) | YES | NEVER | Per-rotation |
| Container TLS | EC-P256 | YES (container needs key) | YES | NEVER | 24 hours |

### 4.1 Key Backup and Recovery

**HSM backup strategy:**

| HSM Type | Backup Method | Recovery |
|----------|--------------|----------|
| SoftHSM2 | Encrypted backup of token directory (`/root/.lobsec/softhsm2/tokens/`) | Restore token directory, same PIN |
| YubiHSM2 | `yubihsm-wrap` key export (wrap key required) | Import wrapped keys into new YubiHSM2 |

**Backup procedure:**

```bash
# lobsec-cli backup --include-hsm

# 1. Lock fscrypt directories
fscrypt lock /root/.openclaw/workspace/
fscrypt lock /root/.openclaw/agents/
fscrypt lock /root/.openclaw/logs/

# 2. Backup SoftHSM2 token store (already encrypted by SoftHSM2)
tar czf /backup/lobsec-hsm-$(date +%Y%m%d).tar.gz \
  /root/.lobsec/softhsm2/tokens/

# 3. Backup OpenClaw data (already encrypted by fscrypt + LUKS)
tar czf /backup/lobsec-data-$(date +%Y%m%d).tar.gz \
  /root/.openclaw/

# 4. Encrypt backup with age (additional layer, passphrase-based)
age -p -o /backup/lobsec-backup-$(date +%Y%m%d).tar.gz.age \
  /backup/lobsec-hsm-$(date +%Y%m%d).tar.gz

# 5. Unlock fscrypt directories
lobsec-cli start  # re-unlocks
```

**Recovery procedure:**

```bash
# 1. Install SoftHSM2 on new host
# 2. Restore token directory from backup
# 3. Restore OpenClaw data
# 4. Run lobsec-cli init (re-generates internal CA, container certs)
# 5. Re-provision external TLS cert (ACME auto-renews, self-signed auto-generates)
```

### 4.2 Key Rotation Schedule

| Key | Rotation Period | Automated? | Procedure |
|-----|----------------|-----------|-----------|
| Container TLS certs | 12 hours | YES (lobsec-cli cron) | Re-issue from internal CA, graceful reload |
| External TLS (ACME) | 60-90 days | YES (Caddy auto-renew) | ACME protocol |
| External TLS (self-signed) | 365 days | YES (lobsec-cli cron) | Re-issue from external CA |
| LLM API keys | 90 days (recommended) | SEMI (lobsec-cli prompts) | Rotate at provider, update HSM |
| Webhook secrets | 90 days | SEMI | Rotate at platform, update HSM |
| Gateway auth token | 30 days | YES (lobsec-cli cron) | Generate new, restart gateway |
| Internal proxy token | 30 days | YES (lobsec-cli cron) | Generate new, restart proxy + gateway |
| Internal CA | 10 years | NO (manual) | Generate new CA, re-issue all certs |
| Audit signing key | 5 years | NO (manual) | Generate new keypair, keep old for verification |
| fscrypt master key | 5 years | NO (manual, requires re-encryption) | Generate new, re-encrypt all directories |
| HSM PIN | User discretion | NO (manual) | `softhsm2-util --change-pin` or YubiHSM2 admin |

---

## Appendix A: LUKS Setup

```bash
#!/bin/bash
# /root/lobsec/scripts/setup-luks.sh
# Full-disk encryption setup for lobsec data partition
# Run ONCE during initial deployment

set -euo pipefail

DATA_DEVICE="${1:?Usage: setup-luks.sh /dev/sdX}"
DATA_MOUNT="/root/.openclaw"

echo "=== lobsec LUKS2 Setup ==="
echo "Device: $DATA_DEVICE"
echo "Mount:  $DATA_MOUNT"
echo ""
echo "WARNING: This will DESTROY all data on $DATA_DEVICE"
read -rp "Continue? (yes/no): " confirm
[ "$confirm" = "yes" ] || exit 1

# Step 1: Create LUKS2 container
echo "[1/6] Creating LUKS2 container..."
cryptsetup luksFormat \
  --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha512 \
  --pbkdf argon2id \
  --pbkdf-memory 1048576 \
  --pbkdf-parallel 4 \
  --pbkdf-force-iterations 4 \
  --label "lobsec-data" \
  "$DATA_DEVICE"

# Step 2: Open the LUKS container
echo "[2/6] Opening LUKS container..."
cryptsetup open "$DATA_DEVICE" lobsec-data

# Step 3: Create ext4 filesystem with encryption support (for fscrypt)
echo "[3/6] Creating ext4 filesystem with encryption feature..."
mkfs.ext4 \
  -O encrypt \
  -L lobsec-data \
  /dev/mapper/lobsec-data

# Step 4: Mount
echo "[4/6] Mounting..."
mkdir -p "$DATA_MOUNT"
mount /dev/mapper/lobsec-data "$DATA_MOUNT"

# Step 5: Initialize fscrypt on the filesystem
echo "[5/6] Initializing fscrypt..."
fscrypt setup --force
fscrypt setup "$DATA_MOUNT" --force

# Step 6: Create directory structure
echo "[6/6] Creating directory structure..."
mkdir -p "$DATA_MOUNT"/{workspace,agents,logs,canvas,cron,devices}
chmod 700 "$DATA_MOUNT"

echo ""
echo "=== LUKS2 + fscrypt setup complete ==="
echo ""
echo "Add to /etc/crypttab:"
echo "  lobsec-data  UUID=$(cryptsetup luksUUID "$DATA_DEVICE")  none  luks,discard"
echo ""
echo "Add to /etc/fstab:"
echo "  /dev/mapper/lobsec-data  $DATA_MOUNT  ext4  defaults,noatime  0  2"
echo ""
echo "Next steps:"
echo "  1. lobsec-cli fscrypt init    # Create fscrypt policies using HSM key"
echo "  2. lobsec-cli init            # Full lobsec initialization"

# Optional: TPM2 auto-unlock (for headless production)
if command -v systemd-cryptenroll &> /dev/null; then
  echo ""
  read -rp "Enroll TPM2 for auto-unlock? (yes/no): " tpm_confirm
  if [ "$tpm_confirm" = "yes" ]; then
    systemd-cryptenroll \
      --tpm2-device=auto \
      --tpm2-pcrs=0+1+2+3+5+7 \
      "$DATA_DEVICE"
    echo "TPM2 enrolled. System will auto-unlock on boot if TPM PCRs match."
    echo "IMPORTANT: If you update kernel/initramfs/bootloader, you must re-enroll."
  fi
fi
```

---

## Appendix B: fscrypt Setup

```bash
#!/bin/bash
# /root/lobsec/scripts/setup-fscrypt.sh
# Per-directory encryption using fscrypt with HSM-backed key

set -euo pipefail

DATA_MOUNT="/root/.openclaw"

echo "=== lobsec fscrypt Setup ==="

# Verify fscrypt is available
command -v fscrypt >/dev/null 2>&1 || {
  echo "Installing fscrypt..."
  apt-get install -y fscrypt libpam-fscrypt
}

# Verify filesystem supports encryption
tune2fs -l "$(df --output=source "$DATA_MOUNT" | tail -1)" | grep -q "encrypt" || {
  echo "ERROR: Filesystem at $DATA_MOUNT does not have 'encrypt' feature."
  echo "Re-create with: mkfs.ext4 -O encrypt ..."
  exit 1
}

# Step 1: Generate fscrypt master key in HSM
echo "[1/4] Generating fscrypt master key in HSM..."
lobsec-cli credential add \
  --label "fscrypt-master-key" \
  --generate \
  --length 32 \
  --type api-key  # extractable (kernel needs the raw key)

# Step 2: Retrieve key and create fscrypt protector
echo "[2/4] Creating fscrypt protector..."
FSCRYPT_KEY=$(lobsec-cli credential get --label fscrypt-master-key --raw)

# Create a custom protector using the raw key
echo "$FSCRYPT_KEY" | fscrypt metadata create protector "$DATA_MOUNT" \
  --source=raw_key \
  --name="lobsec-hsm"

PROTECTOR_ID=$(fscrypt metadata dump "$DATA_MOUNT" | grep "lobsec-hsm" | awk '{print $1}')

# Step 3: Encrypt each directory
echo "[3/4] Encrypting directories..."
for dir in workspace agents logs canvas; do
  target="$DATA_MOUNT/$dir"

  # Directory must be empty for initial encryption
  if [ -d "$target" ] && [ "$(ls -A "$target" 2>/dev/null)" ]; then
    echo "  $dir: migrating existing data..."
    mv "$target" "${target}.bak"
    mkdir "$target"
  else
    mkdir -p "$target"
  fi

  fscrypt encrypt "$target" --protector="$DATA_MOUNT:$PROTECTOR_ID"
  echo "  $dir: encrypted ✓"

  # Restore backed-up data if any
  if [ -d "${target}.bak" ]; then
    cp -a "${target}.bak/." "$target/"
    rm -rf "${target}.bak"
    echo "  $dir: data migrated ✓"
  fi
done

# Step 4: Clear key
unset FSCRYPT_KEY

echo ""
echo "=== fscrypt setup complete ==="
echo ""
echo "[4/4] Verify:"
fscrypt status "$DATA_MOUNT"
echo ""
echo "Directories encrypted:"
for dir in workspace agents logs canvas; do
  fscrypt status "$DATA_MOUNT/$dir"
done
echo ""
echo "To lock (after shutdown): fscrypt lock $DATA_MOUNT/workspace"
echo "To unlock (at startup):  lobsec-cli fscrypt unlock"
```

---

## Appendix C: Internal CA Generation

```typescript
// /root/lobsec/src/tls/internal-ca.ts (conceptual implementation)
// Generates internal mTLS CA and per-container certificates
// CA private key stays in HSM (non-extractable)

import { execSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const CERT_DIR = "/run/lobsec/certs";
const CA_CERT_PATH = "/run/lobsec/internal-ca.crt";

interface CertSpec {
  cn: string;
  sans: string[];
  validityHours: number;
}

const CONTAINERS: CertSpec[] = [
  { cn: "lobsec-caddy", sans: ["DNS:caddy", "DNS:lobsec-caddy", "IP:172.30.0.10"], validityHours: 24 },
  { cn: "lobsec-proxy", sans: ["DNS:lobsec-proxy", "IP:172.30.0.20", "IP:172.30.2.20"], validityHours: 24 },
  { cn: "openclaw-gateway", sans: ["DNS:openclaw-gateway", "IP:172.30.0.30", "IP:172.30.1.30"], validityHours: 24 },
];

/**
 * Generate internal CA if not exists.
 * Uses openssl with PKCS#11 engine for HSM-backed key.
 */
export function generateInternalCA(hsm: { modulePath: string; slot: number; pin: string }): void {
  // Generate EC-P256 keypair in HSM via PKCS#11
  // (lobsec-cli credential store handles this)

  // Create CA cert using openssl with pkcs11 engine
  const opensslConf = `
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = lobsec Internal CA

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
`;

  writeFileSync("/tmp/lobsec-ca.cnf", opensslConf);

  // Use openssl with PKCS#11 engine
  // The private key reference is a PKCS#11 URI
  const pkcs11Uri = `pkcs11:token=lobsec;object=lobsec-internal-ca;type=private;pin-value=${hsm.pin}`;

  execSync(`openssl req -new -x509 \
    -engine pkcs11 -keyform engine \
    -key "${pkcs11Uri}" \
    -config /tmp/lobsec-ca.cnf \
    -days 3650 \
    -out ${CA_CERT_PATH}`, { stdio: "pipe" });
}

/**
 * Issue per-container certificates signed by internal CA.
 * Container private keys are generated locally (not in HSM -- they are short-lived and extractable).
 */
export function issueContainerCerts(hsm: { pin: string }): void {
  mkdirSync(CERT_DIR, { recursive: true });

  for (const spec of CONTAINERS) {
    const keyPath = join(CERT_DIR, `${spec.cn}.key`);
    const csrPath = join(CERT_DIR, `${spec.cn}.csr`);
    const certPath = join(CERT_DIR, `${spec.cn}.crt`);

    const sanString = spec.sans.join(",");
    const validityDays = Math.ceil(spec.validityHours / 24);

    // Generate ephemeral key for this container
    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out ${keyPath}`, { stdio: "pipe" });
    execSync(`chmod 0400 ${keyPath}`);

    // Create CSR
    execSync(`openssl req -new -key ${keyPath} \
      -subj "/CN=${spec.cn}" \
      -addext "subjectAltName=${sanString}" \
      -out ${csrPath}`, { stdio: "pipe" });

    // Sign with CA (using PKCS#11 engine for CA key)
    const pkcs11Uri = `pkcs11:token=lobsec;object=lobsec-internal-ca;type=private;pin-value=${hsm.pin}`;

    const extConf = `
[ext]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = ${sanString}
`;
    writeFileSync("/tmp/lobsec-ext.cnf", extConf);

    execSync(`openssl x509 -req \
      -in ${csrPath} \
      -CA ${CA_CERT_PATH} \
      -engine pkcs11 -CAkeyform engine \
      -CAkey "${pkcs11Uri}" \
      -CAcreateserial \
      -days ${validityDays} \
      -extfile /tmp/lobsec-ext.cnf -extensions ext \
      -out ${certPath}`, { stdio: "pipe" });

    // Clean up CSR
    execSync(`rm -f ${csrPath}`);
  }
}
```

---

## Appendix D: Caddyfile with TLS Modes

### Self-Signed Mode (default)

```caddyfile
# /root/lobsec/config/Caddyfile.self-signed
{
    auto_https off
    log {
        level WARN
    }
}

:443 {
    # External TLS: self-signed cert from lobsec internal CA
    tls /etc/lobsec/tls/external/server.crt /etc/lobsec/tls/external/server.key {
        protocols tls1.3
        ciphers TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256
    }

    # Security headers
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'"
        -Server
    }

    # Rate limiting
    rate_limit {remote.ip} 60r/m

    # Request size cap (10 MB)
    request_body {
        max_size 10MB
    }

    # WebSocket: validate Origin
    @ws_upgrade {
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @ws_upgrade {
        @bad_origin {
            not header Origin "https://localhost"
            not header Origin "https://127.0.0.1"
            not header Origin ""
        }
        respond @bad_origin 403

        # Forward to gateway via mTLS on internal network
        reverse_proxy https://openclaw-gateway:18789 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }

    # Webhooks: forward to lobsec-proxy for validation
    handle /webhook/* {
        reverse_proxy https://lobsec-proxy:8082 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }

    # Default: forward to gateway
    handle {
        reverse_proxy https://openclaw-gateway:18789 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }
}
```

### ACME Mode (Let's Encrypt)

```caddyfile
# /root/lobsec/config/Caddyfile.acme
{
    email {$ACME_EMAIL}

    # Default: Let's Encrypt
    # Override with ACME_CA env var for other CAs
    acme_ca {$ACME_CA:https://acme-v02.api.letsencrypt.org/directory}

    # DNS-01 challenge (no open ports needed)
    # Set ACME_DNS_PROVIDER and credentials via env
    acme_dns {$ACME_DNS_PROVIDER:cloudflare} {
        api_token {$ACME_DNS_API_TOKEN}
    }

    log {
        level WARN
    }
}

{$LOBSEC_DOMAIN} {
    tls {
        protocols tls1.3
        ciphers TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256
    }

    # Security headers (same as self-signed)
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'"
        -Server
    }

    rate_limit {remote.ip} 60r/m
    request_body { max_size 10MB }

    @ws_upgrade {
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @ws_upgrade {
        @bad_origin {
            not header Origin "https://{$LOBSEC_DOMAIN}"
            not header Origin ""
        }
        respond @bad_origin 403

        reverse_proxy https://openclaw-gateway:18789 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }

    handle /webhook/* {
        reverse_proxy https://lobsec-proxy:8082 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }

    handle {
        reverse_proxy https://openclaw-gateway:18789 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }
}
```

### Custom CA Mode

```caddyfile
# /root/lobsec/config/Caddyfile.custom
{
    auto_https off
    log {
        level WARN
    }
}

{$LOBSEC_DOMAIN} {
    # User-provided certificate
    tls /etc/lobsec/tls/external/cert.pem /etc/lobsec/tls/external/key.pem {
        protocols tls1.3
        ciphers TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256

        # Include chain if provided
        # chain /etc/lobsec/tls/external/chain.pem
    }

    # ... (same handler config as above) ...
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'"
        -Server
    }

    rate_limit {remote.ip} 60r/m
    request_body { max_size 10MB }

    @ws_upgrade {
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @ws_upgrade {
        @bad_origin {
            not header Origin "https://{$LOBSEC_DOMAIN}"
            not header Origin ""
        }
        respond @bad_origin 403

        reverse_proxy https://openclaw-gateway:18789 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }

    handle /webhook/* {
        reverse_proxy https://lobsec-proxy:8082 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }

    handle {
        reverse_proxy https://openclaw-gateway:18789 {
            transport http {
                tls
                tls_client_auth /etc/lobsec/tls/server.crt /etc/lobsec/tls/server.key
                tls_trusted_ca_certs /etc/lobsec/tls/ca.crt
            }
        }
    }
}
```

---

## Design Verification Checklist

| # | Item | Status |
|---|------|--------|
| 1 | `fscrypt` available on Ubuntu 24.04, works with ext4 `encrypt` feature | `[NEEDS VERIFICATION]` |
| 2 | fscrypt unlock/lock works with raw key protector (programmatic, no PAM) | `[NEEDS VERIFICATION]` |
| 3 | LUKS2 with argon2id on Jetson Orin (aarch64) | `[NEEDS VERIFICATION]` |
| 4 | TPM2 auto-unlock (`systemd-cryptenroll`) on target hardware | `[NEEDS VERIFICATION]` |
| 5 | OpenSSL PKCS#11 engine for CA signing (`openssl req -engine pkcs11`) | `[NEEDS VERIFICATION]` |
| 6 | Caddy DNS-01 challenge with Cloudflare plugin | Available (confirmed Caddy docs list it) |
| 7 | Caddy `transport http { tls }` for mTLS to upstream (internal containers) | `[NEEDS VERIFICATION]` |
| 8 | OpenClaw respects `NODE_EXTRA_CA_CERTS` for internal CA trust | `[NEEDS VERIFICATION]` |
| 9 | OpenClaw works over HTTPS proxy (not just HTTP) | `[NEEDS VERIFICATION]` |
| 10 | Docker bind mount of tmpfs certs -- containers see cert updates without restart? | `[NEEDS VERIFICATION]` -- may need volume or signal |
| 11 | Caddy PKCS#11 plugin for HSM-stored external TLS key | `[NEEDS VERIFICATION]` |
| 12 | AES-NI available on target x86 host; ARMv8-CE on Jetson | `[NEEDS VERIFICATION]` -- performance impact |

---

## ADR Impact

This document creates:

**ADR-9: Encryption everywhere -- LUKS + fscrypt + mTLS**

**Decision:** Triple-layer encryption at rest (LUKS2 full-disk + fscrypt per-directory + HSM for credentials) and universal encryption in transit (external TLS 1.3 + internal mTLS + encrypted Ollama connections).

**Rationale:** The user requires paranoid-level security. No byte should be readable by an unauthorized party, whether the threat is physical disk theft (LUKS), a running attacker with limited filesystem access (fscrypt), a network sniffer on the Docker bridge (mTLS), or a compromised container (credentials only in HSM + lobsec-proxy memory).

**Status:** DESIGN DRAFT. Needs verification items resolved before implementation.

**ADR-10: Certificate management -- three tiers**

**Decision:** Self-signed (default), ACME/Let's Encrypt (public default), and custom CA support. Internal mTLS always uses HSM-backed self-signed CA. All certificates on tmpfs (RAM only).

**Rationale:** Different deployment environments need different cert strategies. Development/local needs zero-config self-signed. Production with domain needs automated public CA. Enterprise needs custom CA. Internal mTLS is always self-signed because it never needs public trust.

**Status:** DESIGN DRAFT.
