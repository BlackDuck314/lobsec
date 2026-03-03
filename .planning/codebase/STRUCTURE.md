# lobsec Directory & File Structure

## Root Directory Layout

```
/root/lobsec/
├── .git/                          # Git repository
├── .github/                       # GitHub workflows, issue templates
├── .planning/                     # Planning & documentation (THIS FILE HERE)
│   └── codebase/
│       ├── ARCHITECTURE.md        # Architectural patterns & data flow
│       └── STRUCTURE.md           # This file
├── .claude/                       # Claude Code agent memory
├── deploy/                        # Deployment scripts & configurations
├── docs/                          # User-facing documentation
├── packages/                      # pnpm monorepo workspaces
│   ├── plugin/                    # OpenClaw plugin (security hooks)
│   ├── proxy/                     # LLM request proxy
│   ├── shared/                    # Shared infrastructure
│   ├── cli/                       # CLI orchestrator
│   └── tools/                     # Optional utility tools
├── package.json                   # Workspace root (pnpm)
├── pnpm-workspace.yaml            # Workspace configuration
├── pnpm-lock.yaml                 # Dependency lock file
├── tsconfig.json                  # Root TypeScript config
├── README.md                      # Project README
├── LICENSE                        # MIT license
├── CHANGELOG.md                   # Version history
├── CODE_OF_CONDUCT.md             # Community guidelines
├── CONTRIBUTING.md                # Development guide
├── CLAUDE.md                      # AI agent instructions
└── .env                           # Environment (git-ignored)
```

---

## Monorepo Structure: `/root/lobsec/packages/`

### Package: `plugin` — OpenClaw Plugin Hooks

```
packages/plugin/
├── package.json                   # @lobsec/plugin v0.1.0
├── tsconfig.json                  # TypeScript config (strict mode)
├── src/
│   ├── index.ts                   # Public exports (47 items)
│   ├── hook-registry.ts           # Hook system (HookRegistry class, 9 hooks)
│   ├── hook-registry.test.ts      # Hook tests (registration, priority, execution)
│   ├── tool-validator.ts          # Tool call validation (deny-list, symlinks)
│   ├── tool-validator.test.ts     # Validation tests
│   ├── credential-redactor.ts     # PII/credential pattern matching
│   ├── credential-redactor.test.ts # Redaction tests
│   ├── sovereign-router.ts        # Local-first inference routing
│   ├── sovereign-router.test.ts   # Routing tests
│   ├── config-monitor.ts          # Config drift detection & alerts
│   └── config-monitor.test.ts     # Monitor tests
├── openclaw-adapter/
│   └── index.ts                   # Adapter to integrate into OpenClaw
└── dist/                          # Compiled output (tsc)
    ├── index.js
    ├── index.d.ts
    ├── hook-registry.js
    ├── hook-registry.d.ts
    ├── ... (other compiled files)
    └── openclaw-adapter/
```

**Key Exports**: `HookRegistry`, `ToolValidator`, `CredentialRedactor`, `SovereignRouter`, `ConfigMonitor`

**Hook Names** (9 total):
- `pre-tool` — Before tool execution
- `post-tool` — After tool execution
- `pre-message` — Before message processing
- `post-message` — After message processing
- `credential-required` — When credential needed
- `config-drift` — Config change detected
- `audit-event` — Audit entry created
- `backend-unavailable` — Backend failure
- `degradation-started` — Service degradation

---

### Package: `proxy` — LLM Request Proxy

```
packages/proxy/
├── package.json                   # @lobsec/proxy v0.1.0
├── tsconfig.json                  # TypeScript config
├── src/
│   ├── index.ts                   # Public exports (17 items)
│   ├── server.ts                  # Express/WebSocket server (createProxyServer, startProxyFromEnv)
│   ├── credential-manager.ts      # JIT credential lifecycle (pull → inject → revoke)
│   ├── credential-manager.test.ts # Credential lifecycle tests
│   ├── credential-store.ts        # In-memory credential cache
│   ├── credential-store.test.ts   # Store tests
│   ├── llm-router.ts              # Provider detection, token estimation, routing
│   ├── llm-router.test.ts         # Router tests
│   ├── backend-manager.ts         # Health checks, budget, failover
│   ├── backend-manager.test.ts    # Backend tests
│   ├── egress-firewall.ts         # IP allowlist, metadata service blocking
│   ├── egress-firewall.test.ts    # Firewall tests
│   ├── webhook-validator.ts       # Telegram/Slack/Discord signature validation
│   └── webhook-validator.test.ts  # Webhook tests
└── dist/                          # Compiled output
```

**Key Exports**: `createProxyServer`, `startProxyFromEnv`, `CredentialManager`, `BackendManager`, `LlmRouter`

**Entry Points**:
- HTTP POST `/api/v1/llm/request` — LLM inference request
- HTTP GET `/health` — Health probe
- Environment: `PROXY_PORT`, `PROXY_AUTH_TOKEN`, `HSM_*` vars

---

### Package: `shared` — Foundational Infrastructure

```
packages/shared/
├── package.json                   # @lobsec/shared v0.1.0 (no external deps!)
├── tsconfig.json                  # TypeScript config
├── src/
│   ├── index.ts                   # Public exports (130+ items: types + utils)
│   │
│   ├── types/                     # Type definitions (no logic)
│   │   ├── config.ts              # LobsecConfig (encryption, routing, alerts)
│   │   ├── config.test.ts         # Config validation tests
│   │   ├── credential.ts          # CredentialType, CredentialMeta, rotation schedules
│   │   ├── log.ts                 # LogLevel, AuditEventType, LogEntry, ErrorDetail
│   │   ├── log.test.ts            # Log validation tests
│   │   └── openclaw-config.ts     # HardenedOpenClawConfig, deny-lists, dangerous flags
│   │
│   ├── logger.ts                  # Logger class (structured JSONL, redaction, trace IDs)
│   ├── logger.test.ts             # Logger tests (formatting, redaction patterns)
│   │
│   ├── config-generator.ts        # generateHardenedConfig, substituteCredentials
│   ├── config-generator.test.ts   # Config generation tests
│   │
│   ├── drift-detector.ts          # hashConfig, detectDrift, parseSecurityAudit
│   ├── drift-detector.test.ts     # Drift detection tests (cron, heartbeat, hash)
│   │
│   ├── hsm-client.ts              # MockHsmClient (SoftHSM2 interface)
│   ├── hsm-client.test.ts         # HSM operation tests (key generation, signing)
│   │
│   ├── cert-manager.ts            # CertManager (ACME/custom TLS, P-256/ECDSA, 30-day renewal)
│   ├── cert-manager.test.ts       # Certificate lifecycle tests
│   │
│   ├── encryption.ts              # LuksManager, FscryptManager (AES-256-XTS)
│   ├── encryption.test.ts         # Encryption startup/shutdown tests
│   │
│   ├── audit-signer.ts            # AuditSigner (HSM RSA-2048, hash-chain signing)
│   ├── audit-signer.test.ts       # Audit signing & verification tests
│   │
│   ├── container-orchestrator.ts  # ContainerOrchestrator (Docker lifecycle, startup order)
│   ├── container-orchestrator.test.ts # Container tests
│   │
│   ├── backup.ts                  # BackupManager (manifests, snapshots, restore)
│   ├── backup.test.ts             # Backup tests
│   │
│   ├── resilience.ts              # RetryWithBackoff, CircuitBreaker, DegradationManager
│   ├── resilience.test.ts         # Resilience pattern tests
│   │
│   ├── monitor.ts                 # SystemMonitor (health checks, alerts, metrics)
│   ├── monitor.test.ts            # Monitor tests
│   │
│   ├── network-perimeter.ts       # nftables rules, port validation, MDNS suppression
│   ├── network-perimeter.test.ts  # Network tests
│   │
│   ├── caddy-config.ts            # generateCaddyfile (L2 proxy, security headers)
│   ├── caddy-config.test.ts       # Caddy config tests
│   │
│   ├── pkcs11-tool-client.ts      # PKCS#11 CLI client wrapper
│   └── performance.test.ts        # Benchmark tests
│
└── dist/                          # Compiled output (tsc)
```

**Key Exports** (130+):
- Types: `LobsecConfig`, `CredentialType`, `LogLevel`, `AuditEventType`, `HsmKeyInfo`, `CertInfo`, `ContainerConfig`, etc.
- Classes: `Logger`, `CertManager`, `LuksManager`, `FscryptManager`, `AuditSigner`, `CircuitBreaker`, `SystemMonitor`, `BackupManager`, `ContainerOrchestrator`
- Functions: `generateHardenedConfig`, `detectDrift`, `generateNftablesRules`, `generateCaddyfile`, `retryWithBackoff`, `canonicalHash`, etc.

**Test Coverage**: 19 test files, 350+ test cases, zero external dependencies (MockHsmClient for testing).

---

### Package: `cli` — Lifecycle Orchestrator

```
packages/cli/
├── package.json                   # @lobsec/cli v0.1.0
│                                  # bin: lobsec → dist/index.js
│                                  # deps: @lobsec/shared, pino, pino-pretty, commander
├── tsconfig.json                  # TypeScript config
├── src/
│   ├── index.ts                   # CLI entry point (#!/usr/bin/env node)
│   │                              # Commands: init, start, stop, status, logs
│   │
│   ├── commands/
│   │   ├── init.ts                # lobsec init (bootstrap HSM, generate config)
│   │   ├── start.ts               # lobsec start (unlock encryption, start services)
│   │   ├── stop.ts                # lobsec stop (graceful shutdown)
│   │   ├── status.ts              # lobsec status (health probes)
│   │   ├── status.test.ts         # Status tests
│   │   ├── logs.ts                # lobsec logs (tail audit log, filter, verify signatures)
│   │   └── logs.test.ts           # Logs tests
│   │
│   ├── orchestrator.ts            # Orchestrator (startup/shutdown order, health checks)
│   ├── orchestrator.test.ts       # Orchestrator tests
│   │
│   ├── lifecycle.ts               # Lifecycle state machine (encryption → HSM → gateway)
│   ├── lifecycle.test.ts          # Lifecycle tests
│   │
│   ├── output.ts                  # Output formatters (JSON, human-readable)
│   └── ... (util modules)
│
└── dist/                          # Compiled output (tsc)
```

**CLI Commands**:

| Command | Purpose | Options |
|---------|---------|---------|
| `lobsec init` | One-time setup: generate configs, bootstrap HSM | `--config-path`, `--hsm-token` |
| `lobsec start` | Start gateway + proxy + audit-signer | `--config-path`, `--foreground` |
| `lobsec stop` | Graceful shutdown | `--config-path`, `--force` |
| `lobsec status` | Health check (gateway, proxy, HSM, audit) | `--json` |
| `lobsec logs` | Tail & verify audit logs | `--since`, `--component`, `--severity` |

**Global Flags**:
- `--json` — Output in JSON format
- `--verbose` — Enable verbose logging

---

### Package: `tools` — Utility Tools (Optional)

```
packages/tools/
├── package.json                   # @lobsec/tools v0.1.0
├── src/
│   ├── index.ts                   # Placeholder exports
│   └── ... (email, webhook dispatchers)
└── dist/
```

**Status**: Placeholder; not deployed in current phase.

---

## Configuration Directories

### Development (`/root/lobsec/`)

```
.env                              # Local env vars (git-ignored)
tsconfig.json                     # Root TypeScript config
  extends from packages/*/tsconfig.json
```

### Deployment (`/opt/lobsec/` on production server)

```
/opt/lobsec/
├── boot/                         # Bootstrap (unencrypted, required at boot)
│   ├── softhsm2.conf            # SoftHSM2 token paths
│   ├── pin.env                  # HSM PIN
│   └── fscrypt-key.bin          # Master encryption key
│
├── openclaw/                    # Upstream OpenClaw (NOT modified by lobsec)
│   ├── package.json
│   ├── dist/
│   └── ...
│
├── .openclaw/                   # OpenClaw config + data (fscrypt encrypted)
│   ├── config.json              # Hardened OpenClaw config
│   └── data/                    # Message history, plugins
│
├── plugins/
│   └── lobsec-security/         # Deployed @lobsec/plugin
│       ├── index.js
│       ├── index.d.ts
│       └── ...
│
├── proxy/                       # Deployed @lobsec/proxy
│   ├── dist/
│   └── config.json
│
├── hsm/                         # SoftHSM2 persistent tokens (fscrypt encrypted)
│   └── tokens/
│       └── ... (token files)
│
├── logs/                        # Audit logs (fscrypt encrypted)
│   ├── audit.jsonl              # Unsigned entries
│   └── audit-signed/            # Signed batches
│       ├── batch-001.json
│       ├── batch-001.sig
│       └── ...
│
├── run/                         # Runtime state
│   ├── certs/                   # mTLS certificates (self-signed CA + leaf)
│   │   ├── ca.pem
│   │   ├── ca-key.pem
│   │   ├── lobsec-gateway.pem
│   │   └── lobsec-gateway-key.pem
│   └── health/                  # Health check state
│
└── bin/                         # Scripts
    ├── fscrypt-unlock           # Unlock encrypted dirs
    ├── audit-sign               # Batch sign audit logs
    ├── hsm-extract              # Extract credentials from HSM
    ├── mtls-gen                 # Generate mTLS certs
    └── ...
```

---

## Test File Organization

All test files use `.test.ts` suffix, co-located with source:

```
packages/[package]/src/
├── module.ts
├── module.test.ts               # Tests for module.ts
├── subdir/
│   ├── feature.ts
│   └── feature.test.ts
└── ...
```

**Test Framework**: Vitest
- Config: `vitest.config.ts` (root)
- Run: `pnpm test` (all packages)
- Coverage: `pnpm test:coverage`

**Test Counts by Package**:
- `@lobsec/shared`: 12 test files (~300 cases)
- `@lobsec/plugin`: 5 test files (~80 cases)
- `@lobsec/proxy`: 6 test files (~100 cases)
- `@lobsec/cli`: 3 test files (~40 cases)
- **Total**: 29 test files, 680+ test cases

---

## TypeScript Configuration

### Root: `/root/lobsec/tsconfig.json`

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "lib": ["ES2022"],
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist"
  },
  "include": ["src/**/*"],
  "exclude": ["dist", "node_modules", "**/*.test.ts"]
}
```

**Strict Mode**: All packages enforce `strict: true` (no any, implicit types, etc.).

---

## Import Patterns

### Intra-Package Imports

```typescript
// Within @lobsec/shared:
import { Logger } from "./logger.js";
import type { LogEntry } from "./types/log.js";
```

### Inter-Package Imports

```typescript
// In @lobsec/plugin:
import { Logger, generateHardenedConfig } from "@lobsec/shared";

// In @lobsec/proxy:
import { generateHardenedConfig, AuditSigner } from "@lobsec/shared";
```

**Rule**: All packages import from `@lobsec/shared`. Sibling packages DO NOT import each other.

---

## Build & Distribution

### Development Build

```bash
pnpm build                        # tsc in all packages
# Output: packages/*/dist/
```

### Production Build

Compiled packages deployed to `/opt/lobsec/`:
- `@lobsec/plugin` → `/opt/lobsec/plugins/lobsec-security/`
- `@lobsec/proxy` → `/opt/lobsec/proxy/`
- `@lobsec/cli` → `/opt/lobsec/bin/lobsec` (executable)

### Publishing

Currently **not published to npm** (private monorepo). Distributed as:
1. Git clone + `pnpm install`
2. Docker multi-stage build
3. Direct systemd deployment

---

## Naming Conventions

### Files

- **Source**: `*.ts` (lowercase, hyphen-separated: `credential-redactor.ts`)
- **Tests**: `*.test.ts` (same name prefix as source)
- **Exports**: `index.ts` (public API per package)
- **Config**: `*.config.ts` or `*-config.ts`
- **Types**: Defined in source or `types/` subdir

### Classes

- PascalCase: `Logger`, `HookRegistry`, `CircuitBreaker`, `CertManager`
- Suffixes: `Manager`, `Handler`, `Validator`, `Router`, `Signer`, `Monitor`

### Functions

- camelCase: `generateHardenedConfig()`, `detectDrift()`, `retryWithBackoff()`
- Prefixes: `validate*`, `generate*`, `create*`, `is*`, `check*`

### Types

- PascalCase: `LogEntry`, `HookContext`, `RoutingDecision`, `CertInfo`
- Suffixes: `Config`, `Result`, `Event`, `Status`, `Options`, `Meta`

### Constants

- SCREAMING_SNAKE_CASE: `GENESIS_HASH`, `DEFAULT_RETRY_CONFIG`, `LOBSEC_HOOKS`

---

## Key File Locations

| Path | Purpose |
|------|---------|
| `/root/lobsec/packages/shared/src/types/` | All shared type definitions |
| `/root/lobsec/packages/shared/src/logger.ts` | Structured logging with redaction |
| `/root/lobsec/packages/shared/src/hsm-client.ts` | SoftHSM2 interface |
| `/root/lobsec/packages/shared/src/audit-signer.ts` | HSM-signed audit log batching |
| `/root/lobsec/packages/plugin/src/hook-registry.ts` | Hook system (9 hooks) |
| `/root/lobsec/packages/proxy/src/server.ts` | Proxy HTTP/WebSocket entry point |
| `/root/lobsec/packages/proxy/src/credential-manager.ts` | JIT credential lifecycle |
| `/root/lobsec/packages/cli/src/commands/` | CLI subcommands |
| `/root/lobsec/packages/cli/src/orchestrator.ts` | Startup/shutdown orchestration |
| `/root/lobsec/.planning/codebase/` | Architecture & structure docs (this repo) |

---

## Deployment Files (Not in Repo)

Generated at `/opt/lobsec/` on production:

```
/etc/systemd/system/lobsec.service              # Main gateway service
/etc/systemd/system/lobsec-proxy.service        # Proxy service
/etc/systemd/system/lobsec-audit-sign.{service,timer} # Audit signing timer
/opt/lobsec/boot/softhsm2.conf                  # HSM config
/opt/lobsec/boot/pin.env                        # HSM PIN (EnvironmentFile)
/opt/lobsec/.openclaw/config.json               # Hardened OpenClaw config
```

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| **Packages** | 4 active (plugin, proxy, shared, cli) + 1 placeholder (tools) |
| **Source Files** | 48 `.ts` files (excluding tests) |
| **Test Files** | 29 `.test.ts` files |
| **Total TypeScript** | 77 files |
| **Type Definitions** | 50+ types exported |
| **Classes** | 20+ public classes |
| **Functions** | 100+ utility functions |
| **Test Cases** | 680+ (Vitest) |
| **Lines of Code** | ~10,000 (source only, excluding tests) |
| **Dependencies** | 1 (pino, commander for CLI only) |
| **Dev Dependencies** | TypeScript, Vitest, oxlint, fast-check |
| **Node.js Version** | 22 LTS minimum |
| **TypeScript Strict** | Yes (all packages) |

---

## References

- **Workspace Config**: `/root/lobsec/pnpm-workspace.yaml`
- **Root Package**: `/root/lobsec/package.json` (scripts: build, test, lint, typecheck)
- **Individual Packages**: `/root/lobsec/packages/[name]/package.json`
- **Git Repo**: `/root/lobsec/.git/` (main branch)
- **Production Paths**: See ARCHITECTURE.md "Configuration" section
