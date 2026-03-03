# Technology Stack — lobsec

Generated: 2026-03-03

## Runtime & Language

| Component | Version | Notes |
|-----------|---------|-------|
| **Node.js** | >= 22.0.0 LTS | Target: ES2024, strict ESM modules |
| **TypeScript** | ^5.7.0 | Strict mode, verbatim module syntax, declaration maps |
| **pnpm** | >= 9.0.0 | Monorepo package manager |

## Compiler & Type System

**tsconfig.base.json** (shared base configuration):
- **Target**: ES2024
- **Module System**: NodeNext with NodeNext resolution
- **Library**: ES2024
- **Output**: Declaration maps, source maps enabled
- **Strict Checks**:
  - `strict: true`
  - `noUncheckedIndexedAccess: true`
  - `noEmitOnError: true`
  - `verbatimModuleSyntax: true` (no implicits, explicit import/export)
  - `isolatedModules: true` (each file independent)
- **Emit**: `declaration: true`, `declarationMap: true`, `sourceMap: true`
- **Root**: `src/`, Output: `dist/`

## Monorepo Structure

**pnpm workspace** (packages/):
- `packages/plugin` — OpenClaw plugin hooks (tool validation, credential redaction, sovereign routing)
- `packages/proxy` — LLM proxy (credential isolation, routing, egress firewall)
- `packages/shared` — Shared infra (HSM, encryption, monitoring, audit logging)
- `packages/cli` — CLI orchestrator (lifecycle management, systemd integration)
- `packages/tools` — Tool adapters (email, calendar, weather, OpenClaw bridge)

## Build & Testing Infrastructure

| Tool | Version | Purpose |
|------|---------|---------|
| **Vitest** | ^4.0.18 | Unit + integration tests (680+ tests across 29 files) |
| **oxlint** | ^1.50.0 | Fast JavaScript/TypeScript linter (0 warnings) |
| **fast-check** | ^4.5.3 | Property-based testing framework |
| **TypeScript** | ^5.7.0 | Type checking (`tsc --noEmit` in CI) |
| **@types/node** | ^25.3.2 | Node.js type definitions |

**Test Configuration** (vitest.config.ts):
- Test runner for all packages via `pnpm test`
- Coverage support via `pnpm test:coverage`
- Watch mode: `pnpm test:watch`

**Build Pipeline**:
- Each package: `pnpm build` → runs `tsc` → outputs to `dist/`
- Monorepo: `pnpm -r build` (recursive all packages)
- Type checking: `pnpm -r typecheck` (all packages)
- Linting: `oxlint .` (all source)

## Production Dependencies

### @lobsec/cli

| Package | Version | Purpose |
|---------|---------|---------|
| **pino** | ^10.3.1 | Structured JSON logging with levels |
| **pino-pretty** | ^13.0.0 | Pretty-print Pino logs (dev/debug) |
| **commander** | ^14.0.3 | CLI argument parsing & command routing |
| **@lobsec/shared** | workspace:* | Shared services (encryption, HSM, audit) |

### @lobsec/tools

| Package | Version | Purpose |
|---------|---------|---------|
| **nodemailer** | ^8.0.1 | Email transport (SMTP + TLS) |
| **@types/nodemailer** | ^6.4.0 | Type definitions (dev only) |

### @lobsec/plugin

- **@lobsec/shared** (workspace)
- No external runtime dependencies (minimal footprint for OpenClaw plugin)

### @lobsec/proxy

- **@lobsec/shared** (workspace)
- **node:http** (built-in) — HTTP server, request handling
- **node:crypto** (built-in) — HMAC, timing-safe comparison, Ed25519 verification
- **node:fs/promises** (built-in) — File operations
- **node:path** (built-in) — Path utilities

### @lobsec/shared

- **node:crypto** (built-in) — Encryption, hashing, key derivation
- **node:fs/promises** (built-in) — File I/O
- **node:os** (built-in) — System info
- **node:path** (built-in) — Path utilities
- **node:child_process** (built-in) — Subprocess execution (fscrypt, cryptsetup, systemctl)
- **node:http** / **node:https** (built-in) — HTTP client
- **node:util** (built-in) — Utilities

## Configuration Files

| File | Purpose |
|------|---------|
| **pnpm-workspace.yaml** | Monorepo declaration (packages/*) |
| **tsconfig.base.json** | Shared TypeScript compiler options |
| **vitest.config.ts** | Test runner configuration |
| **.env** (gitignored) | Runtime environment variables (secrets) |
| **pnpm-lock.yaml** | Lockfile for reproducible installs |

## Development Dependencies (Root)

| Package | Version | Purpose |
|---------|---------|---------|
| **@types/node** | ^25.3.2 | Node.js type definitions |
| **fast-check** | ^4.5.3 | Property-based testing |
| **oxlint** | ^1.50.0 | Linting |
| **typescript** | ^5.7.0 | Type checking |
| **vitest** | ^4.0.18 | Test framework |

## Module System

- **ESM (ES Modules)** only
- `"type": "module"` in all package.json files
- No CommonJS/UMD builds
- Import extensions required (`.js` for internal modules)

## Deployment Environment

- **Container**: Docker (rootless, with seccomp whitelist profile)
- **Base image**: `lobsec-sandbox:hardened` (74.8MB, Alpine-based)
- **Orchestration**: systemd (no Docker Compose, native service management)
- **Secrets**: SoftHSM2 token (HSM-backed credential store)
- **Encryption**: fscrypt (AES-256-XTS) + optional LUKS (full-disk)

## Code Quality Metrics

- **680+ tests** passing (Vitest)
- **0 lint warnings** (oxlint)
- **100% strict TypeScript** (noUncheckedIndexedAccess, verbatimModuleSyntax)
- **Type-safe workspace imports** (workspace:* protocol in pnpm)

## Key Implementation Details

### Logging
- Pino for structured logging (JSON format in production, pretty in dev)
- Pino-pretty only imported in CLI package (not in production services)

### CLI Framework
- commander.js for argument parsing (subcommands, flags, help)

### Email Transport
- nodemailer with TLS support (SMTP backend)
- Optional auth (user/password or OAuth2)

### Crypto Primitives
- Node.js built-in crypto module exclusively
- No external crypto libraries (minimize attack surface)
- Implementations: HMAC-SHA256, Ed25519, P-256/ECDSA, AES-256-GCM, scrypt KDF

### HTTP/Network
- Node.js http module (no Express, no Fastify)
- Custom proxy implementation (control over headers, auth, routing)
- Built-in fetch API (Node 22+)

## No External Dependencies Pattern

Intentional design:
- **@lobsec/plugin**: Zero production dependencies (OpenClaw plugin constraint)
- **@lobsec/proxy**: Only Node.js built-ins (security-sensitive component)
- **@lobsec/shared**: Only Node.js built-ins (core crypto/system ops)
- **@lobsec/cli**: Only pino, commander (logging + CLI framework)
- **@lobsec/tools**: Only nodemailer (bridge to SMTP)

This minimizes supply-chain risk and simplifies auditability.
