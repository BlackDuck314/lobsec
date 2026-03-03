# Codebase Conventions

## Overview

This document describes the code style, naming patterns, error handling, and TypeScript patterns used throughout the lobsec monorepo (packages: cli, plugin, proxy, shared, tools).

---

## TypeScript Configuration

**File:** `/root/lobsec/tsconfig.base.json`

- **Target:** ES2024
- **Module System:** NodeNext (ES modules)
- **Strict Mode:** Enabled (`strict: true`)
- **Additional Strictness:**
  - `noUncheckedIndexedAccess: true` — require bounds checking on indexed access
  - `noEmitOnError: true` — no emit if type errors occur
  - `isolatedModules: true` — each file can be transpiled independently
  - `verbatimModuleSyntax: true` — preserve import/export syntax exactly
- **Declarations:** Generated with source maps
- **Resolved JSON Modules:** Enabled

---

## Code Organization & File Structure

### Folder Pattern

```
packages/{name}/src/
  ├── *.ts              — Implementation files
  ├── *.test.ts         — Test files (colocated)
  ├── types/            — Shared type definitions
  └── index.ts          — Public exports
```

### Import Organization

```typescript
// 1. Node.js built-ins (absolute)
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

// 2. Local imports (relative, .js extensions required for ESM)
import { MockHsmClient } from "./hsm-client.js";
import type { HsmKeyAttributes } from "./hsm-client.js";

// 3. Monorepo packages (absolute, @lobsec scope)
import type { IHsmClient } from "@lobsec/shared";
import { ROTATION_SCHEDULES } from "@lobsec/shared";
```

**Key Rule:** All relative imports in ESM use `.js` extensions (even for `.ts` source files).

---

## Naming Conventions

### Interfaces & Types

- **Interfaces:** PascalCase with `I` prefix for abstractions
  - `IHsmClient` — main HSM interface
  - `InjectionMethod` — union type (no prefix)

- **Type Aliases:** PascalCase, no prefix
  - `CredentialType` — discriminated union
  - `LuksUnlockMethod` — union of string literals

- **Generic Types:** Single letter or descriptive
  - `T` — standard generic
  - `Event` — context-specific

### Classes

- **PascalCase**
  - `CredentialManager`
  - `MockHsmClient`
  - `LuksManager`

### Functions & Methods

- **camelCase**
  - `getKeyInfo()`
  - `generateKeyPair()`
  - `listCredentials()`
  - Helper functions: `makeAttrs()`, `createManager()`

### Constants & Config Objects

- **UPPER_SNAKE_CASE** for constants
  - `ROTATION_SCHEDULES`
  - `LUKS_DEFAULTS`
  - `FSCRYPT_DEFAULTS`

- **camelCase for config/spec objects**
  - `DEFAULT_CREDENTIAL_SPECS`
  - `FSCRYPT_DIRECTORIES`

### Private Members

- **`private` keyword** for class fields and methods (TypeScript visibility)
  - `private initialized = false`
  - `private ensureInitialized(): void`
  - `private log(...): void`

### Callbacks & Event Handlers

- **Named callbacks in config objects**
  - `onAccess?: CredentialAccessCallback`
  - `onEvent?: (event: CredentialLifecycleEvent) => void`

---

## Error Handling

### Error Throwing

- **Throw descriptive Error objects, never bare strings**
  ```typescript
  throw new Error(`Key not found: ${label}`);
  throw new Error(`Key ${label} is not extractable`);
  ```

- **Include context:** variable name, type, or operation in message

- **Never leak secrets in errors:** Log key labels only, never values

### Error Suppression

- **Use try/catch in cleanup code** that may fail
  ```typescript
  try {
    unlinkSync(fullPath);
  } catch {
    // File may already be gone
  }
  ```

- **Comment clarifies intent:** "may already be gone", "may not exist", etc.

### Async Error Handling

- Use `await` with error boundaries for HSM operations
- Propagate errors unless cleanup is involved
  ```typescript
  try {
    await this.config.hsm.exportKey(label);
  } catch {
    this.emitEvent("load", label, spec.type, spec.injectionMethod, false, "HSM export failed");
    return false;
  }
  ```

---

## TypeScript Patterns

### Interfaces with Documentation

- **JSDoc comments for every interface member**
  ```typescript
  export interface HsmKeyAttributes {
    /** Key label in HSM. */
    label: string;
    /** Whether the key can be extracted from HSM. */
    extractable: boolean;
  }
  ```

### Type Guards & Narrowing

- **Use discriminated unions** for credential types
  ```typescript
  export type CredentialType = "llm-api-key" | "channel-token" | "webhook-secret" | ...;
  ```

- **Switch statements over if/else** for exhaustive matching
  ```typescript
  switch (spec.injectionMethod) {
    case "env": { ... }
    case "tmpfs-file": { ... }
    case "hsm-only": { ... }
    default: ... // TypeScript ensures exhaustiveness
  }
  ```

### Readonly Collections

- **Use `Readonly<>` for immutable defaults**
  ```typescript
  export const LUKS_DEFAULTS: Readonly<Omit<LuksConfig, "device" | "mapperName">> = {
    cipher: "aes-xts-plain64",
    keySize: 512,
  };
  ```

- **Use `as const` for tuple/literal safety**
  ```typescript
  export const FSCRYPT_DIRECTORIES = ["workspace", "agents", "logs", "canvas"] as const;
  ```

### Optional & Nullable

- **Use `?:` for optional properties**
  ```typescript
  envVar?: string;
  detail?: string;
  ```

- **Use `| undefined` for explicitly nullable fields**
  ```typescript
  createdAt?: string;  // optional
  export async function getKeyInfo(...): Promise<HsmKeyInfo | undefined>;
  ```

### Factory Functions & Helpers

- **Named factory functions for test setup**
  ```typescript
  function makeAttrs(overrides: Partial<HsmKeyAttributes> = {}): HsmKeyAttributes {
    return { label: "test-key", extractable: true, ...overrides };
  }
  ```

- **Return object destructuring for multiple values**
  ```typescript
  return { manager, hsm, accessLog, events };
  ```

### Async Patterns

- **Always return `Promise<T>` for async functions**
  ```typescript
  async initialize(modulePath: string, slotIndex: number, pin: string): Promise<void>
  async generateKey(attrs: HsmKeyAttributes): Promise<HsmKeyInfo>
  async loadFromHsm(label: string): Promise<boolean>
  ```

- **Use `Promise<boolean>` for success/failure**, not `Promise<void | T>`

---

## Comments & Documentation

### Header Comments (Layer Markers)

Each file begins with a layer comment:
```typescript
// ── PKCS#11 HSM Client (L6) ─────────────────────────────────────────────────
// Abstracts HSM operations behind a portable interface.
// SoftHSM2 for dev, YubiHSM2 for prod — only LOBSEC_PKCS11_MODULE changes.
```

### Section Dividers

```typescript
// ── Types ───────────────────────────────────────────────────────────────────
// ── Credential Manager ──────────────────────────────────────────────────────
// ── Unit: Key generation ──────────────────────────────────────────────────
```

### Inline Comments

- **Explain why, not what**
  ```typescript
  // Non-extractable credentials stay in HSM (e.g., webhook secrets)
  if (!spec.extractable) { ... }
  ```

- **Keep comments short and tied to adjacent code**

### No Secrets in Comments

- Never include example credentials, keys, or API keys in source

---

## Class Patterns

### Property Initialization

- **Private fields initialized in constructor or at declaration**
  ```typescript
  private initialized = false;
  private keys = new Map<string, KeyData>();
  private specs = new Map<string, CredentialSpec>();
  ```

- **Use getters for derived or lazy properties**
  ```typescript
  get isInitialized(): boolean {
    return this.initialized;
  }
  ```

### Method Order

1. Constructor
2. Public accessors (getters/setters)
3. Public methods (grouped by concern)
4. Private methods
5. Helper logging methods

### Event Emission

- **Delegate to optional callbacks passed in config**
  ```typescript
  private emitEvent(...): void {
    this.config.onEvent?.({ action, label, type, injectionMethod, success, detail });
  }
  ```

---

## Cleanup & Lifecycle

### Destruction Patterns

- **Guard against double cleanup**
  ```typescript
  async cleanup(): Promise<void> {
    if (this.destroyed) return;
    // ... cleanup logic
    this.destroyed = true;
  }
  ```

- **Clear all injected state comprehensively**
  - Env vars: `delete process.env[key]`
  - Files: `unlinkSync()` with try/catch
  - HSM keys: `destroyKey()` in loop
  - Runtime store: `store.destroy()`

### Resource Cleanup Pattern

```typescript
for (const [label, spec] of this.specs) {
  try {
    await this.config.hsm.destroyKey(label);
  } catch {
    // Key may not exist
  }
  this.emitEvent("cleanup", label, spec.type, spec.injectionMethod, true);
}
```

---

## Monorepo & Build

- **Root config:** `/root/lobsec/tsconfig.base.json`
- **Workspace:** `/root/lobsec/pnpm-workspace.yaml` (pnpm monorepo)
- **Package manager:** pnpm 10.x
- **Linter:** oxlint (configured per-package)
- **Module resolution:** ES modules with NodeNext strategy

