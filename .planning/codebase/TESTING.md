# Testing Framework & Patterns

## Overview

This document describes the Vitest-based testing strategy, test structure, mocking patterns, and coverage expectations used across the lobsec monorepo.

---

## Test Framework: Vitest

**File:** `/root/lobsec/vitest.config.ts`

```typescript
{
  test: {
    globals: false,                    // Explicit imports (describe, it, expect)
    include: ["packages/*/src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["packages/*/src/**/*.ts"],
      exclude: ["**/*.test.ts", "**/*.d.ts"],
      thresholds: { lines: 80, functions: 80, branches: 80, statements: 80 },
    },
  },
}
```

### Key Configuration

- **No globals:** All test functions imported explicitly
  ```typescript
  import { describe, it, expect, beforeEach, afterEach } from "vitest";
  ```

- **Colocated tests:** `*.test.ts` files live beside implementation
- **V8 coverage:** V8 provider used for code coverage tracking
- **80% threshold:** All categories (lines, functions, branches, statements) must meet 80%

---

## Test Discovery & Organization

### File Naming

- **Test files:** `{module}.test.ts` colocated with `{module}.ts`
  ```
  packages/shared/src/
  ├── hsm-client.ts
  ├── hsm-client.test.ts
  ├── encryption.ts
  ├── encryption.test.ts
  └── ...
  ```

### Test Suites Organization

- **Group by describe block** with semantic names
  - `"MockHsmClient lifecycle"`
  - `"Key generation"`
  - `"Key import/export"`
  - `"Sign/Verify"`
  - `"Property 1: HSM backend portability"`

### Test Count

- **29 test files** across the monorepo
- **670+ tests total** (as of latest run)
- **0 lint warnings**

---

## Test Structure & Patterns

### Basic Unit Test Template

```typescript
describe("Feature name", () => {
  let resource: SomeClass;

  beforeEach(() => {
    resource = new SomeClass();
  });

  it("description of behavior", () => {
    // Arrange
    const input = ...;

    // Act
    const result = resource.method(input);

    // Assert
    expect(result).toBe(expected);
  });
});
```

### Setup & Teardown

- **beforeEach:** Initialize fresh instances/state before each test
  ```typescript
  beforeEach(() => {
    hsm = new MockHsmClient();
  });
  ```

- **afterEach:** Clean up files, env vars, temp directories
  ```typescript
  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    delete process.env["TEST_KEY"];
  });
  ```

### Async Test Pattern

```typescript
describe("Async operations", () => {
  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("completes async operation", async () => {
    const info = await hsm.generateKey(makeAttrs());
    expect(info.label).toBe("test-key");
  });
});
```

---

## Mocking & Test Doubles

### Mock Implementations

The codebase uses **explicit mock classes** (not mocking libraries):

- **MockHsmClient** (`packages/shared/src/hsm-client.ts`)
  - Implements `IHsmClient` interface fully
  - Uses `Map<string, KeyData>` for in-memory storage
  - Maintains `operationLog` for audit verification
  - No external HSM dependencies

```typescript
export class MockHsmClient implements IHsmClient {
  private initialized = false;
  private keys = new Map<string, { attrs: HsmKeyAttributes; data: Buffer }>();
  private operationLog: HsmOperationLog[] = [];

  async initialize(...): Promise<void> { ... }
  async generateKey(attrs): Promise<HsmKeyInfo> { ... }
  // ... full implementation
}
```

### Mock vs. Real

- **Use MockHsmClient for all unit tests** (no SoftHSM2 required)
- **Real HSM integration tests** deferred to deployment/manual verification
- **No jest.mock() or vi.mock()** — explicit dependency injection

### Test Helper Factories

Common pattern for creating test objects:

```typescript
function makeAttrs(overrides: Partial<HsmKeyAttributes> = {}): HsmKeyAttributes {
  return {
    label: "test-key",
    extractable: true,
    sensitive: true,
    keyType: "aes-256",
    forSigning: false,
    forEncryption: true,
    ...overrides,
  };
}

function createManager(tmpfsDir: string, events: CredentialLifecycleEvent[] = []) {
  const hsm = new MockHsmClient();
  const accessLog: string[] = [];
  const manager = new CredentialManager({
    tmpfsDir,
    hsm,
    onAccess: (label, _type, operation) => {
      accessLog.push(`${operation}:${label}`);
    },
    onEvent: (event) => {
      events.push(event);
    },
  });
  return { manager, hsm, accessLog, events };
}
```

---

## Assertion Patterns

### Vitest Matchers Used

```typescript
// Boolean
expect(bool).toBe(true);
expect(bool).toBe(false);

// Equality
expect(string).toBe("expected");
expect(array).toEqual([...]);
expect(obj).toEqual({ ... });

// Existence
expect(value).toBeDefined();
expect(value).toBeUndefined();

// Arrays & Collections
expect(array).toHaveLength(2);
expect(array.map(k => k.label).sort()).toEqual([...]);
expect(collection).toContain("item");

// Exceptions
await expect(promise).rejects.toThrow("message");
await expect(promise).rejects.toThrow();

// Collections
expect(map.has(key)).toBe(true);
expect(set.has(item)).toBe(true);

// Strings
expect(string).toMatch(/regex/);
expect(string).toContain("substring");
expect(string).not.toContain("secret");
```

### Negative Assertions (Security Critical)

```typescript
// Verify secrets don't leak into logs
const logStr = JSON.stringify(hsm.getOperationLog());
expect(logStr).not.toContain("super-secret-key-material");
expect(logStr).not.toContain(keyData.toString("hex"));

// Verify credentials excluded from events
const eventStr = JSON.stringify(events);
expect(eventStr).not.toContain(secretValue);
```

---

## Test Categories

### Unit Tests

**Test a single class/function in isolation with mocks for dependencies.**

Example: `hsm-client.test.ts`
- Initialize/finalize lifecycle
- Generate symmetric and asymmetric keys
- Import/export keys
- Sign and verify operations
- Key destruction
- Operation logging

### Integration Tests (Limited Scope)

**Test interaction between two or more components** (e.g., CredentialManager + MockHsmClient).

Example: `credential-manager.test.ts`
- Manager registration and import
- Injection into env, tmpfs, HSM
- Credential rotation with HSM
- Revocation across all locations
- Cleanup on shutdown
- Lifecycle event tracking

### Property-Based Testing

**Use fast-check for generative/fuzzy testing of invariants.**

File pattern: `describe("Property N: ...")` blocks

```typescript
import * as fc from "fast-check";

describe("Property 1: HSM backend portability", () => {
  it("interface works regardless of module path", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),    // module path
        fc.nat({ max: 10 }),                             // slot
        fc.string({ minLength: 1, maxLength: 20 }),      // pin
        async (modulePath, slot, pin) => {
          const hsm = new MockHsmClient();
          await hsm.initialize(modulePath, slot, pin);
          expect(hsm.isInitialized).toBe(true);
          // ... further assertions
          await hsm.finalize();
          expect(hsm.isInitialized).toBe(false);
        },
      ),
      { numRuns: 20 },
    );
  });
});
```

### Property Test Examples (HSM Client)

```
Property 1: HSM backend portability
Property 2: API key storage — extractable=true, sensitive=true
Property 3: Signing key storage attributes — extractable=false
Property 4: Non-extractable key protection
Property 5: Transient credential cleanup
Property 6: HSM operation logging without key material
```

### Property Test Examples (Credential Manager)

```
Property 15: Gateway receives only proxy token
Property 16: tokenFile credentials on tmpfs
Property 17: No credentials on persistent disk
Property 18: Credential injection logging without values
```

**Pattern:** Each property uses `fc.assert()` with `asyncProperty()` and 10-20 runs

---

## Filesystem & Temp Directory Handling

### Temp Directory Creation

```typescript
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "lobsec-cred-test-"));
}
```

### Cleanup Pattern

```typescript
let tmpDir: string;

beforeEach(() => {
  tmpDir = makeTmpDir();
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});
```

### File Assertions

```typescript
import { existsSync, readFileSync } from "node:fs";

const filePath = join(tmpDir, "token.txt");
expect(existsSync(filePath)).toBe(true);
expect(readFileSync(filePath, "utf-8")).toBe("file-token-value");
```

---

## Environment Variable Management

### Saving & Restoring

```typescript
let tmpDir: string;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  tmpDir = makeTmpDir();
  savedEnv["TEST_INJECT_KEY"] = process.env["TEST_INJECT_KEY"];
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  if (savedEnv["TEST_INJECT_KEY"] === undefined) {
    delete process.env["TEST_INJECT_KEY"];
  } else {
    process.env["TEST_INJECT_KEY"] = savedEnv["TEST_INJECT_KEY"];
  }
});
```

### Setting for Tests

```typescript
manager.registerSpecs([{
  label: "env-cred",
  type: "llm-api-key",
  extractable: true,
  injectionMethod: "env",
  envVar: "TEST_INJECT_KEY",  // Test-specific name
}]);

process.env["TEST_INJECT_KEY"] = "test-value";
expect(process.env["TEST_INJECT_KEY"]).toBe("test-value");
```

---

## Callback & Event Testing

### Collecting Events

```typescript
const events: CredentialLifecycleEvent[] = [];
const accessLog: string[] = [];

const manager = new CredentialManager({
  tmpfsDir,
  hsm,
  onAccess: (label, _type, operation) => {
    accessLog.push(`${operation}:${label}`);
  },
  onEvent: (event) => {
    events.push(event);
  },
});
```

### Asserting Event Sequences

```typescript
await manager.importCredential("event-key", "val");
manager.inject("event-key");
await manager.rotate("event-key", "new-val");

const actions = events.map((e) => e.action);
expect(actions).toContain("load");
expect(actions).toContain("inject");
expect(actions).toContain("rotate");
```

### Security: No Secrets in Callbacks

```typescript
const events: CredentialLifecycleEvent[] = [];
// ... operations ...
const eventStr = JSON.stringify(events);
expect(eventStr).not.toContain(secretValue);  // Must never leak
```

---

## Coverage & Benchmarks

### Coverage Goals

- **80% threshold** for: lines, functions, branches, statements
- **100% coverage** on critical security paths:
  - Key generation/destruction
  - Sign/verify operations
  - Secret redaction
  - Lifecycle events

### Checking Coverage

```bash
pnpm test --coverage
```

Produces coverage reports per package in:
```
coverage/
├── packages/cli/
├── packages/plugin/
├── packages/proxy/
├── packages/shared/
└── packages/tools/
```

### Performance Notes

- Tests run in **V8 coverage mode** (no external instrumentation)
- Full test suite (670+ tests) completes in ~30-60 seconds
- Property-based tests use `numRuns: 20` (configurable per test)

---

## Common Test Patterns

### Testing with Buffers

```typescript
const keyData = Buffer.from("my-secret-api-key-32-chars!12345");
await hsm.importKey(makeAttrs({ label: "api-key", extractable: true }), keyData);
const exported = await hsm.exportKey("api-key");
expect(exported).toEqual(keyData);
```

### Testing Errors

```typescript
// Sync error
it("throws when not initialized", () => {
  await expect(hsm.generateKey(makeAttrs())).rejects.toThrow("not initialized");
});

// Specific error message matching
await expect(hsm.exportKey("unknown")).rejects.toThrow("not found");
```

### Testing State Transitions

```typescript
// Before cleanup
expect(process.env["CLEANUP_KEY_A"]).toBe("val-a");
expect(existsSync(filePath)).toBe(true);

// After cleanup
await manager.cleanup();
expect(process.env["CLEANUP_KEY_A"]).toBeUndefined();
expect(existsSync(filePath)).toBe(false);
expect(manager.isDestroyed).toBe(true);
```

---

## Running Tests

### Commands

```bash
# Run all tests
pnpm test

# Watch mode
pnpm test --watch

# Coverage report
pnpm test --coverage

# Specific package
pnpm test packages/shared

# Specific file
pnpm test packages/shared/src/hsm-client.test.ts

# Verbose output
pnpm test --reporter=verbose
```

### CI Integration

Tests are designed to run in:
- Local development (all globals available)
- GitHub Actions (no special setup needed)
- Docker containers (V8 coverage available)

---

## Best Practices

1. **One assertion concept per test** (though multiple related assertions OK)
2. **Use descriptive test names** that explain the behavior being tested
3. **Keep helpers isolated** — `makeAttrs()`, `createManager()`, etc.
4. **Cleanup always** — env vars, temp files, HSM keys in afterEach
5. **Never commit secrets** — use obviously fake values (`test-`, `sk-test-`)
6. **Test error cases** — both sync and async rejection paths
7. **Property tests for invariants** — use fast-check for edge cases
8. **No side effects between tests** — each test runs independently

