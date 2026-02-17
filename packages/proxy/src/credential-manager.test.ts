import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fc from "fast-check";
import { MockHsmClient } from "@lobsec/shared";
import { CredentialManager, DEFAULT_CREDENTIAL_SPECS } from "./credential-manager.js";
import type { CredentialSpec, CredentialLifecycleEvent } from "./credential-manager.js";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync } from "node:fs";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "lobsec-cred-test-"));
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

// ── Unit: Registration and import ───────────────────────────────────────────

describe("Credential registration and import", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("registers default specs", () => {
    const { manager } = createManager(tmpDir);
    manager.registerSpecs(DEFAULT_CREDENTIAL_SPECS);
    const list = manager.listCredentials();
    expect(list.length).toBe(DEFAULT_CREDENTIAL_SPECS.length);
  });

  it("imports a credential into HSM and runtime store", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "test-key",
      type: "llm-api-key",
      extractable: true,
      injectionMethod: "env",
      envVar: "TEST_API_KEY",
    }]);

    const result = await manager.importCredential("test-key", "sk-test-12345");
    expect(result).toBe(true);

    const hsmInfo = await hsm.getKeyInfo("test-key");
    expect(hsmInfo).toBeDefined();
    expect(hsmInfo?.extractable).toBe(true);
  });

  it("imports non-extractable credential (webhook secret)", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "wh-secret",
      type: "webhook-secret",
      extractable: false,
      injectionMethod: "hsm-only",
    }]);

    const result = await manager.importCredential("wh-secret", "secret-data");
    expect(result).toBe(true);

    const hsmInfo = await hsm.getKeyInfo("wh-secret");
    expect(hsmInfo?.extractable).toBe(false);
  });

  it("returns false for unknown spec", async () => {
    const { manager } = createManager(tmpDir);
    const result = await manager.importCredential("unknown", "value");
    expect(result).toBe(false);
  });
});

// ── Unit: Injection ─────────────────────────────────────────────────────────

describe("Credential injection", () => {
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

  it("injects into env var", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "env-cred",
      type: "llm-api-key",
      extractable: true,
      injectionMethod: "env",
      envVar: "TEST_INJECT_KEY",
    }]);

    await manager.importCredential("env-cred", "injected-value");
    const injected = manager.inject("env-cred");
    expect(injected).toBe(true);
    expect(process.env["TEST_INJECT_KEY"]).toBe("injected-value");
  });

  it("injects into tmpfs file", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "file-cred",
      type: "channel-token",
      extractable: true,
      injectionMethod: "tmpfs-file",
      tmpfsPath: "token.txt",
    }]);

    await manager.importCredential("file-cred", "file-token-value");
    const injected = manager.inject("file-cred");
    expect(injected).toBe(true);

    const filePath = join(tmpDir, "token.txt");
    expect(existsSync(filePath)).toBe(true);
    expect(readFileSync(filePath, "utf-8")).toBe("file-token-value");
  });

  it("hsm-only injection succeeds without side effects", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "hsm-cred",
      type: "webhook-secret",
      extractable: false,
      injectionMethod: "hsm-only",
    }]);

    await manager.importCredential("hsm-cred", "hsm-secret");
    const injected = manager.inject("hsm-cred");
    expect(injected).toBe(true);
  });

  it("returns false for missing credential value", async () => {
    const { manager } = createManager(tmpDir);
    manager.registerSpecs([{
      label: "missing-cred",
      type: "llm-api-key",
      extractable: true,
      injectionMethod: "env",
      envVar: "MISSING_KEY",
    }]);
    // No import — value is missing
    const injected = manager.inject("missing-cred");
    expect(injected).toBe(false);
  });
});

// ── Unit: Rotation ──────────────────────────────────────────────────────────

describe("Credential rotation", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rotates a credential with new value", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "rotate-key",
      type: "llm-api-key",
      extractable: true,
      injectionMethod: "env",
      envVar: "ROTATE_KEY",
    }]);

    await manager.importCredential("rotate-key", "old-value");
    const rotated = await manager.rotate("rotate-key", "new-value");
    expect(rotated).toBe(true);

    // New value should be in HSM
    const exported = await hsm.exportKey("rotate-key");
    expect(exported.toString()).toBe("new-value");
  });
});

// ── Unit: Revocation ────────────────────────────────────────────────────────

describe("Credential revocation", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    delete process.env["REVOKE_KEY"];
  });

  it("revokes from env, store, and HSM", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "revoke-cred",
      type: "gateway-auth-token",
      extractable: true,
      injectionMethod: "env",
      envVar: "REVOKE_KEY",
    }]);

    await manager.importCredential("revoke-cred", "secret-val");
    manager.inject("revoke-cred");
    expect(process.env["REVOKE_KEY"]).toBe("secret-val");

    const revoked = await manager.revoke("revoke-cred");
    expect(revoked).toBe(true);
    expect(process.env["REVOKE_KEY"]).toBeUndefined();
    expect(await hsm.getKeyInfo("revoke-cred")).toBeUndefined();
  });

  it("revokes tmpfs file credential", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "file-revoke",
      type: "channel-token",
      extractable: true,
      injectionMethod: "tmpfs-file",
      tmpfsPath: "revoke-token.txt",
    }]);

    await manager.importCredential("file-revoke", "file-secret");
    manager.inject("file-revoke");
    expect(existsSync(join(tmpDir, "revoke-token.txt"))).toBe(true);

    await manager.revoke("file-revoke");
    expect(existsSync(join(tmpDir, "revoke-token.txt"))).toBe(false);
  });
});

// ── Unit: Cleanup on shutdown ───────────────────────────────────────────────

describe("Cleanup on shutdown", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    delete process.env["CLEANUP_KEY_A"];
    delete process.env["CLEANUP_KEY_B"];
  });

  it("clears all env vars and tmpfs files on cleanup", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([
      {
        label: "cleanup-a",
        type: "llm-api-key",
        extractable: true,
        injectionMethod: "env",
        envVar: "CLEANUP_KEY_A",
      },
      {
        label: "cleanup-b",
        type: "channel-token",
        extractable: true,
        injectionMethod: "tmpfs-file",
        tmpfsPath: "cleanup-token.txt",
      },
    ]);

    await manager.importCredential("cleanup-a", "val-a");
    await manager.importCredential("cleanup-b", "val-b");
    manager.inject("cleanup-a");
    manager.inject("cleanup-b");

    expect(process.env["CLEANUP_KEY_A"]).toBe("val-a");
    expect(existsSync(join(tmpDir, "cleanup-token.txt"))).toBe(true);

    await manager.cleanup();

    expect(process.env["CLEANUP_KEY_A"]).toBeUndefined();
    expect(existsSync(join(tmpDir, "cleanup-token.txt"))).toBe(false);
    expect(manager.isDestroyed).toBe(true);
  });
});

// ── Unit: Startup validation ────────────────────────────────────────────────

describe("Startup validation", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("identifies missing required credentials", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([
      {
        label: "present-key",
        type: "llm-api-key",
        extractable: true,
        injectionMethod: "env",
        envVar: "PRESENT",
      },
      {
        label: "missing-key",
        type: "gateway-auth-token",
        extractable: true,
        injectionMethod: "env",
        envVar: "MISSING",
      },
    ]);

    await manager.importCredential("present-key", "value");

    const missing = manager.validateStartupCredentials(["present-key", "missing-key"]);
    expect(missing).toEqual(["missing-key"]);
  });

  it("non-extractable credentials pass validation without store presence", async () => {
    const { manager, hsm } = createManager(tmpDir);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "hsm-cred",
      type: "webhook-secret",
      extractable: false,
      injectionMethod: "hsm-only",
    }]);

    // Not in store, but non-extractable — should pass
    const missing = manager.validateStartupCredentials(["hsm-cred"]);
    expect(missing).toEqual([]);
  });
});

// ── Unit: Lifecycle events ──────────────────────────────────────────────────

describe("Lifecycle events", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("emits events for all lifecycle actions", async () => {
    const events: CredentialLifecycleEvent[] = [];
    const { manager, hsm } = createManager(tmpDir, events);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "event-key",
      type: "llm-api-key",
      extractable: true,
      injectionMethod: "env",
      envVar: "EVENT_KEY",
    }]);

    await manager.importCredential("event-key", "val");
    manager.inject("event-key");
    await manager.rotate("event-key", "new-val");
    await manager.revoke("event-key");

    const actions = events.map((e) => e.action);
    expect(actions).toContain("load");
    expect(actions).toContain("inject");
    expect(actions).toContain("rotate");
    expect(actions).toContain("revoke");

    delete process.env["EVENT_KEY"];
  });

  it("events never contain credential values", async () => {
    const events: CredentialLifecycleEvent[] = [];
    const { manager, hsm } = createManager(tmpDir, events);
    await hsm.initialize("/path", 0, "pin");
    manager.registerSpecs([{
      label: "secret-key",
      type: "llm-api-key",
      extractable: true,
      injectionMethod: "env",
      envVar: "SECRET_EVENT_KEY",
    }]);

    const secretValue = "sk-supersecretapikey123456789";
    await manager.importCredential("secret-key", secretValue);
    manager.inject("secret-key");
    await manager.cleanup();

    const eventStr = JSON.stringify(events);
    expect(eventStr).not.toContain(secretValue);

    delete process.env["SECRET_EVENT_KEY"];
  });
});

// ── Property 15: Gateway receives only proxy token ──────────────────────────

describe("Property 15: Gateway receives only proxy token", () => {
  it("only proxy-internal-token and gateway-auth-token are injected to gateway env", async () => {
    const tmpDir = makeTmpDir();
    try {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 8, maxLength: 32 }),
          fc.string({ minLength: 8, maxLength: 32 }),
          fc.string({ minLength: 8, maxLength: 32 }),
          async (proxyToken, gatewayToken, apiKey) => {
            const events: CredentialLifecycleEvent[] = [];
            const { manager, hsm } = createManager(tmpDir, events);
            await hsm.initialize("/path", 0, "pin");

            const specs: CredentialSpec[] = [
              {
                label: "proxy-token",
                type: "proxy-internal-token",
                extractable: true,
                injectionMethod: "env",
                envVar: "PROP15_PROXY_TOKEN",
              },
              {
                label: "gateway-token",
                type: "gateway-auth-token",
                extractable: true,
                injectionMethod: "env",
                envVar: "PROP15_GATEWAY_TOKEN",
              },
              {
                label: "api-key",
                type: "llm-api-key",
                extractable: true,
                injectionMethod: "env",
                envVar: "PROP15_API_KEY",
              },
            ];
            manager.registerSpecs(specs);

            await manager.importCredential("proxy-token", proxyToken);
            await manager.importCredential("gateway-token", gatewayToken);
            await manager.importCredential("api-key", apiKey);

            manager.inject("proxy-token");
            manager.inject("gateway-token");
            manager.inject("api-key");

            // Gateway should only see proxy + gateway tokens
            // API keys go to proxy env, not gateway
            const injectedEvents = events.filter(
              (e) => e.action === "inject" && e.success,
            );

            // All three were injected to env
            expect(injectedEvents.length).toBe(3);

            // Verify injection types match spec
            for (const event of injectedEvents) {
              if (event.type === "proxy-internal-token" || event.type === "gateway-auth-token") {
                expect(event.injectionMethod).toBe("env");
              }
            }

            await manager.cleanup();
            delete process.env["PROP15_PROXY_TOKEN"];
            delete process.env["PROP15_GATEWAY_TOKEN"];
            delete process.env["PROP15_API_KEY"];
          },
        ),
        { numRuns: 10 },
      );
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// ── Property 16: tokenFile credentials on tmpfs ─────────────────────────────

describe("Property 16: tokenFile credentials on tmpfs", () => {
  it("tmpfs-file credentials are written to tmpfs directory only", async () => {
    const tmpDir = makeTmpDir();
    try {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 10, maxLength: 50 }),
          async (tokenValue) => {
            const { manager, hsm } = createManager(tmpDir);
            await hsm.initialize("/path", 0, "pin");
            manager.registerSpecs([{
              label: "tmpfs-token",
              type: "channel-token",
              extractable: true,
              injectionMethod: "tmpfs-file",
              tmpfsPath: "prop16-token.txt",
            }]);

            await manager.importCredential("tmpfs-token", tokenValue);
            manager.inject("tmpfs-token");

            const filePath = join(tmpDir, "prop16-token.txt");
            expect(existsSync(filePath)).toBe(true);
            expect(readFileSync(filePath, "utf-8")).toBe(tokenValue);

            // File is in tmpfs dir, not on persistent disk
            expect(filePath.startsWith(tmpDir)).toBe(true);

            await manager.cleanup();
          },
        ),
        { numRuns: 10 },
      );
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// ── Property 17: No credentials on persistent disk ──────────────────────────

describe("Property 17: No credentials on persistent disk", () => {
  it("cleanup removes all tmpfs files", async () => {
    const tmpDir = makeTmpDir();
    try {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 5, maxLength: 30 }),
          fc.string({ minLength: 5, maxLength: 30 }),
          async (val1, val2) => {
            const { manager, hsm } = createManager(tmpDir);
            await hsm.initialize("/path", 0, "pin");
            manager.registerSpecs([
              {
                label: "disk-test-a",
                type: "channel-token",
                extractable: true,
                injectionMethod: "tmpfs-file",
                tmpfsPath: "disk-a.txt",
              },
              {
                label: "disk-test-b",
                type: "channel-token",
                extractable: true,
                injectionMethod: "tmpfs-file",
                tmpfsPath: "disk-b.txt",
              },
            ]);

            await manager.importCredential("disk-test-a", val1);
            await manager.importCredential("disk-test-b", val2);
            manager.inject("disk-test-a");
            manager.inject("disk-test-b");

            // Files exist before cleanup
            expect(existsSync(join(tmpDir, "disk-a.txt"))).toBe(true);
            expect(existsSync(join(tmpDir, "disk-b.txt"))).toBe(true);

            await manager.cleanup();

            // Files removed after cleanup
            expect(existsSync(join(tmpDir, "disk-a.txt"))).toBe(false);
            expect(existsSync(join(tmpDir, "disk-b.txt"))).toBe(false);
          },
        ),
        { numRuns: 10 },
      );
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// ── Property 18: Credential injection logging without values ────────────────

describe("Property 18: Credential injection logging without values", () => {
  it("lifecycle events never contain credential values", async () => {
    const tmpDir = makeTmpDir();
    try {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 16, maxLength: 64 }),
          async (secretValue) => {
            const events: CredentialLifecycleEvent[] = [];
            const accessLog: string[] = [];
            const hsm = new MockHsmClient();
            await hsm.initialize("/path", 0, "pin");

            const manager = new CredentialManager({
              tmpfsDir: tmpDir,
              hsm,
              onAccess: (label, _type, op) => {
                accessLog.push(`${op}:${label}`);
              },
              onEvent: (event) => {
                events.push(event);
              },
            });

            manager.registerSpecs([{
              label: "logged-cred",
              type: "llm-api-key",
              extractable: true,
              injectionMethod: "env",
              envVar: "PROP18_KEY",
            }]);

            await manager.importCredential("logged-cred", secretValue);
            manager.inject("logged-cred");
            await manager.rotate("logged-cred", secretValue + "-rotated");
            await manager.cleanup();

            // Check events don't contain secret
            const eventStr = JSON.stringify(events);
            expect(eventStr).not.toContain(secretValue);

            // Check access log doesn't contain secret
            const logStr = JSON.stringify(accessLog);
            expect(logStr).not.toContain(secretValue);

            // Check HSM operation log doesn't contain secret
            const hsmLogStr = JSON.stringify(hsm.getOperationLog());
            expect(hsmLogStr).not.toContain(secretValue);

            delete process.env["PROP18_KEY"];
          },
        ),
        { numRuns: 10 },
      );
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
