import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import { MockHsmClient } from "./hsm-client.js";
import type { HsmKeyAttributes } from "./hsm-client.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

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

// ── Unit: MockHsmClient lifecycle ─────────────────────────────────────────

describe("MockHsmClient lifecycle", () => {
  let hsm: MockHsmClient;

  beforeEach(() => {
    hsm = new MockHsmClient();
  });

  it("starts uninitialized", () => {
    expect(hsm.isInitialized).toBe(false);
  });

  it("initializes successfully", async () => {
    await hsm.initialize("/usr/lib/softhsm/libsofthsm2.so", 0, "1234");
    expect(hsm.isInitialized).toBe(true);
  });

  it("finalizes successfully", async () => {
    await hsm.initialize("/path", 0, "pin");
    await hsm.finalize();
    expect(hsm.isInitialized).toBe(false);
  });

  it("throws when not initialized", async () => {
    await expect(hsm.generateKey(makeAttrs())).rejects.toThrow("not initialized");
  });
});

// ── Unit: Key generation ──────────────────────────────────────────────────

describe("Key generation", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("generates a symmetric key", async () => {
    const info = await hsm.generateKey(makeAttrs({ label: "my-aes-key" }));
    expect(info.label).toBe("my-aes-key");
    expect(info.keyType).toBe("aes-256");
    expect(info.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("generates a key pair", async () => {
    const { publicKey, privateKey } = await hsm.generateKeyPair(
      makeAttrs({ label: "my-rsa-key", keyType: "rsa-2048", forSigning: true }),
    );
    expect(publicKey.label).toBe("my-rsa-key-pub");
    expect(privateKey.label).toBe("my-rsa-key");
  });

  it("key info reflects attributes", async () => {
    await hsm.generateKey(makeAttrs({
      label: "sensitive-key",
      extractable: false,
      sensitive: true,
    }));
    const info = await hsm.getKeyInfo("sensitive-key");
    expect(info?.extractable).toBe(false);
    expect(info?.sensitive).toBe(true);
  });
});

// ── Unit: Key import/export ───────────────────────────────────────────────

describe("Key import/export", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("imports and exports an extractable key", async () => {
    const keyData = Buffer.from("my-secret-api-key-32-chars!12345");
    await hsm.importKey(makeAttrs({ label: "api-key", extractable: true }), keyData);
    const exported = await hsm.exportKey("api-key");
    expect(exported).toEqual(keyData);
  });

  it("refuses to export non-extractable key", async () => {
    const keyData = Buffer.from("signing-key-data-32-chars!12345!");
    await hsm.importKey(makeAttrs({ label: "signing-key", extractable: false }), keyData);
    await expect(hsm.exportKey("signing-key")).rejects.toThrow("not extractable");
  });

  it("throws on export of unknown key", async () => {
    await expect(hsm.exportKey("nonexistent")).rejects.toThrow("not found");
  });
});

// ── Unit: Sign/Verify ─────────────────────────────────────────────────────

describe("Sign/Verify", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("signs and verifies with HMAC (symmetric key)", async () => {
    await hsm.generateKey(makeAttrs({ label: "hmac-key", forSigning: true }));
    const data = Buffer.from("audit log entry data");

    const { signature } = await hsm.sign("hmac-key", data);
    expect(signature.length).toBeGreaterThan(0);

    const valid = await hsm.verify("hmac-key", data, signature);
    expect(valid).toBe(true);
  });

  it("rejects tampered data", async () => {
    await hsm.generateKey(makeAttrs({ label: "hmac-key", forSigning: true }));
    const data = Buffer.from("original data");
    const { signature } = await hsm.sign("hmac-key", data);

    const valid = await hsm.verify("hmac-key", Buffer.from("tampered"), signature);
    expect(valid).toBe(false);
  });

  it("signs and verifies with RSA (key pair)", async () => {
    await hsm.generateKeyPair(makeAttrs({
      label: "rsa-sign-key",
      keyType: "rsa-2048",
      forSigning: true,
      extractable: false,
    }));

    const data = Buffer.from("important audit data");
    const { signature, mechanism } = await hsm.sign("rsa-sign-key", data);
    expect(mechanism).toBe("RSA-SHA256");

    const valid = await hsm.verify("rsa-sign-key", data, signature);
    expect(valid).toBe(true);
  });

  it("throws on sign with unknown key", async () => {
    await expect(hsm.sign("unknown", Buffer.from("data"))).rejects.toThrow("not found");
  });
});

// ── Unit: Key destruction ─────────────────────────────────────────────────

describe("Key destruction", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("destroys a key", async () => {
    await hsm.generateKey(makeAttrs({ label: "temp-key" }));
    expect(await hsm.destroyKey("temp-key")).toBe(true);
    expect(await hsm.getKeyInfo("temp-key")).toBeUndefined();
  });

  it("returns false for unknown key", async () => {
    expect(await hsm.destroyKey("nonexistent")).toBe(false);
  });

  it("key is inaccessible after destruction", async () => {
    await hsm.generateKey(makeAttrs({ label: "doomed" }));
    await hsm.destroyKey("doomed");
    await expect(hsm.exportKey("doomed")).rejects.toThrow("not found");
  });
});

// ── Unit: List keys ───────────────────────────────────────────────────────

describe("listKeys", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("lists all keys", async () => {
    await hsm.generateKey(makeAttrs({ label: "key-a" }));
    await hsm.generateKey(makeAttrs({ label: "key-b" }));
    const keys = await hsm.listKeys();
    expect(keys).toHaveLength(2);
    expect(keys.map((k) => k.label).sort()).toEqual(["key-a", "key-b"]);
  });

  it("includes key pairs", async () => {
    await hsm.generateKeyPair(makeAttrs({ label: "rsa-key", keyType: "rsa-2048" }));
    const keys = await hsm.listKeys();
    expect(keys.some((k) => k.label === "rsa-key")).toBe(true);
  });
});

// ── Unit: Operation log ───────────────────────────────────────────────────

describe("Operation log", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("logs all operations", async () => {
    await hsm.generateKey(makeAttrs({ label: "key" }));
    await hsm.sign("key", Buffer.from("data"));
    const log = hsm.getOperationLog();
    expect(log.length).toBeGreaterThanOrEqual(3); // init + generate + sign
  });

  it("never logs key material", async () => {
    const keyData = Buffer.from("super-secret-key-material-12345!");
    await hsm.importKey(makeAttrs({ label: "secret" }), keyData);
    await hsm.exportKey("secret");

    const logStr = JSON.stringify(hsm.getOperationLog());
    expect(logStr).not.toContain("super-secret-key-material");
    expect(logStr).not.toContain(keyData.toString("hex"));
  });
});

// ── Property 1: HSM backend portability ──────────────────────────────────

describe("Property 1: HSM backend portability", () => {
  it("interface works regardless of module path", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.nat({ max: 10 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        async (modulePath, slot, pin) => {
          const hsm = new MockHsmClient();
          await hsm.initialize(modulePath, slot, pin);
          expect(hsm.isInitialized).toBe(true);

          await hsm.generateKey(makeAttrs({ label: "portability-test" }));
          const keys = await hsm.listKeys();
          expect(keys.some((k) => k.label === "portability-test")).toBe(true);

          await hsm.finalize();
          expect(hsm.isInitialized).toBe(false);
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Property 2: API key storage — extractable=true, sensitive=true ───────

describe("Property 2: API key storage attributes", () => {
  it("API keys are stored as extractable + sensitive", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 8, maxLength: 64 }),
        async (apiKeyValue) => {
          const hsm = new MockHsmClient();
          await hsm.initialize("/path", 0, "pin");

          await hsm.importKey(
            makeAttrs({
              label: "api-key",
              extractable: true,
              sensitive: true,
              keyType: "generic-secret",
            }),
            Buffer.from(apiKeyValue),
          );

          const info = await hsm.getKeyInfo("api-key");
          expect(info?.extractable).toBe(true);
          expect(info?.sensitive).toBe(true);

          // Can extract for injection
          const exported = await hsm.exportKey("api-key");
          expect(exported.toString()).toBe(apiKeyValue);

          await hsm.finalize();
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Property 3: Signing key — extractable=false ──────────────────────────

describe("Property 3: Signing key storage attributes", () => {
  it("signing keys cannot be extracted", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        async (keyData) => {
          const hsm = new MockHsmClient();
          await hsm.initialize("/path", 0, "pin");

          await hsm.importKey(
            makeAttrs({
              label: "signing-key",
              extractable: false,
              sensitive: true,
              forSigning: true,
            }),
            Buffer.from(keyData),
          );

          const info = await hsm.getKeyInfo("signing-key");
          expect(info?.extractable).toBe(false);

          // Must throw on extract attempt
          await expect(hsm.exportKey("signing-key")).rejects.toThrow("not extractable");

          await hsm.finalize();
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Property 4: Non-extractable key protection ───────────────────────────

describe("Property 4: Non-extractable key protection", () => {
  it("non-extractable keys can still sign but never export", async () => {
    const hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");

    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 200 }),
        async (dataToSign) => {
          // Ensure key exists
          if (!(await hsm.getKeyInfo("ne-key"))) {
            await hsm.generateKey(makeAttrs({
              label: "ne-key",
              extractable: false,
              forSigning: true,
            }));
          }

          // Can sign
          const { signature } = await hsm.sign("ne-key", Buffer.from(dataToSign));
          expect(signature.length).toBeGreaterThan(0);

          // Can verify
          const valid = await hsm.verify("ne-key", Buffer.from(dataToSign), signature);
          expect(valid).toBe(true);

          // Cannot export
          await expect(hsm.exportKey("ne-key")).rejects.toThrow();
        },
      ),
      { numRuns: 20 },
    );

    await hsm.finalize();
  });
});

// ── Property 5: Transient credential cleanup ─────────────────────────────

describe("Property 5: Transient credential cleanup", () => {
  it("destroyed keys are completely inaccessible", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 30 }),
        async (label) => {
          const hsm = new MockHsmClient();
          await hsm.initialize("/path", 0, "pin");

          await hsm.generateKey(makeAttrs({ label }));
          expect(await hsm.getKeyInfo(label)).toBeDefined();

          await hsm.destroyKey(label);
          expect(await hsm.getKeyInfo(label)).toBeUndefined();
          await expect(hsm.exportKey(label)).rejects.toThrow();
          await expect(hsm.sign(label, Buffer.from("test"))).rejects.toThrow();

          await hsm.finalize();
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Property 6: HSM operation logging without key material ───────────────

describe("Property 6: HSM operation logging without key material", () => {
  it("operation log never contains key data", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 16, maxLength: 64 }),
        fc.uint8Array({ minLength: 1, maxLength: 100 }),
        async (keyBytes, dataToSign) => {
          const hsm = new MockHsmClient();
          await hsm.initialize("/path", 0, "pin");

          const keyHex = Buffer.from(keyBytes).toString("hex");
          const keyBase64 = Buffer.from(keyBytes).toString("base64");

          await hsm.importKey(
            makeAttrs({ label: "logged-key", extractable: true }),
            Buffer.from(keyBytes),
          );
          await hsm.sign("logged-key", Buffer.from(dataToSign));
          await hsm.exportKey("logged-key");

          const logStr = JSON.stringify(hsm.getOperationLog());
          expect(logStr).not.toContain(keyHex);
          expect(logStr).not.toContain(keyBase64);

          await hsm.finalize();
        },
      ),
      { numRuns: 20 },
    );
  });
});
