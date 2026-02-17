import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import { AuditSigner, AUDIT_KEY_LABEL, GENESIS_HASH } from "./audit-signer.js";
import type { SignedAuditEntry } from "./audit-signer.js";
import { MockHsmClient } from "./hsm-client.js";
import type { AuditLogEntry } from "./types/log.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeEntry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    ts: new Date().toISOString(),
    level: "INFO",
    component: "lobsec-proxy",
    module: "audit",
    fn: "testOp",
    msg: "test audit entry",
    traceId: `tr_test_${Math.random().toString(36).slice(2, 10)}`,
    context: {},
    layer: "L9",
    event: "allow",
    prevHash: "",
    ...overrides,
  };
}

let hsm: MockHsmClient;
let signer: AuditSigner;

async function setup(): Promise<void> {
  hsm = new MockHsmClient();
  await hsm.initialize("/mock", 0, "1234");
  signer = new AuditSigner({ hsm, keyLabel: AUDIT_KEY_LABEL });
  await signer.generateSigningKey();
}

// ── Unit: Key generation ────────────────────────────────────────────────────

describe("Audit signing key generation", () => {
  beforeEach(setup);

  it("generates RSA-2048 signing key", async () => {
    const hasKey = await signer.hasSigningKey();
    expect(hasKey).toBe(true);
  });

  it("key is non-extractable", async () => {
    const info = await hsm.getKeyInfo(AUDIT_KEY_LABEL);
    expect(info).toBeDefined();
    expect(info!.extractable).toBe(false);
    expect(info!.sensitive).toBe(true);
  });

  it("logs key generation event", async () => {
    const events = signer.getEventLog();
    expect(events.some((e) => e.action === "key-generate")).toBe(true);
  });
});

// ── Unit: Entry signing ─────────────────────────────────────────────────────

describe("Audit entry signing", () => {
  beforeEach(setup);

  it("signs an entry with HSM", async () => {
    const entry = makeEntry();
    const signed = await signer.sign(entry);

    expect(signed.entryHash).toMatch(/^[0-9a-f]{64}$/);
    expect(signed.hsmSignature).toBeTruthy();
    expect(signed.prevHash).toBe(GENESIS_HASH);
  });

  it("preserves original entry fields", async () => {
    const entry = makeEntry({ msg: "test message", traceId: "tr_preserve" });
    const signed = await signer.sign(entry);

    expect(signed.msg).toBe("test message");
    expect(signed.traceId).toBe("tr_preserve");
    expect(signed.level).toBe("INFO");
    expect(signed.layer).toBe("L9");
  });

  it("chains entries via prevHash", async () => {
    const signed1 = await signer.sign(makeEntry({ msg: "first" }));
    const signed2 = await signer.sign(makeEntry({ msg: "second" }));
    const signed3 = await signer.sign(makeEntry({ msg: "third" }));

    expect(signed1.prevHash).toBe(GENESIS_HASH);
    expect(signed2.prevHash).toBe(signed1.entryHash);
    expect(signed3.prevHash).toBe(signed2.entryHash);
  });

  it("tracks entry count", async () => {
    await signer.sign(makeEntry());
    await signer.sign(makeEntry());
    await signer.sign(makeEntry());

    expect(signer.getEntryCount()).toBe(3);
  });

  it("updates last hash after signing", async () => {
    expect(signer.getLastHash()).toBe(GENESIS_HASH);

    const signed = await signer.sign(makeEntry());
    expect(signer.getLastHash()).toBe(signed.entryHash);
  });

  it("logs signing events", async () => {
    await signer.sign(makeEntry());
    const events = signer.getEventLog();
    expect(events.some((e) => e.action === "sign")).toBe(true);
  });
});

// ── Unit: Entry verification ────────────────────────────────────────────────

describe("Audit entry verification", () => {
  beforeEach(setup);

  it("verifies a valid chain", async () => {
    const entries: SignedAuditEntry[] = [];
    entries.push(await signer.sign(makeEntry({ msg: "entry 1" })));
    entries.push(await signer.sign(makeEntry({ msg: "entry 2" })));
    entries.push(await signer.sign(makeEntry({ msg: "entry 3" })));

    const result = await signer.verify(entries);
    expect(result.valid).toBe(true);
    expect(result.entriesVerified).toBe(3);
    expect(result.errors).toHaveLength(0);
  });

  it("verifies a single entry", async () => {
    const signed = await signer.sign(makeEntry());
    const result = await signer.verify([signed]);
    expect(result.valid).toBe(true);
    expect(result.entriesVerified).toBe(1);
  });

  it("verifies empty chain", async () => {
    const result = await signer.verify([]);
    expect(result.valid).toBe(true);
    expect(result.entriesVerified).toBe(0);
  });

  it("detects tampered message", async () => {
    const entries: SignedAuditEntry[] = [];
    entries.push(await signer.sign(makeEntry({ msg: "original" })));
    entries.push(await signer.sign(makeEntry({ msg: "untampered" })));

    // Tamper with message
    entries[0] = { ...entries[0]!, msg: "TAMPERED" };

    const result = await signer.verify(entries);
    expect(result.valid).toBe(false);
    expect(result.firstInvalidIndex).toBe(0);
    expect(result.errors[0]).toContain("entryHash mismatch");
  });

  it("detects broken chain (modified prevHash)", async () => {
    const entries: SignedAuditEntry[] = [];
    entries.push(await signer.sign(makeEntry({ msg: "entry 1" })));
    entries.push(await signer.sign(makeEntry({ msg: "entry 2" })));

    // Break chain by modifying prevHash
    entries[1] = { ...entries[1]!, prevHash: "ff".repeat(32) };

    const result = await signer.verify(entries);
    expect(result.valid).toBe(false);
    expect(result.firstInvalidIndex).toBe(1);
    expect(result.errors[0]).toContain("prevHash mismatch");
  });

  it("detects tampered signature", async () => {
    const entries: SignedAuditEntry[] = [];
    entries.push(await signer.sign(makeEntry({ msg: "entry 1" })));

    // Corrupt signature
    entries[0] = { ...entries[0]!, hsmSignature: "AAAA" + entries[0]!.hsmSignature.slice(4) };

    const result = await signer.verify(entries);
    expect(result.valid).toBe(false);
    expect(result.firstInvalidIndex).toBe(0);
    expect(result.errors[0]).toContain("signature invalid");
  });

  it("detects deleted entry in chain", async () => {
    const entries: SignedAuditEntry[] = [];
    entries.push(await signer.sign(makeEntry({ msg: "entry 1" })));
    entries.push(await signer.sign(makeEntry({ msg: "entry 2" })));
    entries.push(await signer.sign(makeEntry({ msg: "entry 3" })));

    // Remove middle entry
    entries.splice(1, 1);

    const result = await signer.verify(entries);
    expect(result.valid).toBe(false);
    expect(result.firstInvalidIndex).toBe(1);
    expect(result.errors[0]).toContain("prevHash mismatch");
  });

  it("logs verification events", async () => {
    const signed = await signer.sign(makeEntry());
    await signer.verify([signed]);

    const events = signer.getEventLog();
    expect(events.some((e) => e.action === "verify")).toBe(true);
  });
});

// ── Unit: Reset ─────────────────────────────────────────────────────────────

describe("Audit signer reset", () => {
  beforeEach(setup);

  it("resets chain state", async () => {
    await signer.sign(makeEntry());
    await signer.sign(makeEntry());

    expect(signer.getEntryCount()).toBe(2);
    expect(signer.getLastHash()).not.toBe(GENESIS_HASH);

    signer.reset();
    expect(signer.getEntryCount()).toBe(0);
    expect(signer.getLastHash()).toBe(GENESIS_HASH);
  });
});

// ── Property 42: HSM signature validity ─────────────────────────────────────

describe("Property 42: HSM signature validity", () => {
  beforeEach(setup);

  it("any signed entry verifies successfully", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 50 }),
        fc.constantFrom("allow", "deny", "alert", "error") as fc.Arbitrary<"allow" | "deny" | "alert" | "error">,
        fc.constantFrom("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9") as fc.Arbitrary<"L1" | "L2" | "L3" | "L4" | "L5" | "L6" | "L7" | "L8" | "L9">,
        async (msg, event, layer) => {
          signer.reset();
          const entry = makeEntry({ msg, event, layer });
          const signed = await signer.sign(entry);

          const result = await signer.verify([signed]);
          expect(result.valid).toBe(true);
          expect(result.entriesVerified).toBe(1);
        },
      ),
      { numRuns: 15 },
    );
  });

  it("hash chain is valid for arbitrary-length chains", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 2, max: 8 }),
        async (chainLength) => {
          signer.reset();
          const entries: SignedAuditEntry[] = [];

          for (let i = 0; i < chainLength; i++) {
            entries.push(await signer.sign(makeEntry({ msg: `entry-${i}` })));
          }

          const result = await signer.verify(entries);
          expect(result.valid).toBe(true);
          expect(result.entriesVerified).toBe(chainLength);
        },
      ),
      { numRuns: 10 },
    );
  }, 30000);

  it("tampered entry always fails verification", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 30 }),
        fc.string({ minLength: 1, maxLength: 30 }),
        async (original, tampered) => {
          // Skip if strings are equal
          fc.pre(original !== tampered);

          signer.reset();
          const signed = await signer.sign(makeEntry({ msg: original }));
          const corrupted = { ...signed, msg: tampered };

          const result = await signer.verify([corrupted]);
          expect(result.valid).toBe(false);
        },
      ),
      { numRuns: 15 },
    );
  });
});
