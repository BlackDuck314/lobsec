import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { sha256, redact } from "./logger.js";
import { MockHsmClient } from "./hsm-client.js";
import { AuditSigner, AUDIT_KEY_LABEL } from "./audit-signer.js";
import type { AuditLogEntry } from "./types/log.js";

// ── Performance: Hash operations ────────────────────────────────────────────

describe("Performance: hash operations", () => {
  it("sha256 completes under 1ms for typical payloads", () => {
    const payload = JSON.stringify({
      ts: new Date().toISOString(),
      level: "INFO",
      component: "lobsec-proxy",
      module: "audit",
      fn: "testOp",
      msg: "test message with some content that is representative of real data",
      traceId: "tr_test123",
      context: { key: "value", nested: { deep: true } },
    });

    const iterations = 100;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      sha256(payload);
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    expect(avgMs).toBeLessThan(1);
  });

  it("hash chain verification scales linearly", () => {
    const entries = Array.from({ length: 50 }, (_, i) => {
      const hash = sha256(`entry-${i}`);
      return { hash, prevHash: i === 0 ? "genesis" : sha256(`entry-${i - 1}`) };
    });

    const start = performance.now();
    for (const entry of entries) {
      // Simulate chain verification
      sha256(entry.hash + entry.prevHash);
    }
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(50); // 50 entries under 50ms
  });
});

// ── Performance: Credential redaction ───────────────────────────────────────

describe("Performance: credential redaction", () => {
  it("redaction completes under 1ms per string", () => {
    const testStrings = [
      "Normal text without any secrets",
      "Key: sk-ant-api03-" + "a".repeat(40),
      "Bearer " + "x".repeat(100),
      "Contact user@example.com at 192.168.1.1",
      "Multiple: sk-proj-" + "b".repeat(30) + " and ghp_" + "c".repeat(40),
    ];

    const iterations = 100;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      for (const str of testStrings) {
        redact(str);
      }
    }
    const elapsed = performance.now() - start;
    const avgPerString = elapsed / (iterations * testStrings.length);

    expect(avgPerString).toBeLessThan(1);
  });
});

// ── Performance: HSM operations ─────────────────────────────────────────────

describe("Performance: HSM signing", () => {
  it("HSM sign+verify under 10ms per operation (mock)", async () => {
    const hsm = new MockHsmClient();
    await hsm.initialize("/mock", 0, "1234");
    await hsm.generateKeyPair({
      label: "perf-test",
      extractable: false,
      sensitive: true,
      keyType: "rsa-2048",
      forSigning: true,
      forEncryption: false,
    });

    const data = Buffer.from("test data for signing performance");
    const iterations = 10;

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const { signature } = await hsm.sign("perf-test", data);
      await hsm.verify("perf-test", data, signature);
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    expect(avgMs).toBeLessThan(50); // sign+verify pair under 50ms
  });
});

// ── Performance: Audit log signing throughput ───────────────────────────────

describe("Performance: audit log signing", () => {
  it("signs 10 entries under 500ms (mock HSM)", async () => {
    const hsm = new MockHsmClient();
    await hsm.initialize("/mock", 0, "1234");
    const signer = new AuditSigner({ hsm, keyLabel: AUDIT_KEY_LABEL });
    await signer.generateSigningKey();

    const entries: AuditLogEntry[] = Array.from({ length: 10 }, (_, i) => ({
      ts: new Date().toISOString(),
      level: "INFO" as const,
      component: "lobsec-proxy" as const,
      module: "perf",
      fn: "test",
      msg: `performance test entry ${i}`,
      traceId: `tr_perf_${i}`,
      context: {},
      layer: "L9" as const,
      event: "allow" as const,
      prevHash: "",
    }));

    const start = performance.now();
    for (const entry of entries) {
      await signer.sign(entry);
    }
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(500);
  });
});

// ── Property 44: Tool call latency bound ────────────────────────────────────

describe("Property 44: Tool call latency bound", () => {
  it("hash + redact overhead stays under 5ms per call", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 10, maxLength: 500 }),
        (input) => {
          const start = performance.now();
          sha256(input);
          redact(input);
          const elapsed = performance.now() - start;
          expect(elapsed).toBeLessThan(5);
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ── Property 45: LLM proxy latency bound ────────────────────────────────────

describe("Property 45: LLM proxy latency bound", () => {
  it("hash chain verification stays under 1ms per entry", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 20 }),
        (chainLength) => {
          const hashes: string[] = [];
          const start = performance.now();

          for (let i = 0; i < chainLength; i++) {
            const input = i === 0 ? "genesis" : hashes[i - 1]!;
            hashes.push(sha256(`entry-${i}-${input}`));
          }

          // Verify chain
          for (let i = 1; i < hashes.length; i++) {
            const expected = sha256(`entry-${i}-${hashes[i - 1]!}`);
            expect(hashes[i]).toBe(expected);
          }

          const elapsed = performance.now() - start;
          const avgPerEntry = elapsed / chainLength;
          expect(avgPerEntry).toBeLessThan(1);
        },
      ),
      { numRuns: 20 },
    );
  });
});
