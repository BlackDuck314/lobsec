import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import {
  Logger,
  meetsLevel,
  newTraceId,
  redact,
  sha256,
  verifyHashChain,
} from "./logger.js";
import type { AuditLogEntry, SecurityLayer, AuditEventType, AttackClass } from "./types/log.js";

// ── Unit: meetsLevel ───────────────────────────────────────────────────────

describe("meetsLevel", () => {
  it("TRACE meets TRACE", () => expect(meetsLevel("TRACE", "TRACE")).toBe(true));
  it("INFO does not meet ERROR", () => expect(meetsLevel("INFO", "ERROR")).toBe(false));
  it("CRITICAL meets everything", () => {
    for (const lvl of ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"] as const) {
      expect(meetsLevel("CRITICAL", lvl)).toBe(true);
    }
  });
  it("TRACE only meets TRACE", () => {
    expect(meetsLevel("TRACE", "DEBUG")).toBe(false);
  });
});

// ── Unit: newTraceId ───────────────────────────────────────────────────────

describe("newTraceId", () => {
  it("starts with tr_", () => {
    expect(newTraceId()).toMatch(/^tr_[a-f0-9]{24}$/);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => newTraceId()));
    expect(ids.size).toBe(100);
  });
});

// ── Unit: sha256 ───────────────────────────────────────────────────────────

describe("sha256", () => {
  it("produces 64-char hex string", () => {
    const h = sha256("hello");
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[a-f0-9]{64}$/);
  });

  it("is deterministic", () => {
    expect(sha256("test")).toBe(sha256("test"));
  });

  it("known value", () => {
    // SHA-256 of empty string
    expect(sha256("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

// ── Unit: redact ───────────────────────────────────────────────────────────

describe("redact", () => {
  it("redacts Bearer tokens", () => {
    const input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.abc123";
    const result = redact(input);
    expect(result).not.toContain("eyJhbGci");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts query string tokens", () => {
    const input = "https://api.example.com?token=sk-abcdef123456789&other=safe";
    const result = redact(input);
    expect(result).not.toContain("sk-abcdef123456789");
    expect(result).toContain("[REDACTED]");
    expect(result).toContain("other=safe");
  });

  it("redacts long hex strings", () => {
    const hex = "a".repeat(40);
    const result = redact(`key is ${hex} here`);
    expect(result).toContain("[REDACTED]");
  });

  it("applies extra patterns", () => {
    const input = "my-custom-secret-12345";
    const result = redact(input, [/my-custom-secret-\d+/g]);
    expect(result).toBe("[REDACTED]");
  });

  it("leaves safe strings unchanged", () => {
    const input = "normal log message about user action";
    expect(redact(input)).toBe(input);
  });
});

// ── Unit: Logger ───────────────────────────────────────────────────────────

describe("Logger", () => {
  let logger: Logger;

  beforeEach(() => {
    logger = new Logger({
      component: "lobsec-cli",
      destinations: [
        { type: "console", minLevel: "TRACE", format: "json" },
      ],
    });
  });

  it("initial chain head is 64 zeros", () => {
    expect(logger.chainHead).toBe("0".repeat(64));
  });

  it("audit() returns a valid AuditLogEntry", async () => {
    const entry = await logger.audit({
      layer: "L1",
      event: "deny",
      module: "firewall",
      fn: "checkIngress",
      msg: "blocked port scan",
      attackClass: [1],
    });

    expect(entry.layer).toBe("L1");
    expect(entry.event).toBe("deny");
    expect(entry.prevHash).toBe("0".repeat(64));
    expect(entry.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(entry.traceId).toMatch(/^tr_/);
    expect(entry.component).toBe("lobsec-cli");
  });

  it("audit() advances the hash chain", async () => {
    const e1 = await logger.audit({
      layer: "L1",
      event: "allow",
      module: "net",
      fn: "accept",
      msg: "connection accepted",
    });

    const expectedHash = sha256(JSON.stringify(e1));
    expect(logger.chainHead).toBe(expectedHash);

    const e2 = await logger.audit({
      layer: "L4",
      event: "deny",
      module: "tools",
      fn: "exec",
      msg: "tool denied",
    });

    expect(e2.prevHash).toBe(expectedHash);
  });

  it("audit deny/alert events get WARN level", async () => {
    const deny = await logger.audit({
      layer: "L1",
      event: "deny",
      module: "fw",
      fn: "check",
      msg: "denied",
    });
    expect(deny.level).toBe("WARN");

    const alert = await logger.audit({
      layer: "L9",
      event: "alert",
      module: "audit",
      fn: "drift",
      msg: "drift detected",
    });
    expect(alert.level).toBe("WARN");
  });

  it("audit allow/error events get INFO level", async () => {
    const allow = await logger.audit({
      layer: "L3",
      event: "allow",
      module: "cred",
      fn: "inject",
      msg: "credential injected",
    });
    expect(allow.level).toBe("INFO");
  });
});

// ── Unit: verifyHashChain ──────────────────────────────────────────────────

describe("verifyHashChain", () => {
  it("returns -1 for an empty chain", () => {
    expect(verifyHashChain([])).toBe(-1);
  });

  it("returns -1 for a single entry", async () => {
    const logger = new Logger({
      component: "lobsec-cli",
      destinations: [],
    });
    const e = await logger.audit({
      layer: "L9",
      event: "allow",
      module: "test",
      fn: "test",
      msg: "first",
    });
    expect(verifyHashChain([e])).toBe(-1);
  });

  it("returns -1 for a valid chain", async () => {
    const logger = new Logger({
      component: "lobsec-cli",
      destinations: [],
    });
    const entries: AuditLogEntry[] = [];
    for (let i = 0; i < 5; i++) {
      entries.push(
        await logger.audit({
          layer: "L9",
          event: "allow",
          module: "test",
          fn: "test",
          msg: `entry ${i}`,
        }),
      );
    }
    expect(verifyHashChain(entries)).toBe(-1);
  });

  it("detects tampered entries", async () => {
    const logger = new Logger({
      component: "lobsec-cli",
      destinations: [],
    });
    const entries: AuditLogEntry[] = [];
    for (let i = 0; i < 5; i++) {
      entries.push(
        await logger.audit({
          layer: "L9",
          event: "allow",
          module: "test",
          fn: "test",
          msg: `entry ${i}`,
        }),
      );
    }

    // Tamper with entry 2
    entries[2] = { ...entries[2]!, msg: "TAMPERED" };

    // The break should be at index 3, because entry[3].prevHash
    // won't match sha256(tampered entry[2])
    expect(verifyHashChain(entries)).toBe(3);
  });

  it("detects deletion of entries", async () => {
    const logger = new Logger({
      component: "lobsec-cli",
      destinations: [],
    });
    const entries: AuditLogEntry[] = [];
    for (let i = 0; i < 5; i++) {
      entries.push(
        await logger.audit({
          layer: "L9",
          event: "allow",
          module: "test",
          fn: "test",
          msg: `entry ${i}`,
        }),
      );
    }

    // Remove entry 2 — entry 3's prevHash now points to missing entry
    entries.splice(2, 1);
    expect(verifyHashChain(entries)).toBe(2);
  });
});

// ── Property: Hash chain integrity (Property 40) ──────────────────────────

describe("Property 40: Hash chain integrity", () => {
  // Arbitraries for audit parameters
  const layerArb = fc.constantFrom<SecurityLayer>("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9");
  const eventArb = fc.constantFrom<AuditEventType>("allow", "deny", "alert", "error");
  const attackClassArb = fc.array(
    fc.constantFrom<AttackClass>(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
    { minLength: 0, maxLength: 3 },
  );

  it("any sequence of audit entries forms a valid hash chain", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            layer: layerArb,
            event: eventArb,
            msg: fc.string({ minLength: 1, maxLength: 100 }),
            attackClass: attackClassArb,
          }),
          { minLength: 1, maxLength: 20 },
        ),
        async (params) => {
          const logger = new Logger({
            component: "lobsec-proxy",
            destinations: [],
          });
          const entries: AuditLogEntry[] = [];

          for (const p of params) {
            entries.push(
              await logger.audit({
                ...p,
                module: "proptest",
                fn: "hashChain",
              }),
            );
          }

          // Chain must be intact
          expect(verifyHashChain(entries)).toBe(-1);

          // Every entry after the first must have prevHash matching sha256 of previous
          for (let i = 1; i < entries.length; i++) {
            const expected = sha256(JSON.stringify(entries[i - 1]));
            expect(entries[i]!.prevHash).toBe(expected);
          }
        },
      ),
      { numRuns: 50 },
    );
  });

  it("tamper with any entry breaks the chain at the next position", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            layer: layerArb,
            event: eventArb,
            msg: fc.string({ minLength: 1, maxLength: 50 }),
            attackClass: attackClassArb,
          }),
          { minLength: 3, maxLength: 10 },
        ),
        fc.nat(),
        async (params, tamperSeed) => {
          const logger = new Logger({
            component: "lobsec-cli",
            destinations: [],
          });
          const entries: AuditLogEntry[] = [];

          for (const p of params) {
            entries.push(
              await logger.audit({
                ...p,
                module: "proptest",
                fn: "tamper",
              }),
            );
          }

          // Pick an entry to tamper with (not the last one)
          const tamperIdx = tamperSeed % (entries.length - 1);
          entries[tamperIdx] = { ...entries[tamperIdx]!, msg: "TAMPERED_" + tamperSeed };

          // Chain must break at tamperIdx + 1
          const breakIdx = verifyHashChain(entries);
          expect(breakIdx).toBe(tamperIdx + 1);
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ── Property 39: Audit log structure completeness ─────────────────────────

describe("Property 39: Audit log structure completeness", () => {
  const layerArb = fc.constantFrom<SecurityLayer>("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9");
  const eventArb = fc.constantFrom<AuditEventType>("allow", "deny", "alert", "error");

  it("every audit entry has all required fields", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          layer: layerArb,
          event: eventArb,
          msg: fc.string({ minLength: 1, maxLength: 100 }),
        }),
        async (params) => {
          const logger = new Logger({
            component: "lobsec-plugin",
            destinations: [],
          });

          const entry = await logger.audit({
            ...params,
            module: "proptest",
            fn: "completeness",
          });

          // Required fields per spec
          expect(entry.ts).toBeDefined();
          expect(entry.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
          expect(entry.level).toBeDefined();
          expect(entry.component).toBeDefined();
          expect(entry.module).toBeDefined();
          expect(entry.fn).toBeDefined();
          expect(entry.msg).toBeDefined();
          expect(entry.traceId).toMatch(/^tr_[a-f0-9]{24}$/);
          expect(entry.context).toBeDefined();
          expect(entry.layer).toBeDefined();
          expect(entry.event).toBeDefined();
          expect(entry.prevHash).toMatch(/^[a-f0-9]{64}$/);
        },
      ),
      { numRuns: 50 },
    );
  });
});
