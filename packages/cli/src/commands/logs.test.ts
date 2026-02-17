import { describe, it, expect } from "vitest";
import { filterEntries } from "./logs.js";
import type { AuditLogEntry } from "@lobsec/shared";

function makeEntry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    ts: "2026-02-24T19:00:00.000Z",
    level: "INFO",
    component: "lobsec-cli",
    module: "test",
    fn: "test",
    msg: "test message",
    traceId: "tr_abc123",
    context: {},
    layer: "L1",
    event: "allow",
    prevHash: "0".repeat(64),
    ...overrides,
  };
}

describe("filterEntries", () => {
  const entries: AuditLogEntry[] = [
    makeEntry({ ts: "2026-02-24T18:00:00.000Z", level: "DEBUG", component: "lobsec-cli", layer: "L1", traceId: "tr_aaa" }),
    makeEntry({ ts: "2026-02-24T19:00:00.000Z", level: "INFO", component: "lobsec-proxy", layer: "L5", traceId: "tr_bbb" }),
    makeEntry({ ts: "2026-02-24T20:00:00.000Z", level: "WARN", component: "lobsec-cli", layer: "L9", traceId: "tr_aaa" }),
    makeEntry({ ts: "2026-02-24T21:00:00.000Z", level: "ERROR", component: "lobsec-plugin", layer: "L4", traceId: "tr_ccc" }),
    makeEntry({ ts: "2026-02-24T22:00:00.000Z", level: "CRITICAL", component: "lobsec-cli", layer: "L1", traceId: "tr_ddd" }),
  ];

  it("returns all entries with no filter", () => {
    expect(filterEntries(entries, {})).toHaveLength(5);
  });

  it("filters by minimum level", () => {
    const result = filterEntries(entries, { level: "WARN" });
    expect(result).toHaveLength(3);
    expect(result.every((e) => ["WARN", "ERROR", "CRITICAL"].includes(e.level))).toBe(true);
  });

  it("filters by component", () => {
    const result = filterEntries(entries, { component: "lobsec-cli" });
    expect(result).toHaveLength(3);
  });

  it("filters by layer", () => {
    const result = filterEntries(entries, { layer: "L1" });
    expect(result).toHaveLength(2);
  });

  it("filters by traceId", () => {
    const result = filterEntries(entries, { traceId: "tr_aaa" });
    expect(result).toHaveLength(2);
  });

  it("filters by since", () => {
    const result = filterEntries(entries, { since: "2026-02-24T20:00:00.000Z" });
    expect(result).toHaveLength(3);
  });

  it("filters by until", () => {
    const result = filterEntries(entries, { until: "2026-02-24T19:00:00.000Z" });
    expect(result).toHaveLength(2);
  });

  it("filters by time range", () => {
    const result = filterEntries(entries, {
      since: "2026-02-24T19:00:00.000Z",
      until: "2026-02-24T21:00:00.000Z",
    });
    expect(result).toHaveLength(3);
  });

  it("limits results (last N)", () => {
    const result = filterEntries(entries, { limit: 2 });
    expect(result).toHaveLength(2);
    expect(result[0]!.level).toBe("ERROR");
    expect(result[1]!.level).toBe("CRITICAL");
  });

  it("combines multiple filters", () => {
    const result = filterEntries(entries, {
      level: "WARN",
      component: "lobsec-cli",
    });
    expect(result).toHaveLength(2);
    expect(result[0]!.level).toBe("WARN");
    expect(result[1]!.level).toBe("CRITICAL");
  });
});
