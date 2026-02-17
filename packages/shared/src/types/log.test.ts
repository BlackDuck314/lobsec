import { describe, it, expect } from "vitest";
import type { LogEntry, AuditLogEntry } from "../index.js";

describe("shared types smoke test", () => {
  it("LogEntry shape is valid", () => {
    const entry: LogEntry = {
      ts: new Date().toISOString(),
      level: "INFO",
      component: "lobsec-cli",
      module: "test",
      fn: "smokeTest",
      msg: "hello",
      traceId: "abc-123",
      context: {},
    };
    expect(entry.level).toBe("INFO");
  });

  it("AuditLogEntry extends LogEntry", () => {
    const entry: AuditLogEntry = {
      ts: new Date().toISOString(),
      level: "WARN",
      component: "lobsec-proxy",
      module: "audit",
      fn: "check",
      msg: "denied",
      traceId: "def-456",
      context: { ip: "10.0.0.1" },
      layer: "L1",
      event: "deny",
      attackClass: [1, 2],
      prevHash: "0000000000000000",
    };
    expect(entry.layer).toBe("L1");
    expect(entry.event).toBe("deny");
  });
});
