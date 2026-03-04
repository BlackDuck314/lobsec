import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { buildCommands } from "./bot-commands.js";
import type { CommandDeps } from "./bot-commands.js";
import { SovereignRouter } from "./sovereign-router.js";
import { ConfigMonitor } from "./config-monitor.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

// ── Test fixtures ───────────────────────────────────────────────────────────

let testDir: string;
let auditLogPath: string;
let deps: CommandDeps;
let router: SovereignRouter;

beforeEach(() => {
  testDir = join(tmpdir(), `lobsec-bot-${randomUUID()}`);
  mkdirSync(testDir, { recursive: true });
  auditLogPath = join(testDir, "audit.jsonl");

  // Write sample audit log
  const entries = [
    { ts: "2026-03-03T10:00:00Z", level: "INFO", event: "gateway_start" },
    { ts: "2026-03-03T10:01:00Z", level: "WARN", event: "tool_denied", tool: "exec" },
    { ts: "2026-03-03T10:02:00Z", level: "INFO", event: "llm_request", model: "claude-haiku-4-5" },
  ];
  writeFileSync(auditLogPath, entries.map(e => JSON.stringify(e)).join("\n") + "\n");

  router = new SovereignRouter({
    defaultMode: "auto",
    sovereignBackends: [
      { name: "portullama", url: "http://localhost:11435", model: "qwen2.5:32b", available: true },
    ],
    cloudModels: [],
    channelDefaults: {},
  });

  deps = {
    monitor: null,
    router,
    auditLogPath,
    verifyFn: async () => ({
      overall: "pass",
      layers: [
        { layer: "L1: Credentials", status: "pass", checks: [{ name: "gateway-no-cloud-keys", status: "pass", message: "No keys leaked" }] },
        { layer: "L2: Sovereign", status: "pass", checks: [{ name: "sovereign-config", status: "pass", message: "OK" }] },
        { layer: "L3: Tools", status: "pass", checks: [{ name: "tools-hardened", status: "pass", message: "OK" }] },
        { layer: "L4: Redaction", status: "warn", checks: [{ name: "redactor", status: "warn", message: "Hook check" }] },
        { layer: "L5: Drift", status: "pass", checks: [{ name: "config-drift", status: "pass", message: "Clean" }] },
        { layer: "L6: Audit", status: "pass", checks: [{ name: "audit-log", status: "pass", message: "OK" }] },
        { layer: "L7: Sandbox", status: "pass", checks: [{ name: "sandbox-mode", status: "pass", message: "OK" }] },
        { layer: "L8: Network", status: "pass", checks: [{ name: "loopback", status: "pass", message: "OK" }] },
        { layer: "L9: Encryption", status: "pass", checks: [{ name: "fscrypt", status: "pass", message: "OK" }] },
      ],
      summary: { passed: 8, failed: 0, warned: 1, skipped: 0 },
    }),
  };
});

afterEach(() => {
  rmSync(testDir, { recursive: true, force: true });
});

// ── Unit: buildCommands ──────────────────────────────────────────────────

describe("buildCommands", () => {
  it("returns 5 commands", () => {
    const commands = buildCommands(deps);
    expect(commands).toHaveLength(5);
  });

  it("all commands have name, description, and handler", () => {
    const commands = buildCommands(deps);
    for (const cmd of commands) {
      expect(cmd.name).toBeTruthy();
      expect(cmd.description).toBeTruthy();
      expect(typeof cmd.handler).toBe("function");
    }
  });

  it("command names are correct", () => {
    const commands = buildCommands(deps);
    const names = commands.map(c => c.name);
    expect(names).toContain("status");
    expect(names).toContain("verify");
    expect(names).toContain("audit");
    expect(names).toContain("alerts");
    expect(names).toContain("sovereign");
  });
});

// ── /status command ────────────────────────────────────────────────────────

describe("/status command", () => {
  it("returns layer scorecard", async () => {
    const commands = buildCommands(deps);
    const statusCmd = commands.find(c => c.name === "status")!;
    const result = await statusCmd.handler({ channel: "telegram", senderId: "user1" });
    expect(result.text).toContain("Security Status");
    expect(result.text).toContain("PASS");
    expect(result.text).toContain("L1: Credentials");
    expect(result.text).toContain("8/9 checks passing");
  });

  it("handles missing verifyFn gracefully", async () => {
    const commands = buildCommands({ ...deps, verifyFn: undefined });
    const statusCmd = commands.find(c => c.name === "status")!;
    const result = await statusCmd.handler({ channel: "telegram" });
    expect(result.text).toContain("not available");
  });

  it("handles verifyFn error", async () => {
    const commands = buildCommands({
      ...deps,
      verifyFn: async () => { throw new Error("connection refused"); },
    });
    const statusCmd = commands.find(c => c.name === "status")!;
    const result = await statusCmd.handler({ channel: "telegram" });
    expect(result.text).toContain("failed");
    expect(result.text).toContain("connection refused");
  });
});

// ── /verify command ────────────────────────────────────────────────────────

describe("/verify command", () => {
  it("returns detailed per-check report", async () => {
    const commands = buildCommands(deps);
    const verifyCmd = commands.find(c => c.name === "verify")!;
    const result = await verifyCmd.handler({ channel: "telegram" });
    expect(result.text).toContain("Security Verification");
    expect(result.text).toContain("gateway-no-cloud-keys");
    expect(result.text).toContain("Passed: 8");
    expect(result.text).toContain("Warned: 1");
  });
});

// ── /audit command ─────────────────────────────────────────────────────────

describe("/audit command", () => {
  it("shows last N audit entries", () => {
    const commands = buildCommands(deps);
    const auditCmd = commands.find(c => c.name === "audit")!;
    const result = auditCmd.handler({ channel: "telegram", args: "2" });
    const text = (result as { text: string }).text;
    expect(text).toContain("Last 2 audit entries");
    expect(text).toContain("tool_denied");
    expect(text).toContain("llm_request");
    // Should NOT include the first entry (gateway_start)
    expect(text).not.toContain("gateway_start");
  });

  it("defaults to 10 entries", () => {
    const commands = buildCommands(deps);
    const auditCmd = commands.find(c => c.name === "audit")!;
    const result = auditCmd.handler({ channel: "telegram" });
    const text = (result as { text: string }).text;
    expect(text).toContain("Last 3 audit entries");
  });

  it("handles missing audit log", () => {
    const commands = buildCommands({ ...deps, auditLogPath: "/nonexistent/path" });
    const auditCmd = commands.find(c => c.name === "audit")!;
    const result = auditCmd.handler({ channel: "telegram" });
    expect((result as { text: string }).text).toContain("not readable");
  });
});

// ── /alerts command ────────────────────────────────────────────────────────

describe("/alerts command", () => {
  it("shows no alerts when monitor is null", () => {
    const commands = buildCommands(deps);
    const alertsCmd = commands.find(c => c.name === "alerts")!;
    const result = alertsCmd.handler({ channel: "telegram" });
    expect((result as { text: string }).text).toContain("not running");
  });

  it("shows no alerts when monitor has none", () => {
    const monitor = new ConfigMonitor({
      expectedHash: "abc123",
      config: {},
      heartbeatPath: "/nonexistent",
      intervalSeconds: 60,
    });
    const commands = buildCommands({ ...deps, monitor });
    const alertsCmd = commands.find(c => c.name === "alerts")!;
    const result = alertsCmd.handler({ channel: "telegram" });
    const text = (result as { text: string }).text;
    expect(text).toContain("No active alerts");
  });
});

// ── /sovereign command ────────────────────────────────────────────────────

describe("/sovereign command", () => {
  it("shows current mode when no args", () => {
    const commands = buildCommands(deps);
    const sovCmd = commands.find(c => c.name === "sovereign")!;
    const result = sovCmd.handler({ channel: "telegram", senderId: "user1" });
    expect((result as { text: string }).text).toContain("Current routing mode");
  });

  it("sets mode to sovereign with 'on'", () => {
    const commands = buildCommands(deps);
    const sovCmd = commands.find(c => c.name === "sovereign")!;
    const result = sovCmd.handler({ channel: "telegram", senderId: "user1", args: "on" });
    expect((result as { text: string }).text).toContain("sovereign");
  });

  it("sets mode to public with 'off'", () => {
    const commands = buildCommands(deps);
    const sovCmd = commands.find(c => c.name === "sovereign")!;
    const result = sovCmd.handler({ channel: "telegram", senderId: "user1", args: "off" });
    expect((result as { text: string }).text).toContain("public");
  });

  it("sets mode to auto", () => {
    const commands = buildCommands(deps);
    const sovCmd = commands.find(c => c.name === "sovereign")!;
    const result = sovCmd.handler({ channel: "telegram", senderId: "user1", args: "auto" });
    expect((result as { text: string }).text).toContain("auto");
  });

  it("rejects unknown mode", () => {
    const commands = buildCommands(deps);
    const sovCmd = commands.find(c => c.name === "sovereign")!;
    const result = sovCmd.handler({ channel: "telegram", senderId: "user1", args: "banana" });
    expect((result as { text: string }).text).toContain("Unknown mode");
  });
});
