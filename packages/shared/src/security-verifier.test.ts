import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { verifyAll, LAYER_NAMES } from "./security-verifier.js";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

// ── Test fixtures ───────────────────────────────────────────────────────────

let testDir: string;

const VALID_CONFIG = {
  gateway: {
    bind: "loopback",
    auth: { mode: "token", token: "test" },
    controlUi: { dangerouslyDisableDeviceAuth: false, allowedOrigins: [] },
    trustedProxies: ["127.0.0.1"],
  },
  agents: {
    defaults: {
      model: "default",
      sandbox: {
        mode: "all",
        scope: "agent",
        docker: { readOnlyRoot: true, capDrop: ["ALL"], network: "none" },
      },
    },
  },
  tools: {
    profile: "locked-down",
    deny: ["gateway", "sessions_spawn", "sessions_send", "group:automation", "group:runtime"],
    exec: { security: "deny", ask: "always" },
    fs: { workspaceOnly: true },
    elevated: { enabled: false },
  },
  browser: { ssrfPolicy: { dangerouslyAllowPrivateNetwork: false, hostnameAllowlist: [] } },
  discovery: { mdns: { mode: "off" } },
  session: { dmScope: "per-channel-peer" },
  logging: { redactSensitive: true, redactPatterns: [] },
  update: { auto: { enabled: false } },
  plugins: { allow: [] },
};

const ADAPTER_CONTENT = `
import { CredentialRedactor } from "./dist/credential-redactor.js";
api.on("message_sending", handler);
api.on("tool_result_persist", handler);
`;

beforeEach(async () => {
  testDir = join(tmpdir(), `lobsec-verify-${randomUUID()}`);
  await mkdir(testDir, { recursive: true });
  await mkdir(join(testDir, ".openclaw"), { recursive: true });
  await mkdir(join(testDir, "logs"), { recursive: true });
  await mkdir(join(testDir, "proxy"), { recursive: true });
  await mkdir(join(testDir, "plugins", "lobsec-security"), { recursive: true });

  // Write default config
  await writeFile(join(testDir, ".openclaw", "openclaw.json"), JSON.stringify(VALID_CONFIG, null, 2));

  // Write gateway env (no real cloud keys)
  await writeFile(join(testDir, ".env"), "OPENCLAW_GATEWAY_TOKEN=proxy-token\n");

  // Write proxy env
  await writeFile(join(testDir, "proxy", ".env"), "ANTHROPIC_API_KEY=sk-ant-123\nOLLAMA_API_KEY=ollama-key\n");

  // Write adapter stub
  await writeFile(join(testDir, "plugins", "lobsec-security", "index.js"), ADAPTER_CONTENT);

  // Write audit log
  await writeFile(join(testDir, "logs", "audit.jsonl"), '{"ts":"2026-03-03T10:00:00Z","event":"test"}\n');
});

afterEach(async () => {
  await rm(testDir, { recursive: true, force: true });
});

// ── Unit: verifyAll ──────────────────────────────────────────────────────────

describe("verifyAll", () => {
  it("returns a report with all 9 layers", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      configPath: join(testDir, ".openclaw", "openclaw.json"),
      auditLogPath: join(testDir, "logs", "audit.jsonl"),
      gatewayEnvPath: join(testDir, ".env"),
      proxyEnvPath: join(testDir, "proxy", ".env"),
    });

    expect(report.layers.length).toBe(9);
    expect(report.summary.total).toBeGreaterThan(0);
    expect(report.timestamp).toBeTruthy();
    expect(["pass", "fail", "warn"]).toContain(report.overall);
  });

  it("report structure is correct", async () => {
    const report = await verifyAll({ baseDir: testDir });

    for (const layer of report.layers) {
      expect(layer.layer).toBeTruthy();
      expect(["pass", "fail", "warn", "skip"]).toContain(layer.status);
      expect(Array.isArray(layer.checks)).toBe(true);
      for (const check of layer.checks) {
        expect(check.name).toBeTruthy();
        expect(["pass", "fail", "warn", "skip"]).toContain(check.status);
        expect(check.message).toBeTruthy();
      }
    }

    expect(report.summary.total).toBe(
      report.summary.passed + report.summary.failed +
      report.summary.warned + report.summary.skipped
    );
  });

  it("filters to specific layers", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["credentials", "tools"],
    });

    expect(report.layers.length).toBe(2);
    expect(report.layers.map(l => l.layer)).toContain("L1: Credentials");
    expect(report.layers.map(l => l.layer)).toContain("L3: Tools");
  });

  it("ignores unknown layer names", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["nonexistent"],
    });

    expect(report.layers.length).toBe(0);
    expect(report.overall).toBe("pass");
  });
});

// ── L1: Credentials ──────────────────────────────────────────────────────────

describe("L1: Credentials", () => {
  it("passes when gateway has no real cloud keys", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["credentials"],
    });

    const layer = report.layers[0]!;
    expect(layer.layer).toBe("L1: Credentials");
    const gatewayCheck = layer.checks.find(c => c.name === "gateway-no-cloud-keys");
    expect(gatewayCheck?.status).toBe("pass");
  });

  it("fails when gateway has real Anthropic key", async () => {
    await writeFile(join(testDir, ".env"), "ANTHROPIC_API_KEY=sk-ant-real-secret-key\n");

    const report = await verifyAll({
      baseDir: testDir,
      layers: ["credentials"],
    });

    const layer = report.layers[0]!;
    const gatewayCheck = layer.checks.find(c => c.name === "gateway-no-cloud-keys");
    expect(gatewayCheck?.status).toBe("fail");
  });

  it("passes when proxy has credentials", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["credentials"],
    });

    const layer = report.layers[0]!;
    const proxyAnthropicCheck = layer.checks.find(c => c.name === "proxy-has-anthropic-key");
    expect(proxyAnthropicCheck?.status).toBe("pass");
  });
});

// ── L3: Tools ──────────────────────────────────────────────────────────────

describe("L3: Tools", () => {
  it("passes with hardened config", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["tools"],
    });

    const layer = report.layers[0]!;
    expect(layer.status).toBe("pass");
  });

  it("fails when exec security is allow", async () => {
    const tampered = JSON.parse(JSON.stringify(VALID_CONFIG));
    tampered.tools.exec.security = "allow";
    await writeFile(join(testDir, ".openclaw", "openclaw.json"), JSON.stringify(tampered));

    const report = await verifyAll({
      baseDir: testDir,
      layers: ["tools"],
    });

    const layer = report.layers[0]!;
    expect(layer.status).toBe("fail");
  });
});

// ── L4: Redaction ──────────────────────────────────────────────────────────

describe("L4: Redaction", () => {
  it("passes when adapter has CredentialRedactor and hooks", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["redaction"],
    });

    const layer = report.layers[0]!;
    expect(layer.checks.find(c => c.name === "redactor-imported")?.status).toBe("pass");
    expect(layer.checks.find(c => c.name === "redactor-hook-registered")?.status).toBe("pass");
  });
});

// ── L5: Drift ──────────────────────────────────────────────────────────────

describe("L5: Drift", () => {
  it("warns when no expected hash provided", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["drift"],
    });

    const layer = report.layers[0]!;
    const driftCheck = layer.checks.find(c => c.name === "config-drift");
    expect(driftCheck?.status).toBe("warn");
  });
});

// ── L6: Audit ──────────────────────────────────────────────────────────────

describe("L6: Audit", () => {
  it("passes when audit log exists and is fresh", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["audit"],
    });

    const layer = report.layers[0]!;
    const existsCheck = layer.checks.find(c => c.name === "audit-log-exists");
    expect(existsCheck?.status).toBe("pass");
    const freshCheck = layer.checks.find(c => c.name === "audit-log-fresh");
    expect(freshCheck?.status).toBe("pass");
  });

  it("fails when audit log is missing", async () => {
    await rm(join(testDir, "logs", "audit.jsonl"));

    const report = await verifyAll({
      baseDir: testDir,
      layers: ["audit"],
    });

    const layer = report.layers[0]!;
    const existsCheck = layer.checks.find(c => c.name === "audit-log-exists");
    expect(existsCheck?.status).toBe("fail");
  });
});

// ── L7: Sandbox ────────────────────────────────────────────────────────────

describe("L7: Sandbox", () => {
  it("passes with correct sandbox config", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["sandbox"],
    });

    const layer = report.layers[0]!;
    expect(layer.checks.find(c => c.name === "sandbox-mode")?.status).toBe("pass");
    expect(layer.checks.find(c => c.name === "sandbox-readonly")?.status).toBe("pass");
    expect(layer.checks.find(c => c.name === "sandbox-network")?.status).toBe("pass");
  });

  it("fails when sandbox mode is not 'all'", async () => {
    const tampered = JSON.parse(JSON.stringify(VALID_CONFIG));
    tampered.agents.defaults.sandbox.mode = "none";
    await writeFile(join(testDir, ".openclaw", "openclaw.json"), JSON.stringify(tampered));

    const report = await verifyAll({
      baseDir: testDir,
      layers: ["sandbox"],
    });

    const layer = report.layers[0]!;
    expect(layer.checks.find(c => c.name === "sandbox-mode")?.status).toBe("fail");
  });
});

// ── L8: Network ────────────────────────────────────────────────────────────

describe("L8: Network", () => {
  it("passes loopback check with correct config", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["network"],
    });

    const layer = report.layers[0]!;
    expect(layer.checks.find(c => c.name === "gateway-loopback")?.status).toBe("pass");
  });

  it("fails when gateway binds to 0.0.0.0", async () => {
    const tampered = JSON.parse(JSON.stringify(VALID_CONFIG));
    tampered.gateway.bind = "0.0.0.0";
    await writeFile(join(testDir, ".openclaw", "openclaw.json"), JSON.stringify(tampered));

    const report = await verifyAll({
      baseDir: testDir,
      layers: ["network"],
    });

    const layer = report.layers[0]!;
    expect(layer.checks.find(c => c.name === "gateway-loopback")?.status).toBe("fail");
  });
});

// ── Overall status aggregation ──────────────────────────────────────────────

describe("Overall status aggregation", () => {
  it("overall is fail if any layer fails", async () => {
    // Tamper config to cause a tool failure
    const tampered = JSON.parse(JSON.stringify(VALID_CONFIG));
    tampered.tools.exec.security = "allow";
    await writeFile(join(testDir, ".openclaw", "openclaw.json"), JSON.stringify(tampered));

    const report = await verifyAll({
      baseDir: testDir,
      layers: ["tools"],
    });

    expect(report.overall).toBe("fail");
    expect(report.summary.failed).toBeGreaterThan(0);
  });

  it("overall is pass when all checks pass", async () => {
    const report = await verifyAll({
      baseDir: testDir,
      layers: ["tools"],
    });

    expect(report.overall).toBe("pass");
  });

  it("summary counts are consistent", async () => {
    const report = await verifyAll({ baseDir: testDir });
    const { summary } = report;

    expect(summary.total).toBe(summary.passed + summary.failed + summary.warned + summary.skipped);
    expect(summary.total).toBeGreaterThan(0);
  });
});

// ── LAYER_NAMES ──────────────────────────────────────────────────────────────

describe("LAYER_NAMES", () => {
  it("has 9 layers", () => {
    expect(LAYER_NAMES.length).toBe(9);
  });

  it("contains all expected layer names", () => {
    expect(LAYER_NAMES).toContain("credentials");
    expect(LAYER_NAMES).toContain("sovereign");
    expect(LAYER_NAMES).toContain("tools");
    expect(LAYER_NAMES).toContain("redaction");
    expect(LAYER_NAMES).toContain("drift");
    expect(LAYER_NAMES).toContain("audit");
    expect(LAYER_NAMES).toContain("sandbox");
    expect(LAYER_NAMES).toContain("network");
    expect(LAYER_NAMES).toContain("encryption");
  });
});
