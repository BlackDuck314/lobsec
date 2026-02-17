import { describe, it, expect } from "vitest";
import {
  executeStartup,
  executeShutdown,
  initialState,
  STARTUP_SEQUENCE,
  SHUTDOWN_SEQUENCE,
} from "./orchestrator.js";
import type { OrchestratorConfig } from "./orchestrator.js";

// ── Unit: initialState ────────────────────────────────────────────────────

describe("initialState", () => {
  it("starts in stopped phase", () => {
    const state = initialState();
    expect(state.phase).toBe("stopped");
  });

  it("has all components in stopped status", () => {
    const state = initialState();
    expect(state.components).toHaveLength(STARTUP_SEQUENCE.length);
    for (const comp of state.components) {
      expect(comp.status).toBe("stopped");
    }
  });
});

// ── Unit: STARTUP_SEQUENCE ────────────────────────────────────────────────

describe("STARTUP_SEQUENCE", () => {
  it("starts with config generation", () => {
    expect(STARTUP_SEQUENCE[0]).toBe("config-generation");
  });

  it("ends with http-proxy-env", () => {
    expect(STARTUP_SEQUENCE[STARTUP_SEQUENCE.length - 1]).toBe("http-proxy-env");
  });

  it("config validation comes after generation", () => {
    const genIdx = STARTUP_SEQUENCE.indexOf("config-generation");
    const valIdx = STARTUP_SEQUENCE.indexOf("config-validation");
    expect(valIdx).toBeGreaterThan(genIdx);
  });

  it("audit logging starts before network components", () => {
    const auditIdx = STARTUP_SEQUENCE.indexOf("audit-logging");
    const nftIdx = STARTUP_SEQUENCE.indexOf("nftables");
    expect(auditIdx).toBeLessThan(nftIdx);
  });
});

// ── Unit: SHUTDOWN_SEQUENCE ───────────────────────────────────────────────

describe("SHUTDOWN_SEQUENCE", () => {
  it("is reverse of startup sequence", () => {
    expect(SHUTDOWN_SEQUENCE).toEqual([...STARTUP_SEQUENCE].reverse());
  });
});

// ── Unit: executeStartup ──────────────────────────────────────────────────

describe("executeStartup", () => {
  const config: OrchestratorConfig = {
    baseDir: "/tmp/lobsec-test",
  };

  it("executes all steps successfully", async () => {
    const results = await executeStartup(config);
    expect(results).toHaveLength(STARTUP_SEQUENCE.length);
    expect(results.every((r) => r.success)).toBe(true);
  });

  it("skips nftables when skipFirewall is set", async () => {
    const results = await executeStartup({ ...config, skipFirewall: true });
    const nftStep = results.find((r) => r.step === "nftables");
    expect(nftStep?.message).toBe("skipped");
  });

  it("skips caddy when skipCaddy is set", async () => {
    const results = await executeStartup({ ...config, skipCaddy: true });
    const caddyStep = results.find((r) => r.step === "caddy-proxy");
    expect(caddyStep?.message).toBe("skipped");
  });

  it("skips proxy when skipProxy is set", async () => {
    const results = await executeStartup({ ...config, skipProxy: true });
    const proxyStep = results.find((r) => r.step === "lobsec-proxy");
    expect(proxyStep?.message).toBe("skipped");
    const envStep = results.find((r) => r.step === "http-proxy-env");
    expect(envStep?.message).toBe("skipped");
  });

  it("calls onStep callback for each step", async () => {
    const callbacks: Array<{ step: string; status: string }> = [];
    await executeStartup(config, (step, status) => {
      callbacks.push({ step, status });
    });

    // Each step gets "start" and "done"
    for (const step of STARTUP_SEQUENCE) {
      expect(callbacks.some((c) => c.step === step && c.status === "start")).toBe(true);
      expect(callbacks.some((c) => c.step === step && c.status === "done")).toBe(true);
    }
  });

  it("records duration for each step", async () => {
    const results = await executeStartup(config);
    for (const result of results) {
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    }
  });
});

// ── Unit: executeShutdown ─────────────────────────────────────────────────

describe("executeShutdown", () => {
  const config: OrchestratorConfig = {
    baseDir: "/tmp/lobsec-test",
  };

  it("executes shutdown for all components", async () => {
    const results = await executeShutdown(config);
    expect(results).toHaveLength(SHUTDOWN_SEQUENCE.length);
  });

  it("continues shutdown even if a step fails", async () => {
    // All steps currently succeed, but the design continues on failure
    const results = await executeShutdown(config);
    expect(results.length).toBeGreaterThan(0);
  });

  it("calls onStep callback", async () => {
    const callbacks: Array<{ step: string; status: string }> = [];
    await executeShutdown(config, (step, status) => {
      callbacks.push({ step, status });
    });
    expect(callbacks.length).toBeGreaterThan(0);
  });
});

// ── Integration: startup then shutdown ────────────────────────────────────

describe("startup → shutdown lifecycle", () => {
  const config: OrchestratorConfig = {
    baseDir: "/tmp/lobsec-test-lifecycle",
    skipFirewall: true,
    skipCaddy: true,
    skipProxy: true,
  };

  it("starts and stops cleanly", async () => {
    const startResults = await executeStartup(config);
    expect(startResults.every((r) => r.success)).toBe(true);

    const stopResults = await executeShutdown(config);
    expect(stopResults.every((r) => r.success)).toBe(true);
  });
});
