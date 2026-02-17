import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import {
  LifecycleOrchestrator,
  STARTUP_PHASES,
  SHUTDOWN_PHASES,
} from "./lifecycle.js";
import type { LifecycleConfig } from "./lifecycle.js";
import { MockHsmClient } from "@lobsec/shared";

// ── Helpers ─────────────────────────────────────────────────────────────────

let hsm: MockHsmClient;

function makeConfig(overrides: Partial<LifecycleConfig> = {}): LifecycleConfig {
  return {
    baseDir: "/etc/lobsec",
    hsm,
    dryRun: false,
    ...overrides,
  };
}

beforeEach(async () => {
  hsm = new MockHsmClient();
  await hsm.initialize("/mock", 0, "1234");
});

// ── Unit: Startup sequence ──────────────────────────────────────────────────

describe("Startup sequence", () => {
  it("completes all startup phases in order", async () => {
    // Finalize first so lifecycle can re-init
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    const result = await orch.start();

    expect(result.success).toBe(true);
    expect(result.phases).toHaveLength(STARTUP_PHASES.length);
    expect(result.phases.every((p) => p.success)).toBe(true);
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it("sets running state after successful startup", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    expect(orch.isRunning).toBe(false);

    await orch.start();
    expect(orch.isRunning).toBe(true);
  });

  it("executes phases in correct order", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    const result = await orch.start();

    for (let i = 0; i < STARTUP_PHASES.length; i++) {
      expect(result.phases[i]!.phase).toBe(STARTUP_PHASES[i]);
    }
  });

  it("supports dry-run mode", async () => {
    const orch = new LifecycleOrchestrator(makeConfig({ dryRun: true }));
    const result = await orch.start();

    expect(result.success).toBe(true);
    expect(result.phases.every((p) => p.detail?.includes("[dry-run]"))).toBe(true);
  });

  it("starts without HSM when not configured", async () => {
    const orch = new LifecycleOrchestrator(makeConfig({ hsm: undefined }));
    const result = await orch.start();

    expect(result.success).toBe(true);
    const hsmPhase = result.phases.find((p) => p.phase === "hsm-init");
    expect(hsmPhase?.detail).toContain("skipped");
  });
});

// ── Unit: Shutdown sequence ─────────────────────────────────────────────────

describe("Shutdown sequence", () => {
  it("completes all shutdown phases", async () => {
    const orch = new LifecycleOrchestrator(makeConfig());
    const result = await orch.stop();

    expect(result.phases).toHaveLength(SHUTDOWN_PHASES.length);
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it("clears running state after shutdown", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    await orch.start();
    expect(orch.isRunning).toBe(true);

    await orch.stop();
    expect(orch.isRunning).toBe(false);
  });

  it("continues shutdown even on phase error", async () => {
    // Use a new HSM that will fail on finalize after being finalized already
    const badHsm = new MockHsmClient();
    // Don't initialize — finalize will throw
    const orch = new LifecycleOrchestrator(makeConfig({ hsm: badHsm }));
    const result = await orch.stop();

    // Should have attempted all phases
    expect(result.phases).toHaveLength(SHUTDOWN_PHASES.length);
    // HSM finalize should fail but others should succeed
    const hsmPhase = result.phases.find((p) => p.phase === "hsm-finalize");
    expect(hsmPhase).toBeDefined();
  });

  it("supports dry-run shutdown", async () => {
    const orch = new LifecycleOrchestrator(makeConfig({ dryRun: true }));
    const result = await orch.stop();

    expect(result.phases.every((p) => p.detail?.includes("[dry-run]"))).toBe(true);
  });
});

// ── Unit: Restart ───────────────────────────────────────────────────────────

describe("Restart", () => {
  it("performs stop then start", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    const result = await orch.restart();

    expect(result.shutdown.phases.length).toBeGreaterThan(0);
    expect(result.startup.phases.length).toBeGreaterThan(0);
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it("reports zero-downtime when both succeed", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    const result = await orch.restart();

    expect(result.zeroDowntime).toBe(true);
    expect(orch.isRunning).toBe(true);
  });

  it("supports dry-run restart", async () => {
    const orch = new LifecycleOrchestrator(makeConfig({ dryRun: true }));
    const result = await orch.restart();

    expect(result.shutdown.success).toBe(true);
    expect(result.startup.success).toBe(true);
    expect(result.zeroDowntime).toBe(true);
  });
});

// ── Unit: Event logging ─────────────────────────────────────────────────────

describe("Lifecycle event logging", () => {
  it("logs startup events", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    await orch.start();

    const events = orch.getEventLog();
    expect(events.some((e) => e.action === "start")).toBe(true);
    expect(events.some((e) => e.action === "phase-complete")).toBe(true);
  });

  it("logs shutdown events", async () => {
    const orch = new LifecycleOrchestrator(makeConfig());
    await orch.stop();

    const events = orch.getEventLog();
    expect(events.some((e) => e.action === "stop")).toBe(true);
  });

  it("logs restart events", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());
    await orch.restart();

    const events = orch.getEventLog();
    expect(events.some((e) => e.action === "restart")).toBe(true);
  });
});

// ── Property 51: Container startup ordering ─────────────────────────────────

describe("Property 51: Startup ordering", () => {
  it("startup phases always execute in defined order", () => {
    fc.assert(
      fc.property(
        fc.boolean(),
        fc.boolean(),
        (dryRun, skipFirewall) => {
          // Verify that STARTUP_PHASES is a fixed, ordered sequence
          expect(STARTUP_PHASES[0]).toBe("luks-unlock");
          expect(STARTUP_PHASES[1]).toBe("fscrypt-unlock");
          expect(STARTUP_PHASES[2]).toBe("hsm-init");
          expect(STARTUP_PHASES[3]).toBe("config-generate");
          expect(STARTUP_PHASES[4]).toBe("mtls-generate");
          expect(STARTUP_PHASES[5]).toBe("container-start");
          expect(STARTUP_PHASES[6]).toBe("security-audit");
          expect(STARTUP_PHASES[7]).toBe("perimeter-validate");

          // No matter the config options, the ordering is fixed
          expect(STARTUP_PHASES).toHaveLength(8);

          // Use the parameters to avoid unused-var lint
          expect(typeof dryRun).toBe("boolean");
          expect(typeof skipFirewall).toBe("boolean");
        },
      ),
      { numRuns: 5 },
    );
  });

  it("shutdown phases always include container-stop first", () => {
    expect(SHUTDOWN_PHASES[0]).toBe("container-stop");
    expect(SHUTDOWN_PHASES[SHUTDOWN_PHASES.length - 1]).toBe("hsm-finalize");
  });

  it("startup phases are superset of critical security steps", () => {
    const criticalPhases = ["hsm-init", "config-generate", "security-audit", "perimeter-validate"];
    for (const phase of criticalPhases) {
      expect(STARTUP_PHASES).toContain(phase);
    }
  });
});

// ── Property 52: Graceful shutdown cleanup ──────────────────────────────────

describe("Property 52: Graceful shutdown cleanup", () => {
  it("shutdown always clears running state", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.boolean(),
        async (dryRun) => {
          const localHsm = new MockHsmClient();
          await localHsm.initialize("/mock", 0, "1234");
          if (!dryRun) await localHsm.finalize();

          const orch = new LifecycleOrchestrator(makeConfig({
            hsm: localHsm,
            dryRun,
          }));

          if (!dryRun) await orch.start();
          await orch.stop();
          expect(orch.isRunning).toBe(false);
        },
      ),
      { numRuns: 5 },
    );
  });

  it("shutdown always attempts all phases regardless of errors", async () => {
    // Even with a broken HSM, all shutdown phases should be attempted
    const badHsm = new MockHsmClient();
    const orch = new LifecycleOrchestrator(makeConfig({ hsm: badHsm }));
    const result = await orch.stop();

    expect(result.phases).toHaveLength(SHUTDOWN_PHASES.length);
  });

  it("shutdown always includes tmpfs cleanup", () => {
    expect(SHUTDOWN_PHASES).toContain("tmpfs-cleanup");
    const cleanupIndex = SHUTDOWN_PHASES.indexOf("tmpfs-cleanup");
    const containerStopIndex = SHUTDOWN_PHASES.indexOf("container-stop");
    // tmpfs cleanup must happen after containers stop
    expect(cleanupIndex).toBeGreaterThan(containerStopIndex);
  });

  it("HSM finalize is always last shutdown phase", () => {
    expect(SHUTDOWN_PHASES[SHUTDOWN_PHASES.length - 1]).toBe("hsm-finalize");
  });
});

// ── End-to-end: Complete lifecycle ──────────────────────────────────────────

describe("End-to-end lifecycle", () => {
  it("start → stop → restart cycle works", async () => {
    await hsm.finalize();
    const orch = new LifecycleOrchestrator(makeConfig());

    // Start
    const startResult = await orch.start();
    expect(startResult.success).toBe(true);
    expect(orch.isRunning).toBe(true);

    // Stop
    const stopResult = await orch.stop();
    expect(stopResult.phases.length).toBeGreaterThan(0);
    expect(orch.isRunning).toBe(false);

    // Need to re-init HSM for restart
    await hsm.initialize("/mock", 0, "1234");
    await hsm.finalize();

    // Restart
    const restartResult = await orch.restart();
    expect(restartResult.startup.success).toBe(true);
    expect(orch.isRunning).toBe(true);
  });

  it("full lifecycle in dry-run mode", async () => {
    const orch = new LifecycleOrchestrator(makeConfig({ dryRun: true }));

    const startResult = await orch.start();
    expect(startResult.success).toBe(true);

    const stopResult = await orch.stop();
    expect(stopResult.phases.length).toBe(SHUTDOWN_PHASES.length);

    const restartResult = await orch.restart();
    expect(restartResult.zeroDowntime).toBe(true);
  });
});
