import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { BackendManager } from "./backend-manager.js";
import type {
  BackendConfig,
  BackendManagerConfig,
  BudgetConfig,
  RoutingResult,
} from "./backend-manager.js";
import { CredentialStore } from "./credential-store.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

const JETSON: BackendConfig = {
  name: "jetson-orin",
  type: "sovereign",
  url: "https://jetson.local:8443",
  model: "llama3:8b",
  credentialLabel: "jetson-api-key",
  tlsCertPin: true,
  priority: 1,
};

const REMOTE_GPU: BackendConfig = {
  name: "remote-gpu",
  type: "sovereign",
  url: "https://remote-gpu.wg:8443",
  model: "llama3:70b",
  credentialLabel: "remote-gpu-api-key",
  wireguard: true,
  priority: 2,
};

const ANTHROPIC: BackendConfig = {
  name: "anthropic",
  type: "cloud",
  url: "https://api.anthropic.com",
  model: "claude-sonnet-4-20250514",
  credentialLabel: "anthropic-api-key",
  priority: 1,
};

const OPENAI: BackendConfig = {
  name: "openai",
  type: "cloud",
  url: "https://api.openai.com",
  model: "gpt-4o",
  credentialLabel: "openai-api-key",
  priority: 2,
};

const DEFAULT_BUDGET: BudgetConfig = {
  monthlyBudgetUsd: 100,
  currentSpendUsd: 0,
  warnThreshold: 0.8,
  downgradeThreshold: 0.9,
  hardLimitThreshold: 1.0,
};

function makeConfig(overrides: Partial<BackendManagerConfig> = {}): BackendManagerConfig {
  return {
    backends: [JETSON, REMOTE_GPU, ANTHROPIC, OPENAI],
    budget: { ...DEFAULT_BUDGET },
    ...overrides,
  };
}

function makeCredentials(): CredentialStore {
  const store = new CredentialStore();
  store.load("jetson-api-key", "llm-api-key", "jetson-secret-123");
  store.load("remote-gpu-api-key", "llm-api-key", "remote-gpu-secret-456");
  store.load("anthropic-api-key", "llm-api-key", "sk-ant-test-key-xxxxx");
  store.load("openai-api-key", "llm-api-key", "sk-test-openai-key-yyyyy");
  return store;
}

// ── Unit: Sovereign routing ─────────────────────────────────────────────────

describe("Backend sovereign routing", () => {
  it("routes to highest-priority sovereign backend", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();
    const result = mgr.route({
      sessionId: "s1", requestedModel: "claude-sonnet-4-20250514", traceId: "tr_1", mode: "sovereign",
    }, creds);

    expect(result.backend.name).toBe("jetson-orin");
    expect(result.backend.type).toBe("sovereign");
    expect(result.model).toBe("llama3:8b");
  });

  it("never routes to cloud in sovereign mode", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();
    const result = mgr.route({
      sessionId: "s1", requestedModel: "claude-sonnet-4-20250514", traceId: "tr_1", mode: "sovereign",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
  });

  it("refuses cloud even when no sovereign backends healthy", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    // Mark all sovereign backends unhealthy
    mgr.reportHealth("jetson-orin", false, 0);
    mgr.reportHealth("jetson-orin", false, 0);
    mgr.reportHealth("jetson-orin", false, 0);
    mgr.reportHealth("remote-gpu", false, 0);
    mgr.reportHealth("remote-gpu", false, 0);
    mgr.reportHealth("remote-gpu", false, 0);

    const result = mgr.route({
      sessionId: "s1", requestedModel: "gpt-4o", traceId: "tr_1", mode: "sovereign",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
    expect(result.model).toBe("unavailable");
    expect(result.reason).toContain("refusing cloud");
  });

  it("refuses cloud when no sovereign backends configured", () => {
    const mgr = new BackendManager(makeConfig({
      backends: [ANTHROPIC, OPENAI],
    }));
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "gpt-4o", traceId: "tr_1", mode: "sovereign",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
    expect(result.model).toBe("unavailable");
  });

  it("injects API key from credential store", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "sovereign",
    }, creds);

    expect(result.authorization).toBe("jetson-secret-123");
  });
});

// ── Unit: Public routing ────────────────────────────────────────────────────

describe("Backend public routing", () => {
  it("routes to cloud in public mode", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "claude-sonnet-4-20250514", traceId: "tr_1", mode: "public",
    }, creds);

    expect(result.backend.type).toBe("cloud");
    expect(result.backend.name).toBe("anthropic");
  });

  it("falls back to sovereign when cloud unhealthy", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    // Mark all cloud backends unhealthy
    for (let i = 0; i < 3; i++) {
      mgr.reportHealth("anthropic", false, 0);
      mgr.reportHealth("openai", false, 0);
    }

    const result = mgr.route({
      sessionId: "s1", requestedModel: "claude-sonnet-4-20250514", traceId: "tr_1", mode: "public",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
    expect(result.reason).toContain("sovereign fallback");
  });

  it("falls back to sovereign when no cloud backends configured", () => {
    const mgr = new BackendManager(makeConfig({
      backends: [JETSON, REMOTE_GPU],
    }));
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "claude-sonnet-4-20250514", traceId: "tr_1", mode: "public",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
    expect(result.reason).toContain("fallback");
  });

  it("injects cloud API key", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "public",
    }, creds);

    expect(result.authorization).toBe("sk-ant-test-key-xxxxx");
  });
});

// ── Unit: Auto routing ──────────────────────────────────────────────────────

describe("Backend auto routing", () => {
  it("prefers cloud when available", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "auto",
    }, creds);

    expect(result.backend.type).toBe("cloud");
  });

  it("falls back to sovereign when cloud unhealthy", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    for (let i = 0; i < 3; i++) {
      mgr.reportHealth("anthropic", false, 0);
      mgr.reportHealth("openai", false, 0);
    }

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "auto",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
  });
});

// ── Unit: Budget-aware routing ──────────────────────────────────────────────

describe("Budget-aware routing", () => {
  it("allows requests within budget", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 50 },
    }));

    const check = mgr.checkBudget(1);
    expect(check.action).toBe("allow");
    expect(check.spendRatio).toBeCloseTo(0.51);
  });

  it("warns at 80% threshold", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 80 },
    }));

    const check = mgr.checkBudget(0);
    expect(check.action).toBe("warn");
  });

  it("downgrades at 90% threshold", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 90 },
    }));

    const check = mgr.checkBudget(0);
    expect(check.action).toBe("downgrade");
  });

  it("blocks at 100% threshold", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 100 },
    }));

    const check = mgr.checkBudget(0);
    expect(check.action).toBe("block");
  });

  it("blocks cloud when budget exceeded in public mode", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 100 },
    }));
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "public",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
    expect(result.reason).toContain("budget");
  });

  it("blocks cloud when budget exceeded in auto mode", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 100 },
    }));
    const creds = makeCredentials();

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "auto",
    }, creds);

    expect(result.backend.type).toBe("sovereign");
    expect(result.reason).toContain("budget");
  });

  it("allows request when no budget configured", () => {
    const mgr = new BackendManager(makeConfig({ budget: undefined }));

    const check = mgr.checkBudget(1000);
    expect(check.action).toBe("allow");
  });

  it("tracks spend updates", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 0 },
    }));

    mgr.updateSpend(50);
    expect(mgr.checkBudget(0).spendRatio).toBeCloseTo(0.5);

    mgr.updateSpend(35);
    expect(mgr.checkBudget(0).action).toBe("warn");
  });

  it("considers estimated cost in budget check", () => {
    const mgr = new BackendManager(makeConfig({
      budget: { ...DEFAULT_BUDGET, currentSpendUsd: 79 },
    }));

    // Without estimated cost: under warn threshold
    expect(mgr.checkBudget(0).action).toBe("allow");
    // With estimated cost: above warn threshold
    expect(mgr.checkBudget(2).action).toBe("warn");
  });
});

// ── Unit: Health checks ─────────────────────────────────────────────────────

describe("Backend health checks", () => {
  it("marks backend unhealthy after 3 consecutive failures", () => {
    const mgr = new BackendManager(makeConfig());

    expect(mgr.isHealthy("jetson-orin")).toBe(true);

    mgr.reportHealth("jetson-orin", false, 100);
    mgr.reportHealth("jetson-orin", false, 100);
    expect(mgr.isHealthy("jetson-orin")).toBe(true); // 2 failures, still healthy

    mgr.reportHealth("jetson-orin", false, 100);
    expect(mgr.isHealthy("jetson-orin")).toBe(false); // 3 failures, unhealthy
  });

  it("recovers health after successful check", () => {
    const mgr = new BackendManager(makeConfig());

    mgr.reportHealth("jetson-orin", false, 100);
    mgr.reportHealth("jetson-orin", false, 100);
    mgr.reportHealth("jetson-orin", false, 100);
    expect(mgr.isHealthy("jetson-orin")).toBe(false);

    mgr.reportHealth("jetson-orin", true, 50);
    expect(mgr.isHealthy("jetson-orin")).toBe(true);
  });

  it("tracks latency and request counts", () => {
    const mgr = new BackendManager(makeConfig());

    mgr.reportHealth("anthropic", true, 150);
    mgr.reportHealth("anthropic", true, 200);

    const health = mgr.getHealth("anthropic");
    expect(health?.lastLatencyMs).toBe(200);
    expect(health?.totalRequests).toBe(2);
    expect(health?.totalFailures).toBe(0);
  });

  it("tracks total failures", () => {
    const mgr = new BackendManager(makeConfig());

    mgr.reportHealth("anthropic", true, 100);
    mgr.reportHealth("anthropic", false, 500);
    mgr.reportHealth("anthropic", true, 100);
    mgr.reportHealth("anthropic", false, 500);

    const health = mgr.getHealth("anthropic");
    expect(health?.totalFailures).toBe(2);
    expect(health?.consecutiveFailures).toBe(1);
  });

  it("returns all backend health", () => {
    const mgr = new BackendManager(makeConfig());
    const all = mgr.getAllHealth();
    expect(all).toHaveLength(4);
  });
});

// ── Unit: Failover ──────────────────────────────────────────────────────────

describe("Backend failover", () => {
  it("fails over to second sovereign backend", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    // Make jetson unhealthy
    for (let i = 0; i < 3; i++) mgr.reportHealth("jetson-orin", false, 0);

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "sovereign",
    }, creds);

    expect(result.backend.name).toBe("remote-gpu");
  });

  it("fails over to second cloud backend", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    // Make anthropic unhealthy
    for (let i = 0; i < 3; i++) mgr.reportHealth("anthropic", false, 0);

    const result = mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "public",
    }, creds);

    expect(result.backend.name).toBe("openai");
    expect(result.backend.type).toBe("cloud");
  });

  it("logs failover events", () => {
    const mgr = new BackendManager(makeConfig());
    const creds = makeCredentials();

    // Make all cloud unhealthy
    for (let i = 0; i < 3; i++) {
      mgr.reportHealth("anthropic", false, 0);
      mgr.reportHealth("openai", false, 0);
    }

    mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "public",
    }, creds);

    const events = mgr.getEventLog();
    expect(events.some((e) => e.action === "failover")).toBe(true);
  });
});

// ── Unit: Event logging ─────────────────────────────────────────────────────

describe("Backend event logging", () => {
  it("logs routing decisions", () => {
    const results: RoutingResult[] = [];
    const mgr = new BackendManager(makeConfig({
      onRoute: (r) => results.push(r),
    }));
    const creds = makeCredentials();

    mgr.route({
      sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode: "public",
    }, creds);

    expect(results).toHaveLength(1);
    expect(results[0]!.traceId).toBe("tr_1");
  });

  it("logs health check events", () => {
    const mgr = new BackendManager(makeConfig());
    mgr.reportHealth("jetson-orin", true, 50);

    const events = mgr.getEventLog();
    expect(events.some((e) => e.action === "health-check")).toBe(true);
  });
});

// ── Property 39: Sovereign never routes to cloud ────────────────────────────

describe("Property 39: Sovereign backend routing", () => {
  it("sovereign mode never routes to cloud backend", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        (sessionId, model, traceId) => {
          const mgr = new BackendManager(makeConfig());
          const creds = makeCredentials();
          const result = mgr.route({
            sessionId, requestedModel: model, traceId, mode: "sovereign",
          }, creds);
          expect(result.backend.type).toBe("sovereign");
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 40: Budget hard limit blocks cloud ─────────────────────────────

describe("Property 40: Budget enforcement", () => {
  it("budget at or above hard limit always blocks cloud", () => {
    fc.assert(
      fc.property(
        fc.double({ min: 100, max: 10000, noNaN: true }),
        fc.constantFrom("public", "auto") as fc.Arbitrary<"public" | "auto">,
        (spend, mode) => {
          const mgr = new BackendManager(makeConfig({
            budget: { ...DEFAULT_BUDGET, currentSpendUsd: spend },
          }));
          const creds = makeCredentials();
          const result = mgr.route({
            sessionId: "s1", requestedModel: "model", traceId: "tr_1", mode,
          }, creds);

          // When over budget: should be sovereign (fallback) not cloud
          expect(result.backend.type).toBe("sovereign");
        },
      ),
      { numRuns: 20 },
    );
  });

  it("budget thresholds are monotonic: allow < warn < downgrade < block", () => {
    fc.assert(
      fc.property(
        fc.double({ min: 0, max: 200, noNaN: true }),
        (spend) => {
          const mgr = new BackendManager(makeConfig({
            budget: { ...DEFAULT_BUDGET, currentSpendUsd: spend },
          }));
          const check = mgr.checkBudget(0);
          const ratio = spend / 100; // budget is 100

          if (ratio < 0.8) expect(check.action).toBe("allow");
          else if (ratio < 0.9) expect(check.action).toBe("warn");
          else if (ratio < 1.0) expect(check.action).toBe("downgrade");
          else expect(check.action).toBe("block");
        },
      ),
      { numRuns: 40 },
    );
  });
});

// ── Property 41: Health check consistency ───────────────────────────────────

describe("Property 41: Health check consistency", () => {
  it("backend becomes unhealthy after exactly 3 consecutive failures", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("jetson-orin", "remote-gpu", "anthropic", "openai"),
        fc.array(fc.boolean(), { minLength: 1, maxLength: 10 }),
        (backend, results) => {
          const mgr = new BackendManager(makeConfig());

          let consecutiveFailures = 0;
          for (const success of results) {
            mgr.reportHealth(backend, success, 100);
            if (success) {
              consecutiveFailures = 0;
            } else {
              consecutiveFailures++;
            }

            if (consecutiveFailures >= 3) {
              expect(mgr.isHealthy(backend)).toBe(false);
            } else {
              expect(mgr.isHealthy(backend)).toBe(true);
            }
          }
        },
      ),
      { numRuns: 30 },
    );
  });
});
