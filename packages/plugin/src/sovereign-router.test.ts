import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { SovereignRouter } from "./sovereign-router.js";
import type { RouterConfig, RoutingDecision } from "./sovereign-router.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<RouterConfig> = {}): RouterConfig {
  return {
    defaultMode: "auto",
    sovereignBackends: [
      { name: "ollama-local", url: "http://localhost:11434", model: "llama3:8b", available: true },
    ],
    cloudModels: ["claude-sonnet-4-20250514", "gpt-4o"],
    channelDefaults: {},
    ...overrides,
  };
}

// ── Unit: Mode management ───────────────────────────────────────────────────

describe("Mode management", () => {
  it("starts with default mode", () => {
    const router = new SovereignRouter(makeConfig({ defaultMode: "auto" }));
    const mode = router.getMode("session-1");
    expect(mode).toBe("auto");
  });

  it("sets sovereign mode", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("session-1", "sovereign");
    expect(router.getMode("session-1")).toBe("sovereign");
  });

  it("sets public mode", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("session-1", "public");
    expect(router.getMode("session-1")).toBe("public");
  });

  it("uses channel defaults", () => {
    const router = new SovereignRouter(makeConfig({
      channelDefaults: { "telegram": "sovereign" },
    }));
    const mode = router.getMode("session-1", "telegram");
    expect(mode).toBe("sovereign");
  });

  it("tracks session state", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("session-1", "sovereign", "user");
    const state = router.getSession("session-1");
    expect(state?.mode).toBe("sovereign");
    expect(state?.setBy).toBe("user");
  });
});

// ── Unit: Sovereign routing ─────────────────────────────────────────────────

describe("Sovereign routing", () => {
  it("routes to local backend", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("s1", "sovereign");
    const decision = router.route("s1", "claude-sonnet-4-20250514", "tr_1");
    expect(decision.backend).toBe("sovereign");
    expect(decision.model).toBe("llama3:8b");
  });

  it("refuses cloud even when no sovereign available", () => {
    const router = new SovereignRouter(makeConfig({
      sovereignBackends: [],
    }));
    router.setMode("s1", "sovereign");
    const decision = router.route("s1", "claude-sonnet-4-20250514", "tr_1");
    expect(decision.backend).toBe("sovereign");
    expect(decision.model).toBe("unavailable");
    expect(decision.reason).toContain("refusing cloud");
  });
});

// ── Unit: Public routing ────────────────────────────────────────────────────

describe("Public routing", () => {
  it("routes to cloud", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("s1", "public");
    const decision = router.route("s1", "claude-sonnet-4-20250514", "tr_1");
    expect(decision.backend).toBe("cloud");
    expect(decision.model).toBe("claude-sonnet-4-20250514");
  });

  it("falls back to sovereign when cloud unavailable", () => {
    const router = new SovereignRouter(makeConfig({
      cloudModels: [],
    }));
    router.setMode("s1", "public");
    const decision = router.route("s1", "anything", "tr_1");
    expect(decision.backend).toBe("sovereign");
    expect(decision.reason).toContain("fallback");
  });
});

// ── Unit: Auto routing ──────────────────────────────────────────────────────

describe("Auto routing", () => {
  it("prefers cloud when available", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("s1", "auto");
    const decision = router.route("s1", "claude-sonnet-4-20250514", "tr_1");
    expect(decision.backend).toBe("cloud");
  });

  it("falls back to sovereign when cloud unavailable", () => {
    const router = new SovereignRouter(makeConfig({
      cloudModels: [],
    }));
    router.setMode("s1", "auto");
    const decision = router.route("s1", "anything", "tr_1");
    expect(decision.backend).toBe("sovereign");
  });
});

// ── Unit: Decision logging ──────────────────────────────────────────────────

describe("Decision logging", () => {
  it("logs routing decisions", () => {
    const decisions: RoutingDecision[] = [];
    const router = new SovereignRouter(makeConfig({
      onDecision: (d) => decisions.push(d),
    }));

    router.route("s1", "claude-sonnet-4-20250514", "tr_1");
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.traceId).toBe("tr_1");
  });

  it("tracks request count per session", () => {
    const router = new SovereignRouter(makeConfig());
    router.route("s1", "model", "tr_1");
    router.route("s1", "model", "tr_2");
    router.route("s1", "model", "tr_3");

    const state = router.getSession("s1");
    expect(state?.requestCount).toBe(3);
  });

  it("logs mode changes and routing events", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("s1", "sovereign");
    router.route("s1", "model", "tr_1");

    const events = router.getEventLog();
    expect(events.some((e) => e.action === "mode-change")).toBe(true);
    expect(events.some((e) => e.action === "route")).toBe(true);
  });
});

// ── Unit: List sessions ─────────────────────────────────────────────────────

describe("List sessions", () => {
  it("lists all active sessions", () => {
    const router = new SovereignRouter(makeConfig());
    router.setMode("s1", "sovereign");
    router.setMode("s2", "public");
    router.setMode("s3", "auto");

    const sessions = router.listSessions();
    expect(sessions).toHaveLength(3);
  });
});

// ── Property 36: Sovereign never routes to cloud ────────────────────────────

describe("Property 36: Sovereign session routing", () => {
  it("sovereign mode never routes to cloud backend", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        fc.string({ minLength: 1, maxLength: 20 }),
        (sessionId, model, traceId) => {
          const router = new SovereignRouter(makeConfig());
          router.setMode(sessionId, "sovereign");
          const decision = router.route(sessionId, model, traceId);
          expect(decision.backend).toBe("sovereign");
          expect(decision.mode).toBe("sovereign");
        },
      ),
      { numRuns: 30 },
    );
  });

  it("sovereign mode never routes to cloud even with many backends", () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 3, maxLength: 15 }), { minLength: 1, maxLength: 5 }),
        (cloudModels) => {
          const router = new SovereignRouter(makeConfig({ cloudModels }));
          router.setMode("s1", "sovereign");
          const decision = router.route("s1", cloudModels[0]!, "tr_1");
          expect(decision.backend).toBe("sovereign");
        },
      ),
      { numRuns: 15 },
    );
  });
});

// ── Property 37: Public routes to cloud with fallback ───────────────────────

describe("Property 37: Public session routing", () => {
  it("public mode routes to cloud when available", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("claude-sonnet-4-20250514", "gpt-4o"),
        (model) => {
          const router = new SovereignRouter(makeConfig());
          router.setMode("s1", "public");
          const decision = router.route("s1", model, "tr_1");
          expect(decision.backend).toBe("cloud");
        },
      ),
      { numRuns: 10 },
    );
  });

  it("public mode falls back to sovereign when cloud empty", () => {
    const router = new SovereignRouter(makeConfig({ cloudModels: [] }));
    router.setMode("s1", "public");

    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 20 }),
        (model) => {
          const decision = router.route("s1", model, "tr_1");
          expect(decision.backend).toBe("sovereign");
        },
      ),
      { numRuns: 10 },
    );
  });
});

// ── Property 38: Session mode persistence ───────────────────────────────────

describe("Property 38: Session mode persistence", () => {
  it("mode persists across multiple requests", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("sovereign", "public", "auto") as fc.Arbitrary<"sovereign" | "public" | "auto">,
        fc.integer({ min: 1, max: 20 }),
        (mode, requestCount) => {
          const router = new SovereignRouter(makeConfig());
          router.setMode("persist-session", mode);

          for (let i = 0; i < requestCount; i++) {
            const currentMode = router.getMode("persist-session");
            expect(currentMode).toBe(mode);
          }
        },
      ),
      { numRuns: 15 },
    );
  });

  it("mode changes are reflected immediately", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.constantFrom("sovereign", "public", "auto") as fc.Arbitrary<"sovereign" | "public" | "auto">,
          { minLength: 2, maxLength: 5 },
        ),
        (modes) => {
          const router = new SovereignRouter(makeConfig());

          for (const mode of modes) {
            router.setMode("s1", mode);
            expect(router.getMode("s1")).toBe(mode);
          }
        },
      ),
      { numRuns: 10 },
    );
  });
});
