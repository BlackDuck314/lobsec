import { describe, it, expect, beforeEach } from "vitest";
import {
  HookRegistry,
  createDefaultRegistry,
  LOBSEC_HOOKS,
} from "./hook-registry.js";
import type {
  HookContext,
  HookEvent,
  HookName,
  DefaultRegistryConfig,
} from "./hook-registry.js";

const TEST_REGISTRY_CONFIG: DefaultRegistryConfig = {
  workspaceRoot: "/tmp/test-workspace",
  router: {
    defaultMode: "sovereign",
    sovereignBackends: [{ name: "test", url: "http://localhost:11434", model: "qwen2.5:32b", available: true }],
    cloudModels: [],
    channelDefaults: {},
  },
};

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeContext(hookName: HookName, data: Record<string, unknown> = {}): HookContext {
  return {
    hookName,
    timestamp: new Date().toISOString(),
    traceId: "tr_test123",
    data,
  };
}

// ── Unit: Registration ──────────────────────────────────────────────────────

describe("Hook registration", () => {
  let registry: HookRegistry;

  beforeEach(() => {
    registry = new HookRegistry();
  });

  it("registers a handler", () => {
    registry.register({
      name: "test-handler",
      hookName: "before_tool_call",
      priority: "normal",
      handler: async () => ({ action: "allow" }),
    });

    const handlers = registry.getHandlers("before_tool_call");
    expect(handlers).toHaveLength(1);
    expect(handlers[0]!.name).toBe("test-handler");
  });

  it("sorts handlers by priority", () => {
    registry.register({
      name: "low-handler",
      hookName: "before_tool_call",
      priority: "low",
      handler: async () => ({ action: "allow" }),
    });
    registry.register({
      name: "critical-handler",
      hookName: "before_tool_call",
      priority: "critical",
      handler: async () => ({ action: "allow" }),
    });
    registry.register({
      name: "high-handler",
      hookName: "before_tool_call",
      priority: "high",
      handler: async () => ({ action: "allow" }),
    });

    const handlers = registry.getHandlers("before_tool_call");
    expect(handlers[0]!.name).toBe("critical-handler");
    expect(handlers[1]!.name).toBe("high-handler");
    expect(handlers[2]!.name).toBe("low-handler");
  });

  it("unregisters a handler", () => {
    registry.register({
      name: "to-remove",
      hookName: "after_tool_call",
      priority: "normal",
      handler: async () => ({ action: "log" }),
    });

    expect(registry.unregister("after_tool_call", "to-remove")).toBe(true);
    expect(registry.getHandlers("after_tool_call")).toHaveLength(0);
  });

  it("returns false when unregistering unknown handler", () => {
    expect(registry.unregister("after_tool_call", "nonexistent")).toBe(false);
  });

  it("enables/disables a handler", () => {
    registry.register({
      name: "toggle-handler",
      hookName: "llm_input",
      priority: "normal",
      handler: async () => ({ action: "log" }),
    });

    registry.setEnabled("llm_input", "toggle-handler", false);
    expect(registry.getHandlers("llm_input")[0]!.enabled).toBe(false);

    registry.setEnabled("llm_input", "toggle-handler", true);
    expect(registry.getHandlers("llm_input")[0]!.enabled).toBe(true);
  });
});

// ── Unit: Execution ─────────────────────────────────────────────────────────

describe("Hook execution", () => {
  let registry: HookRegistry;

  beforeEach(() => {
    registry = new HookRegistry();
  });

  it("executes all handlers in order", async () => {
    const order: string[] = [];

    registry.register({
      name: "first",
      hookName: "before_tool_call",
      priority: "critical",
      handler: async () => {
        order.push("first");
        return { action: "allow" };
      },
    });

    registry.register({
      name: "second",
      hookName: "before_tool_call",
      priority: "normal",
      handler: async () => {
        order.push("second");
        return { action: "allow" };
      },
    });

    await registry.execute(makeContext("before_tool_call"));
    expect(order).toEqual(["first", "second"]);
  });

  it("skips disabled handlers", async () => {
    let called = false;
    registry.register({
      name: "disabled-handler",
      hookName: "llm_input",
      priority: "normal",
      handler: async () => {
        called = true;
        return { action: "log" };
      },
    });

    registry.setEnabled("llm_input", "disabled-handler", false);
    await registry.execute(makeContext("llm_input"));
    expect(called).toBe(false);
  });

  it("stops execution on critical deny", async () => {
    const order: string[] = [];

    registry.register({
      name: "denier",
      hookName: "before_tool_call",
      priority: "critical",
      handler: async () => {
        order.push("denier");
        return { action: "deny", reason: "blocked" };
      },
    });

    registry.register({
      name: "after-deny",
      hookName: "before_tool_call",
      priority: "normal",
      handler: async () => {
        order.push("after-deny");
        return { action: "allow" };
      },
    });

    const results = await registry.execute(makeContext("before_tool_call"));
    expect(order).toEqual(["denier"]);
    expect(results).toHaveLength(1);
    expect(results[0]!.action).toBe("deny");
  });

  it("handles errors without crashing", async () => {
    registry.register({
      name: "error-handler",
      hookName: "after_tool_call",
      priority: "normal",
      handler: async () => {
        throw new Error("handler crashed");
      },
    });

    const results = await registry.execute(makeContext("after_tool_call"));
    expect(results).toHaveLength(1);
    expect(results[0]!.action).toBe("log");
    expect(results[0]!.reason).toContain("handler crashed");
  });

  it("returns empty array for unregistered hook", async () => {
    const results = await registry.execute(makeContext("llm_output"));
    expect(results).toEqual([]);
  });
});

// ── Unit: Event logging ─────────────────────────────────────────────────────

describe("Hook event logging", () => {
  it("logs all hook executions", async () => {
    const events: HookEvent[] = [];
    const registry = new HookRegistry((e) => events.push(e));

    registry.register({
      name: "logged-handler",
      hookName: "before_tool_call",
      priority: "normal",
      handler: async () => ({ action: "allow" }),
    });

    await registry.execute(makeContext("before_tool_call"));

    expect(events).toHaveLength(1);
    expect(events[0]!.hookName).toBe("before_tool_call");
    expect(events[0]!.handlerName).toBe("logged-handler");
    expect(events[0]!.success).toBe(true);
  });

  it("logs errors with success=false", async () => {
    const events: HookEvent[] = [];
    const registry = new HookRegistry((e) => events.push(e));

    registry.register({
      name: "failing-handler",
      hookName: "llm_input",
      priority: "normal",
      handler: async () => {
        throw new Error("boom");
      },
    });

    await registry.execute(makeContext("llm_input"));

    expect(events[0]!.success).toBe(false);
    expect(events[0]!.error).toBe("boom");
  });

  it("tracks duration", async () => {
    const registry = new HookRegistry();

    registry.register({
      name: "timed-handler",
      hookName: "llm_output",
      priority: "normal",
      handler: async () => ({ action: "log" }),
    });

    await registry.execute(makeContext("llm_output"));
    const log = registry.getEventLog();
    expect(log[0]!.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// ── Unit: Default registry ──────────────────────────────────────────────────

describe("Default registry", () => {
  it("registers all lobsec hooks", () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);
    const registered = registry.getRegisteredHooks();

    // Should have handlers for most hooks (except registerCommand which has no default handler)
    const expectedHooks: HookName[] = [
      "before_tool_call",
      "after_tool_call",
      "tool_result_persist",
      "before_message_write",
      "message_sending",
      "before_model_resolve",
      "llm_input",
      "llm_output",
    ];

    for (const hook of expectedHooks) {
      expect(registered).toContain(hook);
    }
  });

  it("all default handlers allow by default", async () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);

    for (const hookName of registry.getRegisteredHooks()) {
      const results = await registry.execute(makeContext(hookName));
      // All should allow or log (no denies for default config)
      for (const result of results) {
        expect(["allow", "log"]).toContain(result.action);
      }
    }
  });

  it("returns registration counts", () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);
    const counts = registry.getRegistrationCount();
    expect(Object.keys(counts).length).toBeGreaterThan(0);
  });
});

// ── Integration: Wired handlers ────────────────────────────────────────────

describe("Wired handlers", () => {
  it("tool validator denies dangerous commands", async () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);
    const ctx = makeContext("before_tool_call", {
      tool: "exec",
      rawCommand: "rm -rf /",
      args: {},
    });

    const results = await registry.execute(ctx);
    expect(results[0]!.action).toBe("deny");
    expect(results[0]!.reason).toContain("Dangerous command pattern");
  });

  it("result redactor catches API keys in tool output", async () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);
    const ctx = makeContext("tool_result_persist", {
      content: "Found key: sk-ant-api03-abcdefghijklmnopqrstuvwx in config",
    });

    const results = await registry.execute(ctx);
    const redactorResult = results.find((r) => r.action === "modify");
    expect(redactorResult).toBeDefined();
    expect(redactorResult!.modified!["content"]).toContain("[ANTHROPIC-KEY-REDACTED]");
  });

  it("outbound scanner blocks credential leaks", async () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);
    const ctx = makeContext("message_sending", {
      text: "Here is your key: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    });

    const results = await registry.execute(ctx);
    expect(results[0]!.action).toBe("deny");
    expect(results[0]!.reason).toContain("github-pat");
  });

  it("outbound scanner allows clean messages", async () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);
    const ctx = makeContext("message_sending", {
      text: "Hello, how can I help you today?",
    });

    const results = await registry.execute(ctx);
    expect(results[0]!.action).toBe("allow");
  });

  it("message redactor scrubs PII before persistence", async () => {
    const registry = createDefaultRegistry(TEST_REGISTRY_CONFIG);
    const ctx = makeContext("before_message_write", {
      text: "Contact me at user@example.com or 192.168.1.100",
    });

    const results = await registry.execute(ctx);
    const redactorResult = results.find((r) => r.action === "modify");
    expect(redactorResult).toBeDefined();
    expect(redactorResult!.modified!["text"]).toContain("[EMAIL-REDACTED]");
    expect(redactorResult!.modified!["text"]).toContain("[IP-REDACTED]");
  });
});

// ── Unit: LOBSEC_HOOKS constant ─────────────────────────────────────────────

describe("LOBSEC_HOOKS", () => {
  it("contains all 9 hook names", () => {
    expect(LOBSEC_HOOKS).toHaveLength(9);
  });

  it("includes critical security hooks", () => {
    expect(LOBSEC_HOOKS).toContain("before_tool_call");
    expect(LOBSEC_HOOKS).toContain("message_sending");
    expect(LOBSEC_HOOKS).toContain("before_model_resolve");
  });
});
