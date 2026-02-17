// ── Hook Registry ───────────────────────────────────────────────────────────
// Manages plugin hooks for the chat framework integration.
// Hooks intercept tool calls, messages, LLM requests, and routing decisions.

import {
  ToolValidator,
  DEFAULT_DANGEROUS_PATTERNS,
  type ToolCallRequest,
} from "./tool-validator.js";
import { CredentialRedactor } from "./credential-redactor.js";
import { SovereignRouter, type RouterConfig } from "./sovereign-router.js";

// ── Types ───────────────────────────────────────────────────────────────────

export type HookName =
  | "before_tool_call"
  | "after_tool_call"
  | "tool_result_persist"
  | "before_message_write"
  | "message_sending"
  | "before_model_resolve"
  | "llm_input"
  | "llm_output"
  | "registerCommand";

export type HookPriority = "critical" | "high" | "normal" | "low";

export interface HookHandler {
  name: string;
  hookName: HookName;
  priority: HookPriority;
  handler: (context: HookContext) => Promise<HookResult>;
  enabled: boolean;
}

export interface HookContext {
  hookName: HookName;
  timestamp: string;
  traceId: string;
  data: Record<string, unknown>;
}

export type HookAction = "allow" | "deny" | "modify" | "log";

export interface HookResult {
  action: HookAction;
  modified?: Record<string, unknown>;
  reason?: string;
  logs?: string[];
}

export interface HookRegistration {
  name: string;
  hookName: HookName;
  priority: HookPriority;
  handler: (context: HookContext) => Promise<HookResult>;
}

export interface HookEvent {
  hookName: HookName;
  handlerName: string;
  action: HookAction;
  durationMs: number;
  success: boolean;
  error?: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Priority ordering (lower = runs first). */
const PRIORITY_ORDER: Record<HookPriority, number> = {
  critical: 0,
  high: 1,
  normal: 2,
  low: 3,
};

/** All hooks that lobsec registers. */
export const LOBSEC_HOOKS: HookName[] = [
  "before_tool_call",
  "after_tool_call",
  "tool_result_persist",
  "before_message_write",
  "message_sending",
  "before_model_resolve",
  "llm_input",
  "llm_output",
  "registerCommand",
];

// ── Hook Registry ───────────────────────────────────────────────────────────

export class HookRegistry {
  private handlers = new Map<HookName, HookHandler[]>();
  private eventLog: HookEvent[] = [];
  private onEvent?: (event: HookEvent) => void;

  constructor(onEvent?: (event: HookEvent) => void) {
    this.onEvent = onEvent;
  }

  /** Register a hook handler. */
  register(reg: HookRegistration): void {
    const handler: HookHandler = {
      ...reg,
      enabled: true,
    };

    const existing = this.handlers.get(reg.hookName) ?? [];
    existing.push(handler);

    // Sort by priority
    existing.sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority]);
    this.handlers.set(reg.hookName, existing);
  }

  /** Unregister a hook handler by name. */
  unregister(hookName: HookName, handlerName: string): boolean {
    const existing = this.handlers.get(hookName);
    if (!existing) return false;

    const idx = existing.findIndex((h) => h.name === handlerName);
    if (idx === -1) return false;

    existing.splice(idx, 1);
    return true;
  }

  /** Enable/disable a handler. */
  setEnabled(hookName: HookName, handlerName: string, enabled: boolean): boolean {
    const existing = this.handlers.get(hookName);
    if (!existing) return false;

    const handler = existing.find((h) => h.name === handlerName);
    if (!handler) return false;

    handler.enabled = enabled;
    return true;
  }

  /** Execute all handlers for a hook, in priority order. */
  async execute(context: HookContext): Promise<HookResult[]> {
    const handlers = this.handlers.get(context.hookName) ?? [];
    const results: HookResult[] = [];

    for (const handler of handlers) {
      if (!handler.enabled) continue;

      const start = Date.now();
      try {
        const result = await handler.handler(context);
        const durationMs = Date.now() - start;

        results.push(result);

        const event: HookEvent = {
          hookName: context.hookName,
          handlerName: handler.name,
          action: result.action,
          durationMs,
          success: true,
        };
        this.eventLog.push(event);
        this.onEvent?.(event);

        // If any critical handler denies, stop execution
        if (result.action === "deny" && handler.priority === "critical") {
          break;
        }
      } catch (err) {
        const durationMs = Date.now() - start;
        const event: HookEvent = {
          hookName: context.hookName,
          handlerName: handler.name,
          action: "log",
          durationMs,
          success: false,
          error: (err as Error).message,
        };
        this.eventLog.push(event);
        this.onEvent?.(event);

        // Non-blocking: hook errors don't crash the system
        results.push({
          action: "log",
          reason: `Hook error: ${(err as Error).message}`,
        });
      }
    }

    return results;
  }

  /** Get all registered handlers for a hook. */
  getHandlers(hookName: HookName): HookHandler[] {
    return [...(this.handlers.get(hookName) ?? [])];
  }

  /** Get count of handlers per hook. */
  getRegistrationCount(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const [name, handlers] of this.handlers) {
      counts[name] = handlers.length;
    }
    return counts;
  }

  /** List all registered hook names. */
  getRegisteredHooks(): HookName[] {
    return [...this.handlers.keys()];
  }

  /** Get event log. */
  getEventLog(): HookEvent[] {
    return [...this.eventLog];
  }

  /** Clear event log. */
  clearEventLog(): void {
    this.eventLog = [];
  }
}

// ── Default Hook Registrations ──────────────────────────────────────────────

export interface DefaultRegistryConfig {
  /** Workspace root for path containment checks. */
  workspaceRoot: string;
  /** Sovereign router configuration. */
  router: RouterConfig;
  /** Additional tools to deny beyond the required list. */
  additionalDenyList?: string[];
  /** Hook event callback. */
  onEvent?: (event: HookEvent) => void;
}

/** Create a fully registered HookRegistry with all lobsec hooks. */
export function createDefaultRegistry(config: DefaultRegistryConfig): HookRegistry {
  const registry = new HookRegistry(config.onEvent);

  const toolValidator = new ToolValidator({
    workspaceRoot: config.workspaceRoot,
    additionalDenyList: config.additionalDenyList ?? [],
    dangerousPatterns: DEFAULT_DANGEROUS_PATTERNS,
  });

  const redactor = new CredentialRedactor();
  const router = new SovereignRouter(config.router);

  // ── before_tool_call: validate tool calls ────────────────────────────────

  registry.register({
    name: "lobsec-tool-validator",
    hookName: "before_tool_call",
    priority: "critical",
    handler: async (ctx) => {
      const tool = ctx.data["tool"] as string | undefined;
      if (!tool) return { action: "allow" };

      const request: ToolCallRequest = {
        tool,
        args: (ctx.data["args"] as Record<string, unknown>) ?? {},
        rawCommand: ctx.data["rawCommand"] as string | undefined,
        commandParts: ctx.data["commandParts"] as string[] | undefined,
        filePath: ctx.data["filePath"] as string | undefined,
        traceId: ctx.traceId,
      };

      const result = toolValidator.validate(request);
      if (result.action === "deny") {
        return {
          action: "deny",
          reason: result.reasons.join("; "),
          logs: [`tool denied: ${tool} — ${result.reasons.join("; ")}`],
        };
      }
      return { action: "allow", reason: `tool ${tool} passed validation` };
    },
  });

  // ── after_tool_call: audit log ───────────────────────────────────────────

  registry.register({
    name: "lobsec-tool-logger",
    hookName: "after_tool_call",
    priority: "normal",
    handler: async (ctx) => {
      return { action: "log", logs: [`tool call completed: ${ctx.data["tool"]}`] };
    },
  });

  // ── tool_result_persist: redact credentials from tool results ────────────

  registry.register({
    name: "lobsec-result-redactor",
    hookName: "tool_result_persist",
    priority: "high",
    handler: async (ctx) => {
      const content = ctx.data["content"];
      if (!content || typeof content !== "string") return { action: "allow" };

      const result = redactor.redact(content, ctx.traceId);
      if (result.redactionCount > 0) {
        return {
          action: "modify",
          modified: { content: result.redacted },
          reason: `redacted ${result.redactionCount} sensitive pattern(s): ${result.redactedPatterns.join(", ")}`,
          logs: [`result redacted: ${result.redactedPatterns.join(", ")}`],
        };
      }
      return { action: "allow" };
    },
  });

  // ── before_message_write: redact credentials from persisted messages ─────

  registry.register({
    name: "lobsec-message-redactor",
    hookName: "before_message_write",
    priority: "high",
    handler: async (ctx) => {
      const text = ctx.data["text"];
      if (!text || typeof text !== "string") return { action: "allow" };

      const result = redactor.redact(text, ctx.traceId);
      if (result.redactionCount > 0) {
        return {
          action: "modify",
          modified: { text: result.redacted },
          reason: `redacted ${result.redactionCount} sensitive pattern(s)`,
          logs: [`message redacted: ${result.redactedPatterns.join(", ")}`],
        };
      }
      return { action: "allow" };
    },
  });

  // ── message_sending: block outbound credential leaks ─────────────────────

  registry.register({
    name: "lobsec-outbound-scanner",
    hookName: "message_sending",
    priority: "critical",
    handler: async (ctx) => {
      const text = ctx.data["text"] as string | undefined;
      if (!text) return { action: "allow" };

      if (redactor.containsSensitive(text)) {
        const result = redactor.redact(text, ctx.traceId);
        return {
          action: "deny",
          reason: `blocked outbound message containing: ${result.redactedPatterns.join(", ")}`,
          logs: [`BLOCKED outbound credential leak: ${result.redactedPatterns.join(", ")}`],
        };
      }
      return { action: "allow" };
    },
  });

  // ── before_model_resolve: sovereign/public routing ───────────────────────

  registry.register({
    name: "lobsec-model-router",
    hookName: "before_model_resolve",
    priority: "critical",
    handler: async (ctx) => {
      const sessionId = ctx.data["sessionId"] as string | undefined;
      const model = ctx.data["model"] as string | undefined;
      const channel = ctx.data["channel"] as string | undefined;
      if (!sessionId || !model) return { action: "allow" };

      const decision = router.route(sessionId, model, ctx.traceId, channel);
      if (decision.model === "unavailable") {
        return {
          action: "deny",
          reason: decision.reason,
          logs: [`model routing failed: ${decision.reason}`],
        };
      }
      return {
        action: "modify",
        modified: { model: decision.model, backend: decision.backend },
        reason: decision.reason,
        logs: [`routed to ${decision.backend}:${decision.model}`],
      };
    },
  });

  // ── llm_input: audit log ─────────────────────────────────────────────────

  registry.register({
    name: "lobsec-llm-input-logger",
    hookName: "llm_input",
    priority: "normal",
    handler: async (ctx) => {
      const model = ctx.data["model"] as string ?? "unknown";
      const tokenEstimate = ctx.data["tokenEstimate"] as number ?? 0;
      return {
        action: "log",
        logs: [`llm input: model=${model} tokens~${tokenEstimate}`],
      };
    },
  });

  // ── llm_output: redact and audit ─────────────────────────────────────────

  registry.register({
    name: "lobsec-llm-output-logger",
    hookName: "llm_output",
    priority: "normal",
    handler: async (ctx) => {
      const content = ctx.data["content"] as string | undefined;
      const logs = ["llm output logged"];

      if (content && redactor.containsSensitive(content)) {
        const result = redactor.redact(content, ctx.traceId);
        logs.push(`WARNING: LLM output contained sensitive data: ${result.redactedPatterns.join(", ")}`);
        return {
          action: "modify",
          modified: { content: result.redacted },
          reason: `redacted ${result.redactionCount} pattern(s) from LLM output`,
          logs,
        };
      }
      return { action: "log", logs };
    },
  });

  return registry;
}
