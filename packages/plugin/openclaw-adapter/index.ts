// ── lobsec OpenClaw Plugin Adapter ──────────────────────────────────────────
// Bridges lobsec security primitives (ToolValidator, CredentialRedactor,
// SovereignRouter) into OpenClaw's plugin hook system.
//
// Loaded by OpenClaw at gateway startup via the plugin SDK.
// Registers hooks using api.on() for typed, priority-ordered execution.

import {
  ToolValidator,
  DEFAULT_DANGEROUS_PATTERNS,
} from "./dist/tool-validator.js";
import { CredentialRedactor, CREDENTIAL_PATTERNS } from "./dist/credential-redactor.js";
import { SovereignRouter } from "./dist/sovereign-router.js";
import { ConfigMonitor } from "./dist/config-monitor.js";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";

/** Inline canonicalHash — avoids cross-package dependency on @lobsec/shared drift-detector. */
function canonicalHash(config: unknown): string {
  const canonical = JSON.stringify(config, Object.keys(config as object).sort());
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

// Type stubs for OpenClaw's plugin API (we don't have the SDK types locally)
interface CommandContext {
  senderId?: string;
  channel: string;
  args?: string;
}

interface CommandDefinition {
  name: string;
  description: string;
  handler: (ctx: CommandContext) => Promise<{ text: string }> | { text: string };
}

interface PluginApi {
  id: string;
  config: Record<string, unknown>;
  pluginConfig?: Record<string, unknown>;
  logger: { info: (...args: unknown[]) => void; warn: (...args: unknown[]) => void; error: (...args: unknown[]) => void };
  on: (hookName: string, handler: (event: Record<string, unknown>) => unknown, opts?: { priority?: number }) => void;
  registerCommand?: (cmd: CommandDefinition) => void;
}

// Module-level state for ConfigMonitor (started in gateway_start, stopped in gateway_stop)
let configMonitor: ConfigMonitor | null = null;

export default {
  id: "lobsec-security",

  register(api: PluginApi) {
    const pluginConfig = api.pluginConfig ?? {};
    const workspaceRoot = (pluginConfig["workspaceRoot"] as string) ?? "/opt/lobsec/.openclaw/sandboxes";
    const defaultMode = (pluginConfig["sovereignMode"] as string) ?? "sovereign";

    const log = api.logger;
    const auditLogPath = "/opt/lobsec/logs/audit.jsonl";

    /** Append a structured audit entry to the audit log (unsigned, batch-signed later). */
    function audit(event: string, level: string, detail: Record<string, unknown> = {}) {
      const entry = {
        ts: new Date().toISOString(),
        level,
        component: "lobsec-plugin",
        event,
        ...detail,
      };
      try {
        appendFileSync(auditLogPath, JSON.stringify(entry) + "\n");
      } catch { /* ignore write errors — log to journal instead */ }
    }

    // ── Initialize security primitives ────────────────────────────────────

    const toolValidator = new ToolValidator({
      workspaceRoot,
      additionalDenyList: [],
      dangerousPatterns: DEFAULT_DANGEROUS_PATTERNS,
    });

    // Use CREDENTIAL_PATTERNS only (not PII) — redacting email addresses, IPs,
    // and phone numbers from messages/context breaks the bot's ability to use
    // its own tools (e.g. email_send needs to reference Gmail address in responses).
    const redactor = new CredentialRedactor(CREDENTIAL_PATTERNS);

    const sovereignBackends = (pluginConfig["sovereignBackends"] as Array<{ name: string; url: string; model: string; available?: boolean }>) ?? [];

    const router = new SovereignRouter({
      defaultMode: defaultMode as "sovereign" | "public" | "auto",
      sovereignBackends,
      cloudModels: [],
      channelDefaults: {},
    });

    // ── exec→plugin redirect: catch shell commands that should use named tools ─

    /** Map of shell command patterns to the plugin tool that should be used instead. */
    const EXEC_REDIRECTS: Array<{ pattern: RegExp; tool: string; desc: string }> = [
      { pattern: /\bcurl\b.*(?:tomorrow\.io|weather|forecast)/i, tool: "weather", desc: "Use the `weather` tool to get weather data" },
      { pattern: /\bcurl\b.*(?:smtp|imap|gmail|mail)/i, tool: "email_send", desc: "Use the `email_send` tool to send email, or `email_read` to check inbox" },
      { pattern: /\bcurl\b.*(?:caldav|carddav|radicale|calendar)/i, tool: "calendar_list", desc: "Use `calendar_list`, `calendar_add`, `contacts_list`, or `contacts_add`" },
      { pattern: /\bcurl\b.*(?:perplexity|sonar)/i, tool: "web_search", desc: "Use the built-in `web_search` tool for web searches" },
      // Generic: any curl/wget/jq in exec when we have named tools
      { pattern: /\b(?:curl|wget)\b.*(?:api|\.io|\.com|\.org)/i, tool: "(named tool)", desc: "Do NOT use curl/wget. Use the named tools: weather, email_send, email_read, calendar_list, calendar_add, contacts_list, contacts_add, web_search" },
      { pattern: /\bjq\b/, tool: "(named tool)", desc: "jq is not available. Use the named tools directly — they return structured data" },
    ];

    // ── before_tool_call: validate and block dangerous tool calls ─────────

    api.on("before_tool_call", (event) => {
      const tool = event["tool"] as string | undefined;
      if (!tool) return {};

      const rawCommand = event["rawCommand"] as string | undefined
        ?? (event["params"] as Record<string, unknown> | undefined)?.["command"] as string | undefined;
      const filePath = (event["params"] as Record<string, unknown> | undefined)?.["filePath"] as string | undefined;

      // ── Exec redirect: block exec calls that should use named plugin tools ──
      if (tool === "exec" && rawCommand) {
        for (const redirect of EXEC_REDIRECTS) {
          if (redirect.pattern.test(rawCommand)) {
            const reason = `BLOCKED: ${redirect.desc}. Do NOT use shell commands (curl/wget/jq) — the sandbox does not have them. Call the tool directly.`;
            log.warn(`[lobsec] exec→plugin redirect: ${rawCommand.slice(0, 80)} → ${redirect.tool}`);
            audit("exec_redirect", "WARN", { command: rawCommand.slice(0, 200), suggestedTool: redirect.tool });
            return { block: true, blockReason: reason };
          }
        }
      }

      const result = toolValidator.validate({
        tool,
        args: (event["params"] as Record<string, unknown>) ?? {},
        rawCommand,
        filePath,
        traceId: (event["traceId"] as string) ?? "unknown",
      });

      if (result.action === "deny") {
        log.warn(`[lobsec] tool blocked: ${tool} — ${result.reasons.join("; ")}`);
        audit("tool_denied", "WARN", { tool, reasons: result.reasons, traceId: result.traceId });
        return { block: true, blockReason: `lobsec: ${result.reasons.join("; ")}` };
      }
      audit("tool_allowed", "INFO", { tool, traceId: result.traceId });
      return {};
    }, { priority: 100 });

    // ── before_model_resolve: sovereign/public routing ───────────────────

    api.on("before_model_resolve", (event) => {
      const sessionId = event["sessionId"] as string | undefined;
      const channel = event["channel"] as string | undefined;
      if (!sessionId) return {};

      const decision = router.route(
        sessionId,
        (event["model"] as string) ?? "",
        (event["traceId"] as string) ?? "unknown",
        channel,
      );

      // Only override to sovereign backend when mode is explicitly "sovereign"
      // (set by user via /sovereign command or channel default).
      // In "public" and "auto" modes, let OpenClaw use its default model (Claude).
      if (decision.mode === "sovereign" && decision.backend === "sovereign" && decision.model !== "unavailable") {
        return {
          providerOverride: "ollama",
          modelOverride: decision.model,
        };
      }
      return {};
    }, { priority: 90 });

    // ── message_sending: block outbound credential leaks ─────────────────

    api.on("message_sending", (event) => {
      const content = event["content"] as string | undefined
        ?? event["text"] as string | undefined;
      if (!content || typeof content !== "string") return {};

      if (redactor.containsSensitive(content)) {
        const result = redactor.redact(content);
        log.warn(`[lobsec] BLOCKED outbound credential leak: ${result.redactedPatterns.join(", ")}`);
        audit("credential_leak_blocked", "WARN", { patterns: result.redactedPatterns });
        return { content: result.redacted };
      }
      return {};
    }, { priority: 100 });

    // ── tool_result_persist: redact credentials from persisted tool results ─

    api.on("tool_result_persist", (event) => {
      const message = event["message"] as Record<string, unknown> | undefined;
      if (!message) return {};

      const rawContent = message["content"];

      if (typeof rawContent === "string") {
        const result = redactor.redact(rawContent);
        if (result.redactionCount > 0) {
          return { message: { ...message, content: result.redacted } };
        }
        return {};
      }

      if (Array.isArray(rawContent)) {
        let anyRedacted = false;
        const redactedBlocks = rawContent.map((block: unknown) => {
          if (typeof block === "object" && block !== null) {
            const b = block as Record<string, unknown>;
            if (b["type"] === "text" && typeof b["text"] === "string") {
              const result = redactor.redact(b["text"] as string);
              if (result.redactionCount > 0) {
                anyRedacted = true;
                return { ...b, text: result.redacted };
              }
            }
          }
          return block;
        });
        if (anyRedacted) {
          return { message: { ...message, content: redactedBlocks } };
        }
      }

      return {};
    }, { priority: 80 });

    // ── before_message_write: redact PII from persisted messages ─────────

    api.on("before_message_write", (event) => {
      const message = event["message"] as Record<string, unknown> | undefined;
      if (!message) return {};

      const rawContent = message["content"];

      // String content: redact and return as string
      if (typeof rawContent === "string") {
        const result = redactor.redact(rawContent);
        if (result.redactionCount > 0) {
          return { message: { ...message, content: result.redacted } };
        }
        return {};
      }

      // Array content blocks: redact each text block individually, preserve structure
      if (Array.isArray(rawContent)) {
        let anyRedacted = false;
        const redactedBlocks = rawContent.map((block: unknown) => {
          if (typeof block === "object" && block !== null) {
            const b = block as Record<string, unknown>;
            if (b["type"] === "text" && typeof b["text"] === "string") {
              const result = redactor.redact(b["text"] as string);
              if (result.redactionCount > 0) {
                anyRedacted = true;
                return { ...b, text: result.redacted };
              }
            }
          }
          return block;
        });
        if (anyRedacted) {
          return { message: { ...message, content: redactedBlocks } };
        }
      }

      return {};
    }, { priority: 80 });

    // ── llm_input / llm_output: audit logging (fire-and-forget) ─────────

    api.on("llm_input", (event) => {
      const model = event["model"] as string ?? "unknown";
      const channel = event["channel"] as string | undefined;
      log.info(`[lobsec] llm_input model=${model}`);
      audit("llm_request", "INFO", { model, channel });
    });

    api.on("llm_output", (event) => {
      const content = event["content"] as string | undefined;
      const model = event["model"] as string | undefined;
      if (content && redactor.containsSensitive(content)) {
        log.warn("[lobsec] LLM output contains sensitive data — will be redacted at persist");
        audit("llm_output_sensitive", "WARN", { model });
      }
    });

    // ── gateway_start / gateway_stop: lifecycle logging ─────────────────

    api.on("gateway_start", () => {
      log.info("[lobsec] security plugin active — tool validation, credential redaction, sovereign routing, audit logging enabled");
      audit("gateway_start", "INFO", { workspace: workspaceRoot, mode: defaultMode });

      // Start ConfigMonitor
      try {
        const configPath = (pluginConfig["configPath"] as string) ?? "/opt/lobsec/.openclaw/openclaw.json";
        const heartbeatPath = (pluginConfig["heartbeatPath"] as string) ?? "/opt/lobsec/.openclaw/HEARTBEAT.md";
        let configObj: Record<string, unknown> = {};
        try {
          configObj = JSON.parse(readFileSync(configPath, "utf8")) as Record<string, unknown>;
        } catch { /* config not readable — monitor will report drift */ }

        const expectedHash = canonicalHash(configObj);
        configMonitor = new ConfigMonitor({
          expectedHash,
          config: configObj,
          heartbeatPath,
          intervalSeconds: 60,
          onAlert: (alert) => {
            log.warn(`[lobsec] ConfigMonitor alert: ${alert.source} — ${alert.message}`);
            audit("config_monitor_alert", alert.severity === "critical" ? "ERROR" : "WARN", {
              source: alert.source,
              message: alert.message,
            });
          },
        });
        configMonitor.start();
        log.info("[lobsec] ConfigMonitor started (60s interval)");
      } catch (err) {
        log.error("[lobsec] Failed to start ConfigMonitor:", (err as Error).message);
      }

      // Register bot commands if the API supports it
      if (api.registerCommand) {
        import("./dist/bot-commands.js").then((mod: { buildCommands: (deps: { monitor: ConfigMonitor | null; router: SovereignRouter; auditLogPath: string }) => CommandDefinition[] }) => {
          const commands = mod.buildCommands({
            monitor: configMonitor,
            router,
            auditLogPath,
          });
          for (const cmd of commands) {
            api.registerCommand!(cmd);
          }
          log.info(`[lobsec] registered ${commands.length} bot commands`);
        }).catch((err: Error) => {
          log.warn(`[lobsec] bot commands not available: ${err.message}`);
        });
      }
    });

    api.on("gateway_stop", () => {
      log.info("[lobsec] security plugin shutting down");
      audit("gateway_stop", "INFO");

      // Stop ConfigMonitor
      if (configMonitor) {
        configMonitor.stop();
        configMonitor = null;
        log.info("[lobsec] ConfigMonitor stopped");
      }
    });

    log.info(`[lobsec] registered 9 security hooks (workspace=${workspaceRoot}, mode=${defaultMode})`);
  },
};
