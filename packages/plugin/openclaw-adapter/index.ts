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
import { CredentialRedactor } from "./dist/credential-redactor.js";
import { SovereignRouter } from "./dist/sovereign-router.js";
import { appendFileSync } from "node:fs";

// Type stubs for OpenClaw's plugin API (we don't have the SDK types locally)
interface PluginApi {
  id: string;
  config: Record<string, unknown>;
  pluginConfig?: Record<string, unknown>;
  logger: { info: (...args: unknown[]) => void; warn: (...args: unknown[]) => void; error: (...args: unknown[]) => void };
  on: (hookName: string, handler: (event: Record<string, unknown>) => unknown, opts?: { priority?: number }) => void;
}

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

    const redactor = new CredentialRedactor();

    const sovereignBackends = [];
    const gpuUrl = process.env["OLLAMA_SOVEREIGN_URL"];
    if (gpuUrl) {
      sovereignBackends.push({ name: "remote-gpu", url: gpuUrl, model: process.env["OLLAMA_SOVEREIGN_MODEL"] ?? "qwen2.5:32b", available: true });
    }
    const jetsonUrl = process.env["OLLAMA_JETSON_URL"];
    if (jetsonUrl) {
      sovereignBackends.push({ name: "jetson", url: jetsonUrl, model: process.env["OLLAMA_JETSON_MODEL"] ?? "gemma3:1b", available: true });
    }

    const router = new SovereignRouter({
      defaultMode: defaultMode as "sovereign" | "public" | "auto",
      sovereignBackends,
      cloudModels: [],
      channelDefaults: { telegram: "sovereign" },
    });

    // ── before_tool_call: validate and block dangerous tool calls ─────────

    api.on("before_tool_call", (event) => {
      const tool = event["tool"] as string | undefined;
      if (!tool) return {};

      const rawCommand = event["rawCommand"] as string | undefined
        ?? (event["params"] as Record<string, unknown> | undefined)?.["command"] as string | undefined;
      const filePath = (event["params"] as Record<string, unknown> | undefined)?.["filePath"] as string | undefined;

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

      if (decision.backend === "sovereign" && decision.model !== "unavailable") {
        return {
          providerOverride: decision.backend === "sovereign" ? "ollama" : undefined,
          modelOverride: decision.model,
        };
      }
      return {};
    }, { priority: 90 });

    // ── message_sending: block outbound credential leaks ─────────────────

    api.on("message_sending", (event) => {
      const content = event["content"] as string | undefined
        ?? event["text"] as string | undefined;
      if (!content) return {};

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

      const content = message["content"] as string | undefined;
      if (!content) return {};

      const result = redactor.redact(content);
      if (result.redactionCount > 0) {
        return { message: { ...message, content: result.redacted } };
      }
      return {};
    }, { priority: 80 });

    // ── before_message_write: redact PII from persisted messages ─────────

    api.on("before_message_write", (event) => {
      const message = event["message"] as Record<string, unknown> | undefined;
      if (!message) return {};

      const content = message["content"] as string | undefined;
      if (!content) return {};

      const result = redactor.redact(content);
      if (result.redactionCount > 0) {
        return { message: { ...message, content: result.redacted } };
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
    });

    api.on("gateway_stop", () => {
      log.info("[lobsec] security plugin shutting down");
      audit("gateway_stop", "INFO");
    });

    log.info(`[lobsec] registered 9 security hooks (workspace=${workspaceRoot}, mode=${defaultMode})`);
  },
};
