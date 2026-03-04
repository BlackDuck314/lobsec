// ── Bot Commands ──────────────────────────────────────────────────────────
// Builds Telegram bot command handlers for the lobsec control plane.
// Commands: /status, /verify, /audit, /alerts, /sovereign

import type { ConfigMonitor, MonitorAlert } from "./config-monitor.js";
import type { SovereignRouter, RoutingMode } from "./sovereign-router.js";
import { readFileSync } from "node:fs";

// ── Types ───────────────────────────────────────────────────────────────────

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

export interface CommandDeps {
  monitor: ConfigMonitor | null;
  router: SovereignRouter;
  auditLogPath: string;
  verifyFn?: () => Promise<{ overall: string; layers: Array<{ layer: string; status: string; checks: Array<{ name: string; status: string; message: string }> }>; summary: { passed: number; failed: number; warned: number; skipped: number } }>;
}

// ── Status icons ──────────────────────────────────────────────────────────

const ICONS: Record<string, string> = {
  pass: "\u2705",   // green check
  fail: "\u274c",   // red X
  warn: "\u26a0\ufe0f",  // warning
  skip: "\u23ed\ufe0f",  // skip
};

// ── Command builders ──────────────────────────────────────────────────────

function buildStatusCommand(deps: CommandDeps): CommandDefinition {
  return {
    name: "status",
    description: "Quick security layer scorecard",
    handler: async () => {
      if (!deps.verifyFn) {
        return { text: "Security verifier not available." };
      }

      try {
        const report = await deps.verifyFn();
        const lines = report.layers.map((l) => {
          const icon = ICONS[l.status] ?? "?";
          return `${icon} ${l.layer}`;
        });

        const header = `Security Status: ${ICONS[report.overall] ?? "?"} ${report.overall.toUpperCase()}`;
        return { text: `${header}\n\n${lines.join("\n")}\n\n${report.summary.passed}/${report.summary.passed + report.summary.failed + report.summary.warned + report.summary.skipped} checks passing` };
      } catch (err) {
        return { text: `Status check failed: ${(err as Error).message}` };
      }
    },
  };
}

function buildVerifyCommand(deps: CommandDeps): CommandDefinition {
  return {
    name: "verify",
    description: "Full security verification with per-check details",
    handler: async () => {
      if (!deps.verifyFn) {
        return { text: "Security verifier not available." };
      }

      try {
        const report = await deps.verifyFn();
        const sections = report.layers.map((layer) => {
          const icon = ICONS[layer.status] ?? "?";
          const checks = layer.checks.map((c) =>
            `  ${ICONS[c.status] ?? "?"} ${c.name}: ${c.message}`
          ).join("\n");
          return `${icon} ${layer.layer}\n${checks}`;
        });

        const header = `Security Verification: ${ICONS[report.overall] ?? "?"} ${report.overall.toUpperCase()}`;
        const summary = `\nPassed: ${report.summary.passed} | Failed: ${report.summary.failed} | Warned: ${report.summary.warned} | Skipped: ${report.summary.skipped}`;
        return { text: `${header}\n\n${sections.join("\n\n")}${summary}` };
      } catch (err) {
        return { text: `Verification failed: ${(err as Error).message}` };
      }
    },
  };
}

function buildAuditCommand(deps: CommandDeps): CommandDefinition {
  return {
    name: "audit",
    description: "Show last N audit log entries (default 10)",
    handler: (ctx) => {
      const n = parseInt(ctx.args ?? "10", 10) || 10;
      const maxEntries = Math.min(n, 50); // Cap at 50

      try {
        const content = readFileSync(deps.auditLogPath, "utf8");
        const lines = content.trim().split("\n").filter(Boolean);
        const recent = lines.slice(-maxEntries);

        if (recent.length === 0) {
          return { text: "No audit log entries found." };
        }

        const entries = recent.map((line) => {
          try {
            const entry = JSON.parse(line) as Record<string, unknown>;
            const ts = (entry["ts"] as string)?.slice(11, 19) ?? "??:??:??";
            const event = entry["event"] as string ?? "unknown";
            const level = entry["level"] as string ?? "INFO";
            return `[${ts}] ${level} ${event}`;
          } catch {
            return line.slice(0, 80);
          }
        });

        return { text: `Last ${recent.length} audit entries:\n\n${entries.join("\n")}` };
      } catch {
        return { text: "Audit log not readable." };
      }
    },
  };
}

function buildAlertsCommand(deps: CommandDeps): CommandDefinition {
  return {
    name: "alerts",
    description: "Show active alerts from ConfigMonitor",
    handler: () => {
      if (!deps.monitor) {
        return { text: "ConfigMonitor not running. No alerts to display." };
      }

      const status = deps.monitor.getStatus();
      const alerts = deps.monitor.getAlerts();

      const header = `ConfigMonitor: ${status.running ? "running" : "stopped"} | Checks: ${status.checksCompleted} | Alerts: ${status.alertsRaised}`;

      if (alerts.length === 0) {
        return { text: `${header}\n\nNo active alerts.` };
      }

      const recentAlerts = alerts.slice(-20).map((a: MonitorAlert) => {
        const ts = a.timestamp.slice(11, 19);
        const icon = a.severity === "critical" ? "\u274c" : a.severity === "warning" ? "\u26a0\ufe0f" : "\u2139\ufe0f";
        return `${icon} [${ts}] ${a.source}: ${a.message}`;
      });

      return { text: `${header}\n\n${recentAlerts.join("\n")}` };
    },
  };
}

function buildSovereignCommand(deps: CommandDeps): CommandDefinition {
  return {
    name: "sovereign",
    description: "Toggle sovereign routing mode (on/off/auto)",
    handler: (ctx) => {
      const arg = ctx.args?.trim().toLowerCase();

      if (!arg) {
        // Show current mode
        const sessionId = ctx.senderId ?? ctx.channel;
        const decision = deps.router.route(sessionId, "", "status-check", ctx.channel);
        return { text: `Current routing mode: ${decision.mode}` };
      }

      const modeMap: Record<string, RoutingMode> = {
        on: "sovereign",
        off: "public",
        auto: "auto",
        sovereign: "sovereign",
        public: "public",
      };

      const newMode = modeMap[arg];
      if (!newMode) {
        return { text: `Unknown mode: ${arg}. Use: on, off, auto` };
      }

      const sessionId = ctx.senderId ?? ctx.channel;
      deps.router.setMode(sessionId, newMode);
      return { text: `Routing mode set to: ${newMode}` };
    },
  };
}

// ── Main entry point ──────────────────────────────────────────────────────

export function buildCommands(deps: CommandDeps): CommandDefinition[] {
  return [
    buildStatusCommand(deps),
    buildVerifyCommand(deps),
    buildAuditCommand(deps),
    buildAlertsCommand(deps),
    buildSovereignCommand(deps),
  ];
}
