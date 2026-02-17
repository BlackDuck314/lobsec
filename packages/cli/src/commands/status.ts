import { Command } from "commander";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { detectDrift, canonicalHash } from "@lobsec/shared";
import { output, outputError } from "../output.js";

export function statusCommand(): Command {
  return new Command("status")
    .description("Show lobsec status and component health")
    .option("-d, --dir <path>", "Base directory for lobsec data", "/etc/lobsec")
    .action(async function (this: Command) {
      const opts = this.opts() as { dir: string };
      const baseDir = opts.dir;

      try {
        // Read state
        const stateFile = join(baseDir, "config", "state.json");
        let state: Record<string, unknown> = { status: "not-initialized" };
        try {
          const content = await readFile(stateFile, "utf8");
          state = JSON.parse(content) as Record<string, unknown>;
        } catch {
          // No state file means not initialized or not running
        }

        // Check config
        const configPath = join(baseDir, "config", "lobsec.json");
        let configStatus = "missing";
        let configHash: string | undefined;
        let driftStatus = "unknown";

        try {
          const configContent = await readFile(configPath, "utf8");
          const config = JSON.parse(configContent) as unknown;
          configHash = canonicalHash(config);
          configStatus = "present";

          const drift = detectDrift(config, state.configHash as string | undefined);
          driftStatus = drift.clean ? "clean" : `drift detected (${drift.violations.length} violations)`;
        } catch {
          // Config missing or invalid
        }

        // Check audit log
        const auditLogPath = join(baseDir, "logs", "audit", "audit.log");
        let auditLogSize: string | undefined;
        try {
          const s = await stat(auditLogPath);
          auditLogSize = `${(s.size / 1024).toFixed(1)} KB`;
        } catch {
          auditLogSize = "no log file";
        }

        const statusData = {
          status: state.status,
          startedAt: state.startedAt,
          configStatus,
          configHash: configHash?.slice(0, 12),
          driftStatus,
          auditLog: auditLogSize,
          baseDir,
        };

        const lines = [
          `Status:      ${state.status}`,
          state.startedAt ? `Started:     ${state.startedAt}` : null,
          `Config:      ${configStatus}${configHash ? ` (${configHash.slice(0, 12)}...)` : ""}`,
          `Drift:       ${driftStatus}`,
          `Audit log:   ${auditLogSize}`,
          `Base dir:    ${baseDir}`,
        ].filter(Boolean).join("\n");

        output(this, statusData, lines);
      } catch (err) {
        outputError(this, `Failed to get status: ${(err as Error).message}`);
      }
    });
}
