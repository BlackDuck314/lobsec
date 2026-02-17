import { Command } from "commander";
import { readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { Logger } from "@lobsec/shared";
import { output, outputError } from "../output.js";

export function stopCommand(): Command {
  return new Command("stop")
    .description("Stop lobsec security hardening")
    .option("-d, --dir <path>", "Base directory for lobsec data", "/etc/lobsec")
    .action(async function (this: Command) {
      const opts = this.opts() as { dir: string };
      const baseDir = opts.dir;

      try {
        const stateFile = join(baseDir, "config", "state.json");

        // Check current state
        let state: { status: string; configHash?: string } | undefined;
        try {
          const content = await readFile(stateFile, "utf8");
          state = JSON.parse(content) as typeof state;
        } catch {
          outputError(this, "lobsec is not running (no state file found)");
          return;
        }

        if (state?.status !== "running") {
          outputError(this, `lobsec is not running (status: ${state?.status ?? "unknown"})`);
          return;
        }

        // Log the stop event
        const logger = new Logger({
          component: "lobsec-cli",
          destinations: [
            {
              type: "file",
              minLevel: "INFO",
              format: "json",
              path: join(baseDir, "logs", "audit", "audit.log"),
            },
          ],
        });

        await logger.audit({
          layer: "L4",
          event: "allow",
          module: "cli",
          fn: "stop",
          msg: "lobsec stopped",
          context: { configHash: state.configHash },
        });

        // Clean up tmpfs files if they exist
        try {
          await rm(join(baseDir, "tmp"), { recursive: true, force: true });
        } catch {
          // Ignore cleanup errors
        }

        // Update state
        await writeFile(
          stateFile,
          JSON.stringify({
            status: "stopped",
            stoppedAt: new Date().toISOString(),
          }, null, 2) + "\n",
          { mode: 0o600 },
        );

        output(this, {
          status: "stopped",
        }, "lobsec stopped");
      } catch (err) {
        outputError(this, `Failed to stop: ${(err as Error).message}`);
      }
    });
}
