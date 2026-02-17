import { Command } from "commander";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  validateHardenedConfig,
  generateNftablesRules,
  detectDrift,
  canonicalHash,
  Logger,
} from "@lobsec/shared";
import { output, outputError, getGlobalOpts } from "../output.js";

export function startCommand(): Command {
  return new Command("start")
    .description("Start lobsec security hardening")
    .option("-d, --dir <path>", "Base directory for lobsec data", "/etc/lobsec")
    .option("--skip-firewall", "Skip nftables rule application (for testing)")
    .option("--dry-run", "Show what would be done without applying changes")
    .action(async function (this: Command) {
      const opts = this.opts() as {
        dir: string;
        skipFirewall: boolean;
        dryRun: boolean;
      };
      const baseDir = opts.dir;
      const { verbose } = getGlobalOpts(this);

      try {
        // 1. Load and validate config
        const configPath = join(baseDir, "config", "lobsec.json");
        const configContent = await readFile(configPath, "utf8");
        const config = JSON.parse(configContent) as unknown;

        const violations = validateHardenedConfig(config);
        if (violations.length > 0) {
          outputError(this, "Configuration validation failed", {
            violations,
          });
          return;
        }

        // 2. Compute config hash for drift detection
        const configHash = canonicalHash(config);

        // 3. Check for drift
        const drift = detectDrift(config, configHash);
        if (!drift.clean) {
          outputError(this, "Configuration drift detected", {
            violations: drift.violations,
          });
          return;
        }

        // 4. Generate nftables rules
        const nftRules = generateNftablesRules();

        if (opts.dryRun) {
          output(this, {
            status: "dry-run",
            configValid: true,
            configHash,
            nftablesRules: nftRules,
          }, `[dry-run] Config valid (hash: ${configHash.slice(0, 12)}...)\n[dry-run] Would apply nftables rules`);
          return;
        }

        // 5. Write nftables rules
        if (!opts.skipFirewall) {
          const nftPath = join(baseDir, "config", "lobsec.nft");
          await writeFile(nftPath, nftRules, { mode: 0o600 });
          if (verbose) {
            process.stderr.write(`Wrote nftables rules to ${nftPath}\n`);
            process.stderr.write("Note: Apply with 'nft -f' (requires root)\n");
          }
        }

        // 6. Start audit logger
        const logger = new Logger({
          component: "lobsec-cli",
          destinations: [
            {
              type: "file" as const,
              minLevel: "INFO" as const,
              format: "json" as const,
              path: join(baseDir, "logs", "audit", "audit.log"),
              rotation: { maxSizeMb: 100, maxFiles: 10, compress: true },
            },
            ...(verbose
              ? [{ type: "console" as const, minLevel: "DEBUG" as const, format: "pretty" as const }]
              : []),
          ],
        });

        await logger.audit({
          layer: "L4",
          event: "allow",
          module: "cli",
          fn: "start",
          msg: "lobsec started successfully",
          context: { configHash, baseDir },
        });

        // 7. Save state
        const stateFile = join(baseDir, "config", "state.json");
        await writeFile(
          stateFile,
          JSON.stringify({
            status: "running",
            configHash,
            startedAt: new Date().toISOString(),
            pid: process.pid,
          }, null, 2) + "\n",
          { mode: 0o600 },
        );

        output(this, {
          status: "started",
          configHash,
          firewall: !opts.skipFirewall,
        }, `lobsec started\n  Config hash: ${configHash.slice(0, 12)}...\n  Firewall: ${opts.skipFirewall ? "skipped" : "rules written"}\n  Audit log: ${join(baseDir, "logs", "audit", "audit.log")}`);
      } catch (err) {
        outputError(this, `Failed to start: ${(err as Error).message}`);
      }
    });
}
