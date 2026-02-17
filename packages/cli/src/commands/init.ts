import { Command } from "commander";
import { mkdir, writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import { generateHardenedConfig } from "@lobsec/shared";
import { output, outputError } from "../output.js";

/** Default lobsec directory structure. */
const LOBSEC_DIRS = [
  "config",
  "logs",
  "logs/audit",
  "certs",
  "tmp",
] as const;

export function initCommand(): Command {
  return new Command("init")
    .description("Initialize lobsec directory structure and config")
    .option("-d, --dir <path>", "Base directory for lobsec data", "/etc/lobsec")
    .option("--force", "Overwrite existing config")
    .action(async function (this: Command) {
      const opts = this.opts() as { dir: string; force: boolean };
      const baseDir = opts.dir;

      try {
        // Check if already initialized
        const configPath = join(baseDir, "config", "lobsec.json");
        if (!opts.force) {
          try {
            await access(configPath);
            outputError(this, `Already initialized at ${baseDir}. Use --force to overwrite.`);
            return;
          } catch {
            // Not initialized yet, continue
          }
        }

        // Create directory structure
        for (const dir of LOBSEC_DIRS) {
          await mkdir(join(baseDir, dir), { recursive: true, mode: 0o700 });
        }

        // Generate initial hardened config with placeholder token
        const config = generateHardenedConfig({
          gatewayAuthToken: "${GATEWAY_AUTH_TOKEN}",
        });

        await writeFile(
          configPath,
          JSON.stringify(config, null, 2) + "\n",
          { mode: 0o600 },
        );

        // Generate minimal lobsec.json
        const lobsecConfig = {
          version: "0.1.0",
          configPath,
          logsPath: join(baseDir, "logs"),
          auditPath: join(baseDir, "logs", "audit"),
          certsPath: join(baseDir, "certs"),
        };

        await writeFile(
          join(baseDir, "config", "meta.json"),
          JSON.stringify(lobsecConfig, null, 2) + "\n",
          { mode: 0o600 },
        );

        output(this, {
          status: "initialized",
          baseDir,
          directories: LOBSEC_DIRS,
          configPath,
        }, `lobsec initialized at ${baseDir}\n  Config: ${configPath}\n  Logs: ${join(baseDir, "logs")}`);
      } catch (err) {
        outputError(this, `Failed to initialize: ${(err as Error).message}`);
      }
    });
}
