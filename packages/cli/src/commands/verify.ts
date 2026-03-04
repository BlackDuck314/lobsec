import { Command } from "commander";
import { verifyAll, LAYER_NAMES } from "@lobsec/shared";
import type { LayerReport, CheckResult } from "@lobsec/shared";
import { output, outputError } from "../output.js";

const STATUS_ICONS: Record<string, string> = {
  pass: "[OK]",
  fail: "[FAIL]",
  warn: "[WARN]",
  skip: "[SKIP]",
};

function formatLayer(layer: LayerReport): string {
  const icon = STATUS_ICONS[layer.status] ?? "[??]";
  const checks = layer.checks.map((c: CheckResult) =>
    `  ${STATUS_ICONS[c.status] ?? "[??]"} ${c.name}: ${c.message}`
  ).join("\n");
  return `${icon} ${layer.layer}\n${checks}`;
}

export function verifyCommand(): Command {
  return new Command("verify")
    .description("Run security verification across all 9 layers")
    .option("-d, --dir <path>", "Base directory for lobsec data", "/opt/lobsec")
    .option("-l, --layer <name>", "Only verify a specific layer")
    .option("--config <path>", "Path to openclaw.json")
    .option("--expected-hash <hash>", "Expected config hash for drift detection")
    .action(async function (this: Command) {
      const opts = this.opts() as {
        dir: string;
        layer?: string;
        config?: string;
        expectedHash?: string;
      };

      try {
        const layers = opts.layer ? [opts.layer] : undefined;

        // Validate layer name
        if (opts.layer && !LAYER_NAMES.includes(opts.layer)) {
          outputError(this, `Unknown layer: ${opts.layer}. Available: ${LAYER_NAMES.join(", ")}`);
          return;
        }

        const report = await verifyAll({
          baseDir: opts.dir,
          configPath: opts.config,
          layers,
          expectedConfigHash: opts.expectedHash,
        });

        // Set exit code based on overall status
        if (report.overall === "fail") {
          process.exitCode = 1;
        } else if (report.overall === "warn") {
          process.exitCode = 2;
        }

        const humanLines = [
          `Security Verification: ${STATUS_ICONS[report.overall]} ${report.overall.toUpperCase()}`,
          `Timestamp: ${report.timestamp}`,
          "",
          ...report.layers.map(formatLayer),
          "",
          `Summary: ${report.summary.passed} passed, ${report.summary.failed} failed, ${report.summary.warned} warned, ${report.summary.skipped} skipped`,
        ];

        output(this, report as unknown as Record<string, unknown>, humanLines.join("\n"));
      } catch (err) {
        outputError(this, `Verification failed: ${(err as Error).message}`);
      }
    });
}
