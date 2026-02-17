import type { Command } from "commander";

/** Get the root program's global options. */
export function getGlobalOpts(cmd: Command): { json: boolean; verbose: boolean } {
  // Walk up to root to get global opts
  let root = cmd;
  while (root.parent) root = root.parent;
  const opts = root.opts() as { json?: boolean; verbose?: boolean };
  return {
    json: opts.json ?? false,
    verbose: opts.verbose ?? false,
  };
}

/** Output a result in either JSON or human-readable format. */
export function output(
  cmd: Command,
  data: Record<string, unknown>,
  humanMessage: string,
): void {
  const { json } = getGlobalOpts(cmd);
  if (json) {
    process.stdout.write(JSON.stringify(data, null, 2) + "\n");
  } else {
    process.stdout.write(humanMessage + "\n");
  }
}

/** Output an error. */
export function outputError(
  cmd: Command,
  error: string,
  details?: Record<string, unknown>,
): void {
  const { json } = getGlobalOpts(cmd);
  if (json) {
    process.stdout.write(
      JSON.stringify({ error, ...details }, null, 2) + "\n",
    );
  } else {
    process.stderr.write(`Error: ${error}\n`);
  }
  process.exitCode = 1;
}
