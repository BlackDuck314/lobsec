// ── Feynman Research Plugin Tool ─────────────────────────────────────────────
// Spawns Feynman CLI research workflows and collects outputs.
// Fire-and-forget pattern: returns result file path immediately, writes
// status/output to JSON when complete. Follows the examy_test pattern.

import { spawn } from "node:child_process";
import { writeFile, readFile, readdir, mkdir, stat, rm } from "node:fs/promises";
import { join } from "node:path";

// ── Types ────────────────────────────────────────────────────────────────────

export type FeynmanWorkflow =
  | "deepresearch"
  | "lit"
  | "summarize"
  | "audit"
  | "compare"
  | "draft"
  | "review"
  | "replicate";

export interface FeynmanResult {
  status: "started" | "complete" | "error";
  workflow: FeynmanWorkflow;
  topic: string;
  model: string;
  startTime: string;
  endTime?: string;
  mainOutput?: string;
  outputFiles?: string[];
  stdout?: string;
  stderr?: string;
  error?: string;
  resultPath: string;
}

const VALID_WORKFLOWS: ReadonlySet<string> = new Set<FeynmanWorkflow>([
  "deepresearch", "lit", "summarize", "audit",
  "compare", "draft", "review", "replicate",
]);

const FEYNMAN_BIN = "/opt/lobsec/.local/bin/feynman";
const FEYNMAN_HOME = "/opt/lobsec";
const OUTPUT_DIR = "/opt/lobsec/outputs";
const RESULT_BASE = "/opt/lobsec/data/feynman-outputs";

// Timeouts in milliseconds per workflow (generous — Feynman uses chunked
// processing for large sources, which can take much longer than expected)
const WORKFLOW_TIMEOUTS: Record<FeynmanWorkflow, number> = {
  summarize: 8 * 60_000,
  review: 8 * 60_000,
  audit: 10 * 60_000,
  compare: 10 * 60_000,
  draft: 10 * 60_000,
  replicate: 10 * 60_000,
  deepresearch: 15 * 60_000,
  lit: 15 * 60_000,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/** List .md files in the outputs dir, with mtime */
async function listOutputFiles(): Promise<Map<string, number>> {
  const map = new Map<string, number>();
  try {
    const entries = await readdir(OUTPUT_DIR);
    for (const entry of entries) {
      if (entry.endsWith(".md")) {
        const fullPath = join(OUTPUT_DIR, entry);
        const s = await stat(fullPath);
        map.set(fullPath, s.mtimeMs);
      }
    }
  } catch {
    // outputs dir may not exist yet
  }
  return map;
}

/** Find .md files created/modified after the given timestamp */
async function findNewOutputs(beforeSnapshot: Map<string, number>): Promise<string[]> {
  const newFiles: string[] = [];
  try {
    const entries = await readdir(OUTPUT_DIR);
    for (const entry of entries) {
      if (!entry.endsWith(".md")) continue;
      const fullPath = join(OUTPUT_DIR, entry);
      const s = await stat(fullPath);
      const prevMtime = beforeSnapshot.get(fullPath);
      if (prevMtime === undefined || s.mtimeMs > prevMtime) {
        newFiles.push(fullPath);
      }
    }
  } catch {
    // ignore
  }
  return newFiles;
}

/** Read the primary (non-provenance, non-notes) output file */
async function readPrimaryOutput(files: string[]): Promise<string | undefined> {
  // Prefer the file that doesn't contain "provenance" or "notes"
  const primary = files.find(
    (f) => !f.includes("provenance") && !f.includes(".notes"),
  ) ?? files[0];
  if (!primary) return undefined;
  try {
    return await readFile(primary, "utf-8");
  } catch {
    return undefined;
  }
}

/** Prune result dirs older than 30 days */
async function pruneOldResults(): Promise<void> {
  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  try {
    const entries = await readdir(RESULT_BASE);
    for (const entry of entries) {
      const fullPath = join(RESULT_BASE, entry);
      const s = await stat(fullPath);
      if (s.isFile() && s.mtimeMs < thirtyDaysAgo) {
        await rm(fullPath).catch(() => {});
      }
    }
  } catch {
    // result dir may not exist yet
  }
}

// ── Core ─────────────────────────────────────────────────────────────────────

export async function runFeynman(
  workflow: FeynmanWorkflow,
  topic: string,
  resultPath: string,
  model?: string,
): Promise<void> {
  const startTime = new Date().toISOString();
  const usedModel = model ?? "claude-haiku-4-5-20251001";
  const timeout = WORKFLOW_TIMEOUTS[workflow];

  // Snapshot outputs before run
  const beforeSnapshot = await listOutputFiles();

  // Build command args
  const args = [workflow, topic];

  // Ensure Feynman tmp dir exists (systemd ProtectSystem=strict blocks /tmp)
  const feynmanTmp = join(FEYNMAN_HOME, "tmp", "feynman");
  await mkdir(feynmanTmp, { recursive: true });

  // Spawn Feynman CLI
  const child = spawn(FEYNMAN_BIN, args, {
    cwd: FEYNMAN_HOME,
    env: {
      ...process.env,
      HOME: FEYNMAN_HOME,
      TMPDIR: feynmanTmp,
      // Force non-interactive — no TTY
      CI: "true",
      TERM: "dumb",
    },
    stdio: ["ignore", "pipe", "pipe"],
    // Don't use Node's timeout — we manage it ourselves
  });

  let stdout = "";
  let stderr = "";

  // Feynman workflows complete their work then drop into an interactive REPL.
  // Feynman replaces its stdout with IPC sockets, so we can't rely on
  // child.stdout alone. We monitor BOTH stdout AND output file modifications.
  const spawnedAt = Date.now();
  let lastActivityAt = Date.now();
  let hasActivity = false;
  const IDLE_KILL_MS = 30_000;      // 30s of no activity = done
  const GRACE_PERIOD_MS = 60_000;   // Wait at least 60s before idle-killing

  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString();
    lastActivityAt = Date.now();
    hasActivity = true;
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
    lastActivityAt = Date.now();
    hasActivity = true;
  });

  // Idle detection: monitor stdout AND output files for changes
  const idleCheck = setInterval(async () => {
    const elapsed = Date.now() - spawnedAt;
    if (elapsed < GRACE_PERIOD_MS) return; // Grace period

    // Check if output files have been modified recently
    try {
      const entries = await readdir(OUTPUT_DIR).catch(() => [] as string[]);
      for (const entry of entries) {
        if (!entry.endsWith(".md")) continue;
        const s = await stat(join(OUTPUT_DIR, entry)).catch(() => null);
        if (s && s.mtimeMs > lastActivityAt) {
          lastActivityAt = s.mtimeMs;
          hasActivity = true;
        }
      }
    } catch { /* ignore */ }

    if (hasActivity && Date.now() - lastActivityAt > IDLE_KILL_MS) {
      child.kill("SIGTERM");
      clearInterval(idleCheck);
    }
    // Fallback: if no activity at all after 2x grace period, kill anyway
    if (!hasActivity && elapsed > GRACE_PERIOD_MS * 2) {
      child.kill("SIGTERM");
      clearInterval(idleCheck);
    }
  }, 5_000);

  // Hard timeout as safety net
  const hardTimeout = setTimeout(() => {
    child.kill("SIGKILL");
    clearInterval(idleCheck);
  }, timeout);

  // Wait for process exit
  const exitCode = await new Promise<number | null>((resolve) => {
    child.on("close", (code) => resolve(code));
    child.on("error", (err) => {
      stderr += `\nSpawn error: ${err.message}`;
      resolve(1);
    });
  });

  clearInterval(idleCheck);
  clearTimeout(hardTimeout);

  // Treat SIGTERM kill (from idle detection) as success if we got activity
  const wasIdleKilled = exitCode === null && hasActivity;

  // Find new output files
  const newFiles = await findNewOutputs(beforeSnapshot);
  const mainOutput = await readPrimaryOutput(newFiles);

  // Strip ANSI escape codes from stdout/stderr
  const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

  const result: FeynmanResult = {
    status: (exitCode === 0 || wasIdleKilled) ? "complete" : "error",
    workflow,
    topic,
    model: usedModel,
    startTime,
    endTime: new Date().toISOString(),
    mainOutput: mainOutput ?? undefined,
    outputFiles: newFiles.length > 0 ? newFiles : undefined,
    stdout: stripAnsi(stdout).slice(0, 10_000) || undefined,
    stderr: stripAnsi(stderr).slice(0, 5_000) || undefined,
    error: (exitCode !== 0 && !wasIdleKilled) ? `Feynman exited with code ${exitCode}` : undefined,
    resultPath,
  };

  await writeFile(resultPath, JSON.stringify(result, null, 2));

  // Background cleanup — don't await
  pruneOldResults().catch(() => {});
}

export function isValidWorkflow(s: string): s is FeynmanWorkflow {
  return VALID_WORKFLOWS.has(s);
}
