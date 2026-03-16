/**
 * Statistical Analysis Pipeline Orchestrator
 *
 * Sequences the 6 Python analysis modules in dependency order,
 * logs each step to analysis_log, and dispatches the monthly Telegram digest.
 *
 * Dependency graph:
 *   stationarity (always)
 *     → granger (only if stationarity succeeded)
 *       → composite (only if granger succeeded)
 *   anomalies (always, independent)
 *   affordability (always, independent)
 *   expat_funnel (always, independent)
 */

import type Database from "better-sqlite3";
import { runPython } from "./bridge.js";
import type { PythonScriptName } from "./types.js";
import { generateDigest, formatDigestMessage } from "./digest.js";

/** Result for a single pipeline step. */
export interface StepResult {
  step: string;
  status: "success" | "failed" | "skipped";
  durationMs: number;
  signalsProcessed?: number;
  signalsSkipped?: number;
  error?: string;
}

/** Overall pipeline run result. */
export interface PipelineResult {
  success: boolean;
  steps: StepResult[];
  totalDurationMs: number;
  digestSent: boolean;
}

/** Summary data returned by batch Python analysis modules via stdout. */
interface AnalysisSummary {
  processed?: number;
  skipped?: number;
  signals_processed?: number;
  signals_skipped?: number;
}

/**
 * Get the next analysis run date: 25th of the current or next month at 02:00 UTC.
 *
 * If today is before the 25th of the current month, returns the 25th of this month.
 * Otherwise returns the 25th of next month. Always 02:00 UTC.
 */
export function getNextAnalysisDate(): Date {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth(); // 0-indexed
  const day = now.getUTCDate();

  // Candidate: 25th of current month at 02:00 UTC
  const candidate = new Date(Date.UTC(year, month, 25, 2, 0, 0));

  if (day < 25) {
    // Still before the 25th this month
    return candidate;
  }

  // On or after 25th: return 25th of next month
  // Date.UTC handles month overflow automatically (month 12 = January next year)
  return new Date(Date.UTC(year, month + 1, 25, 2, 0, 0));
}

/**
 * Sanitize an error message for storage in analysis_log.
 *
 * Strips numeric sequences that could be data values (SEC-07: no PII/data in logs).
 * Keeps structural error text only.
 */
function sanitizeError(raw: string): string {
  // Remove long numeric sequences (>= 4 digits) that could be data values
  return raw
    .replace(/\b\d{4,}\b/g, "[N]")
    .slice(0, 500); // truncate to reasonable length
}

/**
 * Send a Telegram message via the Bot API.
 *
 * Uses TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables.
 * Silently skips if token is absent.
 */
async function sendTelegramMessage(text: string): Promise<boolean> {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID || "7197099561";

  if (!token) {
    console.error("[pipeline] No TELEGRAM_BOT_TOKEN, skipping digest dispatch");
    return false;
  }

  const url = `https://api.telegram.org/bot${token}/sendMessage`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: "HTML",
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      console.error(`[pipeline] Telegram API error ${response.status}: ${body}`);
      return false;
    }

    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[pipeline] Telegram send failed: ${msg}`);
    return false;
  }
}

/**
 * Execute the statistical analysis pipeline.
 *
 * Runs 6 Python analysis modules in dependency order:
 * 1. analyze_stationarity (always)
 * 2. analyze_granger (only if step 1 succeeded)
 * 3. analyze_composite (only if step 2 succeeded)
 * 4. analyze_anomalies (always, independent)
 * 5. analyze_affordability (always, independent)
 * 6. analyze_expat_funnel (always, independent)
 *
 * Each step is logged to analysis_log with parameterized statements (SEC-06).
 * Error messages are sanitized before storage (SEC-07).
 *
 * After all steps, dispatches Telegram digest if >= 3 Granger-validated signals exist.
 *
 * @param db - Open better-sqlite3 database instance
 * @returns Pipeline run result with step details and digest status
 */
export async function runAnalysisPipeline(
  db: Database.Database
): Promise<PipelineResult> {
  const pipelineStart = Date.now();
  const steps: StepResult[] = [];
  const dbPath = db.name;

  // Batch timeout: 5 minutes for all analysis steps
  const BATCH_TIMEOUT_MS = 300_000;

  // Prepared statements for analysis_log (SEC-06: all SQL parameterized)
  const insertLog = db.prepare(
    "INSERT INTO analysis_log (pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) VALUES (?, 'in_progress', 0, 0, 0, NULL, datetime('now'))"
  );

  const updateLogSuccess = db.prepare(
    "UPDATE analysis_log SET status = 'success', signals_processed = ?, signals_skipped = ?, duration_ms = ? WHERE pipeline_step = ? AND status = 'in_progress' ORDER BY id DESC LIMIT 1"
  );

  const updateLogFailed = db.prepare(
    "UPDATE analysis_log SET status = 'failed', duration_ms = ?, error = ? WHERE pipeline_step = ? AND status = 'in_progress' ORDER BY id DESC LIMIT 1"
  );

  const insertSkipped = db.prepare(
    "INSERT INTO analysis_log (pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) VALUES (?, 'skipped', 0, 0, 0, NULL, datetime('now'))"
  );

  /**
   * Execute one pipeline step.
   */
  async function runStep(
    stepName: string,
    scriptName: PythonScriptName,
    skip: boolean
  ): Promise<StepResult> {
    if (skip) {
      insertSkipped.run(stepName);
      const result: StepResult = {
        step: stepName,
        status: "skipped",
        durationMs: 0,
      };
      steps.push(result);
      console.error(`[pipeline] ${stepName}: skipped (upstream dependency failed)`);
      return result;
    }

    // Log start
    insertLog.run(stepName);
    const stepStart = Date.now();

    console.error(`[pipeline] ${stepName}: starting`);

    const pythonResult = await runPython<AnalysisSummary>(
      scriptName,
      { db_path: dbPath },
      { defaultTimeoutMs: BATCH_TIMEOUT_MS }
    );

    const durationMs = Date.now() - stepStart;

    if (pythonResult.success && pythonResult.data) {
      const processed =
        pythonResult.data.signals_processed ??
        pythonResult.data.processed ??
        0;
      const skipped =
        pythonResult.data.signals_skipped ??
        pythonResult.data.skipped ??
        0;

      updateLogSuccess.run(processed, skipped, durationMs, stepName);

      const result: StepResult = {
        step: stepName,
        status: "success",
        durationMs,
        signalsProcessed: processed,
        signalsSkipped: skipped,
      };
      steps.push(result);
      console.error(
        `[pipeline] ${stepName}: success (processed=${processed}, skipped=${skipped}, duration=${durationMs}ms)`
      );
      return result;
    } else {
      const rawError = pythonResult.error ?? "Unknown error";
      const safeError = sanitizeError(rawError);

      updateLogFailed.run(durationMs, safeError, stepName);

      const result: StepResult = {
        step: stepName,
        status: "failed",
        durationMs,
        error: safeError,
      };
      steps.push(result);
      console.error(
        `[pipeline] ${stepName}: failed (duration=${durationMs}ms, error=${safeError})`
      );
      return result;
    }
  }

  // ── Step 1: Stationarity (always run) ────────────────────────────────────
  const stationarityResult = await runStep(
    "stationarity",
    "analyze_stationarity",
    false
  );
  const stationarityFailed = stationarityResult.status === "failed";

  // ── Step 2: Granger (requires stationarity success) ───────────────────────
  const grangerResult = await runStep(
    "granger",
    "analyze_granger",
    stationarityFailed
  );
  const grangerFailed =
    grangerResult.status === "failed" || grangerResult.status === "skipped";

  // ── Step 3: Composite (requires granger success) ──────────────────────────
  await runStep("composite", "analyze_composite", grangerFailed);

  // ── Step 4: Anomalies (always run, independent) ───────────────────────────
  await runStep("anomalies", "analyze_anomalies", false);

  // ── Step 5: Affordability (always run, independent) ───────────────────────
  await runStep("affordability", "analyze_affordability", false);

  // ── Step 6: Expat funnel (always run, independent) ────────────────────────
  await runStep("expat_funnel", "analyze_expat_funnel", false);

  // ── Update cache TTL for all analysis products ────────────────────────────
  const nextRunDate = getNextAnalysisDate();
  const expiresAt = nextRunDate.toISOString();

  const updateCacheTtl = db.prepare(
    "UPDATE intelligence_cache SET expires_at = ? WHERE product IN ('stationarity', 'granger', 'composite', 'anomalies', 'affordability', 'expat_funnel')"
  );
  updateCacheTtl.run(expiresAt);
  console.error(`[pipeline] cache TTL updated, next run: ${expiresAt}`);

  // ── Digest dispatch ───────────────────────────────────────────────────────
  let digestSent = false;

  const grangerCountRow = db
    .prepare(
      "SELECT COUNT(*) AS cnt FROM granger_results WHERE significant = 1 AND tested_at > datetime('now', '-1 day')"
    )
    .get() as { cnt: number } | undefined;

  const grangerCount = grangerCountRow?.cnt ?? 0;

  if (grangerCount >= 3) {
    console.error(
      `[pipeline] ${grangerCount} validated Granger signals — generating digest`
    );
    try {
      const digestData = generateDigest(db);
      const message = formatDigestMessage(digestData);
      digestSent = await sendTelegramMessage(message);
      if (digestSent) {
        console.error("[pipeline] digest sent via Telegram");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[pipeline] digest generation failed: ${msg}`);
    }
  } else {
    const logMsg = `insufficient validated signals for digest (${grangerCount} < 3)`;
    console.error(`[pipeline] ${logMsg}`);
    // Log to analysis_log so the skip reason is visible in the audit trail
    db.prepare(
      "INSERT INTO analysis_log (pipeline_step, status, signals_processed, signals_skipped, duration_ms, error, run_at) VALUES (?, 'skipped', 0, 0, 0, ?, datetime('now'))"
    ).run("digest", logMsg);
  }

  // ── Compute overall result ────────────────────────────────────────────────
  const anyFailed = steps.some((s) => s.status === "failed");
  const totalDurationMs = Date.now() - pipelineStart;

  console.error(
    `[pipeline] complete — success=${!anyFailed}, steps=${steps.length}, duration=${totalDurationMs}ms, digestSent=${digestSent}`
  );

  return {
    success: !anyFailed,
    steps,
    totalDurationMs,
    digestSent,
  };
}
