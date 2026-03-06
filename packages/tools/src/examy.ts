// ── Examy QA Test Automation ──────────────────────────────────────────────────
// Automated login and study session testing of dev.examy.app using Playwright.
// Three student personas (Grades 4, 8, 11) driven by Claude Haiku interact with
// Examy's AI tutor as real students. Captures JS exceptions, network errors,
// screenshots on failure, conversation transcripts, and structured JSON results.

import { chromium, type Page, type Browser } from "playwright";
import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";
import Anthropic from "@anthropic-ai/sdk";
import { sendEmail, type EmailConfig } from "./email.js";
import { githubAction, type GitHubConfig } from "./github.js";
import { compareVisualBaselines, type VisualCheckResult } from "./visual-regression.js";

// ── Types ───────────────────────────────────────────────────────────────────

export interface PersonaConfig {
  id: string;
  name: string;
  grade: number;
  personality: string;
  errorRate: number;
  username?: string | null;
  password?: string | null;
}

export interface TestConfig {
  username: string;
  password: string;
  anthropicApiKey: string;
  proxyBaseUrl: string;
}

export interface ErrorCollector {
  consoleErrors: Array<{ timestamp: string; message: string; url?: string }>;
  uncaughtExceptions: Array<{ timestamp: string; message: string; stack?: string }>;
  networkErrors: Array<{ timestamp: string; message: string; url?: string; method?: string; status?: number }>;
}

export interface TranscriptEntry {
  speaker: string;
  text: string;
  timestamp: string;
}

export interface PersonaResult {
  persona: string;
  passed: boolean;
  transcript: TranscriptEntry[];
  consoleErrors: ErrorCollector["consoleErrors"];
  networkErrors: ErrorCollector["networkErrors"];
  uncaughtExceptions: ErrorCollector["uncaughtExceptions"];
  screenshots: string[];
  duration: number;
}

export interface TestResult {
  status: "complete" | "error";
  startTime: string;
  endTime: string;
  results: PersonaResult[];
  summary: string;
  resultPath: string;
  visualRegression?: VisualCheckResult[];
  reporting?: {
    emailSent: boolean;
    telegramSent: boolean;
    issuesCreated: number[];
    issuesClosed: number[];
    issuesExisting: number[];
  };
}

// ── Configuration ───────────────────────────────────────────────────────────

const DEFAULT_PERSONA_CONFIG_PATH = "/opt/lobsec/config/examy-personas.json";
const SCREENSHOT_DIR = "/opt/lobsec/logs/examy";
const TARGET_URL = "https://dev.examy.app";
const TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
const EXAMY_REPO = "kromo77/examy.app";
const RECIPIENTS_PATH = "/opt/lobsec/config/examy-report-recipients.json";

const IGNORE_PATTERNS = [
  /Download the React DevTools/,
  /hydration/i,
  /deprecated/i,
];

// ── Persona Loading ────────────────────────────────────────────────────────

export function loadPersonas(configPath?: string): PersonaConfig[] {
  const path = configPath || DEFAULT_PERSONA_CONFIG_PATH;
  const content = readFileSync(path, "utf-8");
  const personas = JSON.parse(content);

  if (!Array.isArray(personas)) {
    throw new Error(`Invalid persona config: expected array, got ${typeof personas}`);
  }

  return personas as PersonaConfig[];
}

// ── Reporting Pipeline ──────────────────────────────────────────────────────

export function hashError(errorMessage: string): string {
  return createHash("sha256")
    .update(errorMessage, "utf8")
    .digest("hex")
    .substring(0, 32);
}

function loadRecipients(): string[] {
  try {
    const content = readFileSync(RECIPIENTS_PATH, "utf-8");
    const recipients = JSON.parse(content);
    if (!Array.isArray(recipients)) return [];
    return recipients.filter((r: unknown): r is string => typeof r === "string");
  } catch {
    console.error("[examy] Could not load recipients from", RECIPIENTS_PATH);
    return [];
  }
}

function formatFailureEmail(
  results: PersonaResult[],
  visualResults: VisualCheckResult[],
  runTime: string,
): string {
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;

  const lines: string[] = [
    "Examy QA Test Failure Report",
    "========================================================================",
    "",
    `Run time: ${runTime}`,
    `Total personas: ${total}`,
    `Passed: ${passed}  Failed: ${failed}`,
    "",
  ];

  // Visual regression summary
  const visualFailed = visualResults.filter((v) => !v.passed && !v.isNewBaseline);
  if (visualFailed.length > 0) {
    lines.push(`Visual regressions: ${visualFailed.length}`);
    for (const vr of visualFailed) {
      lines.push(`  - ${vr.name}: ${vr.diffPercent.toFixed(2)}% difference`);
    }
    lines.push("");
  }

  // Per-persona breakdown (only failed personas)
  const failedPersonas = results.filter((r) => !r.passed);
  for (const result of failedPersonas) {
    lines.push("------------------------------------------------------------------------");
    lines.push(`Persona: ${result.persona} — FAIL`);
    lines.push("------------------------------------------------------------------------");
    lines.push(`Duration: ${result.duration}ms`);
    lines.push(`Console errors: ${result.consoleErrors.length}`);
    lines.push(`Network errors: ${result.networkErrors.length}`);
    lines.push(`Uncaught exceptions: ${result.uncaughtExceptions.length}`);
    if (result.screenshots.length > 0) {
      lines.push(`Screenshots: ${result.screenshots.join(", ")}`);
    }
    lines.push("");

    if (result.consoleErrors.length > 0) {
      lines.push("Console Errors:");
      for (const err of result.consoleErrors) {
        lines.push(`  ${err.timestamp}: ${err.message.substring(0, 200)}`);
      }
      lines.push("");
    }

    if (result.networkErrors.length > 0) {
      lines.push("Network Errors:");
      for (const err of result.networkErrors) {
        const statusInfo = err.status ? ` (${err.status})` : "";
        lines.push(`  ${err.timestamp}: ${err.method || "?"} ${err.url || "N/A"}${statusInfo} — ${err.message.substring(0, 200)}`);
      }
      lines.push("");
    }

    if (result.uncaughtExceptions.length > 0) {
      lines.push("Uncaught Exceptions:");
      for (const err of result.uncaughtExceptions) {
        lines.push(`  ${err.timestamp}: ${err.message.substring(0, 200)}`);
        if (err.stack) {
          const stackLines = err.stack.split("\n").slice(0, 3);
          for (const line of stackLines) {
            lines.push(`    ${line.substring(0, 200)}`);
          }
        }
      }
      lines.push("");
    }

    if (result.transcript.length > 0) {
      lines.push("Transcript (last 4 entries):");
      const lastFour = result.transcript.slice(-4);
      for (const entry of lastFour) {
        lines.push(`  [${entry.speaker}]: ${entry.text.substring(0, 200)}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

function formatSuccessEmail(
  results: PersonaResult[],
  visualResults: VisualCheckResult[],
  runTime: string,
): string {
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const totalDuration = results.reduce((sum, r) => sum + r.duration, 0);
  const durationSec = Math.round(totalDuration / 1000);

  const lines: string[] = [
    "Examy QA Daily Report — All Passed",
    "========================================================================",
    "",
    `Run time: ${runTime}`,
    `Duration: ${durationSec}s`,
    `Personas tested: ${total}`,
    `Passed: ${passed}`,
    "",
  ];

  for (const result of results) {
    const interactions = result.transcript.filter((t) => t.speaker !== "Examy").length;
    lines.push(`  ${result.persona}: PASS (${result.duration}ms, ${interactions} interactions)`);
  }

  lines.push("");

  // Visual regression summary
  if (visualResults.length > 0) {
    const visualPassed = visualResults.filter((v) => v.passed || v.isNewBaseline).length;
    lines.push(`Visual regression: ${visualPassed}/${visualResults.length} OK`);
  } else {
    lines.push("Visual regression: not run");
  }

  return lines.join("\n");
}

function categorizeError(error: { type: "console" | "network" | "exception" | "visual"; message: string }): {
  category: string;
  label: string;
} {
  switch (error.type) {
    case "console": return { category: "JS Console Error", label: "js-error" };
    case "exception": return { category: "JS Exception", label: "js-error" };
    case "network": return { category: "Network Error", label: "network-error" };
    case "visual": return { category: "Visual Regression", label: "visual-regression" };
  }
}

function formatIssueBody(
  error: { type: "console" | "network" | "exception" | "visual"; message: string; details: Record<string, unknown> },
  errorHash: string,
): string {
  const cat = categorizeError(error);
  const timestamp = (error.details.timestamp as string) || new Date().toISOString();
  const url = (error.details.url as string) || "N/A";
  const persona = (error.details.persona as string) || "Unknown";
  const stack = (error.details.stack as string) || "No stack trace available";

  const lines = [
    `<!-- lobsec-qa-hash:${errorHash} -->`,
    "",
    "## Error Details",
    "",
    `**Type:** ${cat.category}`,
    `**Error:** ${error.message}`,
    `**Page URL:** ${url}`,
    `**Persona:** ${persona}`,
    `**Timestamp:** ${timestamp}`,
    "",
    "## Stack Trace",
    "",
    "```",
    stack,
    "```",
    "",
    "## Reproduction",
    "",
    "This error was detected by lobsec automated QA testing.",
    `Persona: ${persona}`,
    "",
    "---",
    `*Auto-created by lobsec QA. Error hash: ${errorHash}*`,
  ];

  return lines.join("\n");
}

async function ensureLabels(labels: string[], config: GitHubConfig): Promise<void> {
  for (const label of labels) {
    try {
      await githubAction({
        action: "create_label",
        repo: EXAMY_REPO,
        name: label,
      }, config);
    } catch (err) {
      console.error(`[examy] Failed to ensure label ${label}:`, err);
    }
  }
}

async function reconcileGitHubIssues(
  errors: Array<{ type: "console" | "network" | "exception" | "visual"; message: string; details: Record<string, unknown> }>,
  config: GitHubConfig,
): Promise<{ created: number[]; closed: number[]; existing: number[] }> {
  const created: number[] = [];
  const closed: number[] = [];
  const existing: number[] = [];

  try {
    // Collect current error hashes
    const currentHashes = new Set<string>();
    const errorsByHash = new Map<string, typeof errors[0]>();

    for (const error of errors) {
      const hash = hashError(error.message);
      currentHashes.add(hash);
      if (!errorsByHash.has(hash)) {
        errorsByHash.set(hash, error);
      }
    }

    // Search all open lobsec-qa issues
    const openIssuesResult = await githubAction({
      action: "search_issues",
      query: `repo:${EXAMY_REPO} is:issue is:open [lobsec-qa] in:title`,
    }, config);

    const openIssues = (openIssuesResult.data as { items: Array<{ number: number; body?: string }> }).items || [];

    // Auto-close resolved issues
    for (const issue of openIssues) {
      const body = issue.body || "";
      const hashMatch = body.match(/lobsec-qa-hash:([a-f0-9]{32})/);
      if (hashMatch && hashMatch[1]) {
        const issueHash = hashMatch[1];
        if (!currentHashes.has(issueHash)) {
          // Issue's error is not in current results — close it
          try {
            await githubAction({
              action: "close_issue",
              repo: EXAMY_REPO,
              issue_number: issue.number,
              comment: `Automatically closed: error no longer detected in QA test run ${new Date().toISOString()}`,
            }, config);
            closed.push(issue.number);
          } catch (closeErr) {
            console.error(`[examy] Failed to close issue #${issue.number}:`, closeErr);
          }
        }
      }
    }

    // Create issues for new errors
    for (const [hash, error] of errorsByHash.entries()) {
      try {
        // Check if issue already exists for this hash
        const searchResult = await githubAction({
          action: "search_issues",
          query: `repo:${EXAMY_REPO} is:issue is:open ${hash} in:body`,
        }, config);

        const existingIssues = (searchResult.data as { items: Array<{ number: number }> }).items || [];
        if (existingIssues.length > 0 && existingIssues[0]) {
          existing.push(existingIssues[0].number);
          continue;
        }

        // Create new issue
        const cat = categorizeError(error);
        const title = `[lobsec-qa] ${cat.category}: ${error.message.substring(0, 80)}`;
        const body = formatIssueBody(error, hash);
        const labels = ["lobsec-qa", cat.label];

        // Ensure labels exist
        await ensureLabels(labels, config);

        const createResult = await githubAction({
          action: "create_issue",
          repo: EXAMY_REPO,
          title,
          body,
          labels,
        }, config);

        const issueNumber = (createResult.data as { number: number }).number;
        created.push(issueNumber);
      } catch (createErr) {
        console.error(`[examy] Failed to create issue for hash ${hash}:`, createErr);
      }
    }
  } catch (err) {
    console.error("[examy] Error in reconcileGitHubIssues:", err);
  }

  return { created, closed, existing };
}

async function sendTelegramNotification(
  results: PersonaResult[],
  visualResults: VisualCheckResult[],
): Promise<boolean> {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    console.warn("[examy] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID, skipping Telegram notification");
    return false;
  }

  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;
  const totalDuration = results.reduce((sum, r) => sum + r.duration, 0);
  const durationSec = Math.round(totalDuration / 1000);

  const visualFailed = visualResults.filter((v) => !v.passed && !v.isNewBaseline);
  const visualOk = visualResults.length - visualFailed.length;

  let text: string;
  if (failed === 0 && visualFailed.length === 0) {
    const visualPart = visualResults.length > 0 ? ` | ${visualOk} visual OK` : "";
    text = `Examy QA: ${total} personas PASS (${durationSec}s)${visualPart}`;
  } else {
    const jsErrors = results.reduce((sum, r) => sum + r.consoleErrors.length + r.uncaughtExceptions.length, 0);
    const netErrors = results.reduce((sum, r) => sum + r.networkErrors.length, 0);
    const parts = [`Examy QA: ${failed}/${total} FAIL`];
    if (jsErrors > 0) parts.push(`${jsErrors} JS errors`);
    if (netErrors > 0) parts.push(`${netErrors} network errors`);
    if (visualFailed.length > 0) parts.push(`${visualFailed.length} visual regression`);
    text = parts.join(" | ");
  }

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text }),
  });

  if (!resp.ok) {
    const body = await resp.text();
    console.error(`[examy] Telegram API error ${resp.status}: ${body}`);
    return false;
  }

  console.log("[examy] Telegram sent");
  return true;
}

async function reportResults(
  results: PersonaResult[],
  visualResults: VisualCheckResult[],
): Promise<{ emailSent: boolean; telegramSent: boolean; issuesCreated: number[]; issuesClosed: number[]; issuesExisting: number[] }> {
  let emailSent = false;
  let telegramSent = false;
  let issuesCreated: number[] = [];
  let issuesClosed: number[] = [];
  let issuesExisting: number[] = [];

  try {
    // Check if any failures occurred
    const hasFailures = results.some((r) => !r.passed) || visualResults.some((v) => !v.passed && !v.isNewBaseline);

    // Collect all errors from all personas
    const errors: Array<{ type: "console" | "network" | "exception" | "visual"; message: string; details: Record<string, unknown> }> = [];

    for (const result of results) {
      // Console errors
      for (const err of result.consoleErrors) {
        errors.push({
          type: "console",
          message: err.message,
          details: {
            timestamp: err.timestamp,
            url: err.url || "",
            persona: result.persona,
          },
        });
      }

      // Network errors
      for (const err of result.networkErrors) {
        errors.push({
          type: "network",
          message: err.message,
          details: {
            timestamp: err.timestamp,
            url: err.url || "",
            method: err.method || "",
            status: err.status,
            persona: result.persona,
          },
        });
      }

      // Uncaught exceptions
      for (const err of result.uncaughtExceptions) {
        errors.push({
          type: "exception",
          message: err.message,
          details: {
            timestamp: err.timestamp,
            stack: err.stack || "",
            persona: result.persona,
          },
        });
      }
    }

    // Visual regression failures
    for (const vr of visualResults) {
      if (!vr.passed && !vr.isNewBaseline) {
        errors.push({
          type: "visual",
          message: `Visual regression on ${vr.name}: ${vr.diffPercent.toFixed(2)}% difference`,
          details: {
            timestamp: new Date().toISOString(),
            diffPercent: vr.diffPercent,
            diffPath: vr.diffPath || "",
            persona: "visual-regression",
          },
        });
      }
    }

    // Get GitHub config
    const gitConfig: GitHubConfig = {
      pat: process.env.GITHUB_PAT || "",
      user: process.env.GITHUB_USER || "lobsec",
    };

    // Reconcile GitHub issues (always run, even on success, to auto-close)
    if (gitConfig.pat) {
      try {
        const issueResult = await reconcileGitHubIssues(errors, gitConfig);
        issuesCreated = issueResult.created;
        issuesClosed = issueResult.closed;
        issuesExisting = issueResult.existing;
      } catch (issueErr) {
        console.error("[examy] GitHub issue reconciliation failed:", issueErr);
      }
    } else {
      console.warn("[examy] No GITHUB_PAT found, skipping GitHub issue creation");
    }

    // Always send email (success or failure)
    const recipients = loadRecipients();
    if (recipients.length > 0) {
      try {
        const emailConfig: EmailConfig = {
          user: process.env.GMAIL_USER || "",
          appPassword: process.env.GMAIL_APP_PASSWORD || "",
        };

        if (emailConfig.user && emailConfig.appPassword) {
          const runTime = new Date().toISOString();
          const emailBody = hasFailures
            ? formatFailureEmail(results, visualResults, runTime)
            : formatSuccessEmail(results, visualResults, runTime);
          const subject = hasFailures
            ? `[Examy QA] Test Failure - ${errors.length} errors detected`
            : "[Examy QA] Daily Report - All Passed";
          await sendEmail({
            to: recipients.join(", "),
            subject,
            body: emailBody,
            html: false,
          }, emailConfig);
          emailSent = true;
          console.log("[examy] Email sent");
        } else {
          console.warn("[examy] No email credentials found, skipping email notification");
        }
      } catch (emailErr) {
        console.error("[examy] Email notification failed:", emailErr);
      }
    } else {
      console.warn("[examy] No email recipients configured");
    }

    // Telegram notification (non-blocking)
    try {
      telegramSent = await sendTelegramNotification(results, visualResults);
    } catch (telegramErr) {
      console.error("[examy] Telegram notification failed:", telegramErr);
    }
  } catch (err) {
    console.error("[examy] Error in reportResults:", err);
  }

  return { emailSent, telegramSent, issuesCreated, issuesClosed, issuesExisting };
}

// ── Error Collection ────────────────────────────────────────────────────────

export function attachErrorListeners(page: Page): ErrorCollector {
  const collector: ErrorCollector = {
    consoleErrors: [],
    uncaughtExceptions: [],
    networkErrors: [],
  };

  // Console errors only (not warnings or info)
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      const text = msg.text();
      // Filter out known noise patterns
      if (!IGNORE_PATTERNS.some((pattern) => pattern.test(text))) {
        collector.consoleErrors.push({
          timestamp: new Date().toISOString(),
          message: text,
          url: msg.location().url,
        });
      }
    }
  });

  // Uncaught JavaScript exceptions (these ARE bugs)
  page.on("pageerror", (error) => {
    collector.uncaughtExceptions.push({
      timestamp: new Date().toISOString(),
      message: error.message,
      stack: error.stack,
    });
  });

  // Network failures
  page.on("requestfailed", (request) => {
    const failure = request.failure();
    collector.networkErrors.push({
      timestamp: new Date().toISOString(),
      message: failure?.errorText || "Request failed",
      url: request.url(),
      method: request.method(),
    });
  });

  return collector;
}

// ── Login ───────────────────────────────────────────────────────────────────

export async function login(page: Page, username: string, password: string): Promise<boolean> {
  try {
    // Navigate directly to Examy login page (SPA hash route)
    await page.goto(`${TARGET_URL}/#/entrar`, { timeout: 30000, waitUntil: "networkidle" });

    // Wait for login form to render
    await page.waitForSelector("#username", { timeout: 10000 });

    // Fill credentials using known element IDs
    await page.fill("#username", username);
    await page.fill("#password", password);

    // Click the Log in button
    await page.click('button:has-text("Log in")');
    await page.waitForLoadState("networkidle", { timeout: 30000 });

    // Wait for dashboard to appear (URL changes to /#/dashboard on success)
    // Also check for post-login UI elements (Portuguese: Dashboard, Sessões, Progresso)
    const loggedInIndicators = [
      'text=Dashboard',
      'text=Sessões',
      'text=Progresso',
      'text=Iniciar nova sessão',
    ];

    // Give SPA time to route after login
    await page.waitForTimeout(2000);

    let isLoggedIn = false;
    for (const selector of loggedInIndicators) {
      const count = await page.locator(selector).count();
      if (count > 0) {
        isLoggedIn = true;
        break;
      }
    }

    // Fallback: check URL for dashboard route
    if (!isLoggedIn && page.url().includes("/dashboard")) {
      isLoggedIn = true;
    }

    return isLoggedIn;
  } catch (error) {
    console.error("[examy] Login error:", error);
    return false;
  }
}

// ── Screenshot Capture ──────────────────────────────────────────────────────

export async function captureFailureScreenshot(
  page: Page,
  personaId: string,
  label: string,
): Promise<string> {
  const timestamp = new Date().toISOString().replace(/:/g, "-").replace(/\..+/, "");
  const filename = `${personaId}-${label}-${timestamp}.png`;
  const path = `${SCREENSHOT_DIR}/${filename}`;

  // Ensure directory exists
  mkdirSync(SCREENSHOT_DIR, { recursive: true });

  // Mask password field on login page to prevent credential exposure in screenshots
  const url = page.url();
  const isLoginPage = url.includes("/entrar") || url.includes("/login") || url === TARGET_URL + "/" || url === TARGET_URL;
  const maskLocators = isLoginPage ? [page.locator('input[type="password"]')] : [];

  await page.screenshot({ path, fullPage: true, mask: maskLocators });
  return path;
}

// ── Result Formatting ───────────────────────────────────────────────────────

export function formatSummary(
  results: PersonaResult[],
  visualResults?: VisualCheckResult[],
  reporting?: { emailSent: boolean; telegramSent: boolean; issuesCreated: number[]; issuesClosed: number[]; issuesExisting: number[] },
): string {
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;

  const totalConsoleErrors = results.reduce((sum, r) => sum + r.consoleErrors.length, 0);
  const totalNetworkErrors = results.reduce((sum, r) => sum + r.networkErrors.length, 0);

  const lines = [
    `${total} personas tested. ${passed} passed, ${failed} failed. ${totalConsoleErrors} JS errors, ${totalNetworkErrors} network errors.`,
  ];

  for (const result of results) {
    const status = result.passed ? "PASS" : "FAIL";
    const interactions = result.transcript.filter((t) => t.speaker !== "Examy").length;
    lines.push(
      `${result.persona}: ${status} (${result.duration}ms, ${interactions} interactions)`,
    );
  }

  if (visualResults && visualResults.length > 0) {
    const visualPassed = visualResults.filter((v) => v.passed || v.isNewBaseline).length;
    const visualFailed = visualResults.length - visualPassed;
    lines.push(`Visual regression: ${visualPassed} passed, ${visualFailed} failed`);
  }

  if (reporting) {
    if (reporting.emailSent) {
      lines.push("Email notification sent");
    }
    if (reporting.telegramSent) {
      lines.push("Telegram notification sent");
    }
    if (reporting.issuesCreated.length > 0) {
      lines.push(`GitHub issues created: ${reporting.issuesCreated.length}`);
    }
    if (reporting.issuesClosed.length > 0) {
      lines.push(`GitHub issues closed: ${reporting.issuesClosed.length}`);
    }
  }

  return lines.join("\n");
}

// ── Study Session ───────────────────────────────────────────────────────────

async function runStudySession(
  page: Page,
  persona: PersonaConfig,
  client: Anthropic,
  collector: ErrorCollector,
): Promise<TranscriptEntry[]> {
  const transcript: TranscriptEntry[] = [];
  const sessionStartTime = Date.now();

  try {
    // Navigate to study area (PT: Praticar / Iniciar nova sessão, EN: Study / Practice)
    const studySelectors = [
      'button:has-text("Iniciar nova sessão")',
      'text=Praticar',
      'a:has-text("Praticar")',
      'text=Study',
      'a[href*="study" i]',
      'button:has-text("Study")',
      'button:has-text("Practice")',
      '[data-testid*="study" i]',
      '[data-testid*="practice" i]',
    ];

    let studyClicked = false;
    for (const selector of studySelectors) {
      const element = page.locator(selector).first();
      if (await element.count() > 0) {
        await element.scrollIntoViewIfNeeded();
        try {
          await element.click({ timeout: 5000 });
        } catch {
          // Navbar may intercept pointer events — force click
          await element.click({ force: true });
        }
        studyClicked = true;
        break;
      }
    }

    if (!studyClicked) {
      console.error("[examy] Could not find Study button/link");
      return transcript;
    }

    await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {
      console.log("[examy] Networkidle timeout after Study click (non-fatal)");
    });
    // Wait for SPA to render subject selection UI
    await page.waitForTimeout(3000);

    // Pick subject and start session
    // Examy's "Nova Sessão" page has suggestion cards (button.suggestion-card)
    // and a manual flow (topic textarea + discipline grid + "Criar Sessão" button).
    // Try suggestion cards first (one-click start), then fall back to manual flow.
    // Wait for suggestion cards or discipline elements to appear
    await page.locator("button.suggestion-card, [class*='discipline' i], [class*='disciplina' i]")
      .first().waitFor({ timeout: 10000 }).catch(() => {
        console.log("[examy] No subject UI detected after 10s, proceeding with fallback");
      });

    const suggestionCard = page.locator("button.suggestion-card").first();
    let subjectClicked = false;

    if (await suggestionCard.count() > 0) {
      await suggestionCard.scrollIntoViewIfNeeded();
      try {
        await suggestionCard.click({ timeout: 5000 });
      } catch {
        await suggestionCard.click({ force: true });
      }
      subjectClicked = true;
      console.log("[examy] Clicked suggestion card");
    }

    if (!subjectClicked) {
      // Fallback: manual flow — select a discipline card + click "Criar Sessão"
      const disciplineCard = page.locator('[class*="discipline" i], [class*="disciplina" i], .subject-card').first();
      if (await disciplineCard.count() > 0) {
        await disciplineCard.scrollIntoViewIfNeeded();
        await disciplineCard.click({ force: true });
        subjectClicked = true;
        console.log("[examy] Clicked discipline card (fallback)");
      }
    }

    if (!subjectClicked) {
      console.error("[examy] Could not find subject/course to start");
      return transcript;
    }

    await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {
      console.log("[examy] Networkidle timeout after subject selection (non-fatal)");
    });

    // If "Criar Sessão" button appears, click it to start the session
    const criarSessao = page.locator('button:has-text("Criar Sessão"), button:has-text("Create Session")').first();
    if (await criarSessao.count() > 0) {
      await criarSessao.scrollIntoViewIfNeeded();
      try {
        await criarSessao.click({ timeout: 5000 });
      } catch {
        await criarSessao.click({ force: true });
      }
      console.log("[examy] Clicked Criar Sessão");
      await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
    }

    // Wait for tutor chat UI to appear (textarea, chat messages, or input field)
    await page.locator('textarea, .chat-message, .tutor-message, [class*="chat" i], [class*="message" i], [contenteditable="true"]')
      .first().waitFor({ timeout: 15000 }).catch(() => {
        console.log("[examy] Chat UI not detected after 15s, proceeding anyway");
      });
    await page.waitForTimeout(2000);

    // Main interaction loop
    let consecutiveNoQuestion = 0;
    const maxNoQuestionRetries = 5;

    while (Date.now() - sessionStartTime < TIMEOUT_MS) {
      try {
        // Step A: Extract Examy's question via DOM
        const questionSelectors = [
          '[data-testid*="tutor" i]',
          '[data-testid*="question" i]',
          '.tutor-message:last-child',
          '.question-text',
          '.chat-message:last-child',
          '[class*="tutor" i]:last-child',
          '[class*="question" i]',
        ];

        let examyQuestion = "";
        for (const selector of questionSelectors) {
          const element = page.locator(selector).first();
          if (await element.count() > 0) {
            const text = await element.textContent();
            if (text?.trim()) {
              examyQuestion = text.trim();
              break;
            }
          }
        }

        // Step B: Vision fallback if DOM extraction returns empty
        if (!examyQuestion) {
          try {
            const screenshot = await page.screenshot({ type: "png" });
            const visionResponse = await client.messages.create({
              model: "claude-haiku-4-5-20251001",
              max_tokens: 150,
              messages: [
                {
                  role: "user",
                  content: [
                    {
                      type: "image",
                      source: {
                        type: "base64",
                        media_type: "image/png",
                        data: screenshot.toString("base64"),
                      },
                    },
                    {
                      type: "text",
                      text: 'Extract the tutor\'s current question or prompt from this screenshot. The UI may be in Portuguese or English. Return ONLY the question text (in whatever language it appears). If there is no question visible, respond with "NO_QUESTION".',
                    },
                  ],
                },
              ],
            });

            const visionText = visionResponse.content[0]?.type === "text"
              ? visionResponse.content[0].text.trim()
              : "";

            if (visionText && visionText !== "NO_QUESTION") {
              examyQuestion = visionText;
            }
          } catch (visionError) {
            console.error("[examy] Vision fallback failed:", visionError);
            // Continue with empty question to trigger session end check
          }
        }

        // Step C: Check if session ended (PT + EN)
        if (!examyQuestion) {
          const sessionEndSelectors = [
            'text=Congratulations', 'text=Session complete', 'text=Great job',
            'text=Well done', 'text=Finished',
            'text=Parabéns', 'text=Sessão completa', 'text=Muito bem',
            'text=Bom trabalho', 'text=Terminado', 'text=Concluído',
          ];
          let sessionEnded = false;
          for (const sel of sessionEndSelectors) {
            if (await page.locator(sel).count() > 0) {
              sessionEnded = true;
              break;
            }
          }

          if (sessionEnded) {
            console.log("[examy] Session completed successfully");
            break;
          }

          consecutiveNoQuestion++;
          if (consecutiveNoQuestion >= maxNoQuestionRetries) {
            console.log("[examy] Too many consecutive 'no question' iterations, ending session");
            break;
          }

          // Wait a bit for question to appear
          await page.waitForTimeout(2000);
          continue;
        }

        // Reset no-question counter when we successfully extract a question
        consecutiveNoQuestion = 0;

        // Step D: Record Examy's question in transcript
        transcript.push({
          speaker: "Examy",
          text: examyQuestion,
          timestamp: new Date().toISOString(),
        });

        // Step E: Generate student response via Claude Haiku
        const gradeAge = persona.grade + 6;
        const sentenceGuidance =
          persona.grade < 6
            ? "1-2 sentences"
            : persona.grade < 10
              ? "2-3 sentences"
              : "2-4 sentences";

        let systemPrompt = `You are ${persona.name}, a Grade ${persona.grade} student (age ${gradeAge}).
${persona.personality}
Answer the tutor's question naturally as this student would.
The tutor may speak Portuguese or English — always reply in the SAME language as the question.
Keep answers ${sentenceGuidance}.
Do NOT break character. Do NOT mention you are an AI.`;

        // Apply error rate
        if (Math.random() < persona.errorRate) {
          systemPrompt +=
            "\n\nIMPORTANT: Give a partially incorrect answer or show confusion about the concept. Make a realistic mistake a student of this grade might make.";
        }

        let studentAnswer = "";
        try {
          const response = await client.messages.create({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 200,
            system: systemPrompt,
            messages: [{ role: "user", content: examyQuestion }],
          });

          studentAnswer =
            response.content[0]?.type === "text" ? response.content[0].text.trim() : "";
        } catch (apiError) {
          console.error("[examy] Claude API error:", apiError);
          // Add to network errors
          collector.networkErrors.push({
            timestamp: new Date().toISOString(),
            message: `Claude API call failed: ${apiError instanceof Error ? apiError.message : String(apiError)}`,
          });
          // Skip this interaction
          await page.waitForTimeout(2000);
          continue;
        }

        if (!studentAnswer) {
          console.error("[examy] Empty student response from Claude");
          await page.waitForTimeout(2000);
          continue;
        }

        // Step F: Record student answer in transcript
        transcript.push({
          speaker: persona.name,
          text: studentAnswer,
          timestamp: new Date().toISOString(),
        });

        // Step G: Natural pacing delay (2-5 seconds)
        const delay = 2000 + Math.random() * 3000;
        await page.waitForTimeout(delay);

        // Step H: Detect input type and interact
        const hasTextInput =
          (await page.locator('textarea, input[type="text"], [contenteditable="true"]').count()) > 0;

        if (hasTextInput) {
          // Text input detected — use clear + pressSequentially to trigger Vue/React input events
          const inputLocator =
            (await page.locator("textarea").count()) > 0 ? page.locator("textarea").first()
            : (await page.locator('input[type="text"]').count()) > 0 ? page.locator('input[type="text"]').first()
            : page.locator('[contenteditable="true"]').first();

          await inputLocator.click();
          await inputLocator.fill("");
          await inputLocator.pressSequentially(studentAnswer, { delay: 30 });

          // Wait for the app to react to input (enable submit button, etc.)
          await page.waitForTimeout(500);

          // Click submit (PT: Enviar/Responder/Próximo, EN: Submit/Send/Answer/Next)
          const submitSelectors = [
            'button[type="submit"]',
            'button:has-text("Enviar")',
            'button:has-text("Responder")',
            'button:has-text("Próximo")',
            'button:has-text("Confirmar")',
            'button:has-text("Submit")',
            'button:has-text("Send")',
            'button:has-text("Answer")',
            'button:has-text("Next")',
          ];

          let submitted = false;
          for (const selector of submitSelectors) {
            const button = page.locator(selector).first();
            if (await button.count() > 0) {
              try {
                await button.click({ timeout: 5000 });
              } catch {
                // Button may be disabled — try force click or Enter
                await button.click({ force: true });
              }
              submitted = true;
              break;
            }
          }

          if (!submitted) {
            console.error("[examy] Could not find submit button");
            // Try pressing Enter as fallback
            await page.keyboard.press("Enter");
          }
        } else {
          // Multiple choice - get all options
          const optionSelectors = [
            'button[role="option"]',
            '.choice-button',
            '[class*="option" i]',
            '[class*="choice" i]',
            '[role="radio"]',
          ];

          let optionClicked = false;
          for (const selector of optionSelectors) {
            const options = page.locator(selector);
            const count = await options.count();
            if (count > 0) {
              // For Phase 2 simplification, just pick the first option
              // Phase 3+ could ask Claude to analyze options and pick best match
              await options.first().click();
              optionClicked = true;
              break;
            }
          }

          if (!optionClicked) {
            console.error("[examy] Could not find multiple choice options");
            await page.waitForTimeout(2000);
            continue;
          }
        }

        // Wait for networkidle after interaction
        await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {
          console.log("[examy] Networkidle timeout after answer submission (non-fatal)");
        });

        // Step I: Wait for next question to appear
        await page.waitForTimeout(1000);
      } catch (loopError) {
        console.error("[examy] Error in study session loop:", loopError);
        // Continue to next iteration
        await page.waitForTimeout(2000);

        // Check if page crashed
        if (page.isClosed()) {
          console.error("[examy] Page closed unexpectedly");
          break;
        }
      }
    }

    if (Date.now() - sessionStartTime >= TIMEOUT_MS) {
      console.log("[examy] Study session reached 10-minute timeout");
    }
  } catch (error) {
    console.error("[examy] Study session error:", error);
  }

  return transcript;
}

// ── Per-Persona Test Execution ─────────────────────────────────────────────

export async function runPersonaTest(
  persona: PersonaConfig,
  config: TestConfig,
): Promise<PersonaResult> {
  const startTime = Date.now();
  let browser: Browser | null = null;

  const result: PersonaResult = {
    persona: persona.id,
    passed: false,
    transcript: [],
    consoleErrors: [],
    networkErrors: [],
    uncaughtExceptions: [],
    screenshots: [],
    duration: 0,
  };

  try {
    // ProtectSystem=strict makes /tmp read-only; redirect Playwright temp files
    process.env.TMPDIR = "/opt/lobsec/logs/examy";

    // Launch browser — explicit executablePath because ESM hoists imports before
    // any module-level process.env assignment, so PLAYWRIGHT_BROWSERS_PATH won't work
    browser = await chromium.launch({
      executablePath: "/opt/lobsec/browsers/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell",
      headless: true,
      args: [
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-software-rasterizer",
        "--no-sandbox",
        "--disable-crashpad",
        "--disable-crash-reporter",
        "--crash-dumps-dir=/opt/lobsec/logs/examy",
      ],
    });

    const page = await browser.newPage();

    // Attach error listeners BEFORE navigation
    const collector = attachErrorListeners(page);

    // Resolve credentials (persona-specific or shared from config)
    const username = persona.username || config.username;
    const password = persona.password || config.password;

    // Attempt login
    const loginSuccess = await login(page, username, password);

    if (!loginSuccess) {
      console.error(`[examy] Login failed for persona ${persona.id}`);
      const screenshot = await captureFailureScreenshot(page, persona.id, "login-failed");
      result.screenshots.push(screenshot);
      result.duration = Date.now() - startTime;
      return result;
    }

    // Create Anthropic client with proxy
    const client = new Anthropic({
      apiKey: config.anthropicApiKey,
      baseURL: config.proxyBaseUrl,
      // Note: For self-signed proxy cert, NODE_TLS_REJECT_UNAUTHORIZED=0 is set at runtime
    });

    // Run study session
    result.transcript = await runStudySession(page, persona, client, collector);

    // Copy errors from collector
    result.consoleErrors = collector.consoleErrors;
    result.networkErrors = collector.networkErrors;
    result.uncaughtExceptions = collector.uncaughtExceptions;

    // Determine pass/fail: must have interactions, no uncaught exceptions, no 5xx errors
    const has5xxErrors = collector.networkErrors.some(
      (e) => e.status && e.status >= 500,
    );
    const interactions = result.transcript.filter((t) => t.speaker !== "Examy").length;
    if (interactions === 0) {
      console.error("[examy] No interactions recorded — marking as FAIL");
    }
    result.passed = interactions > 0 && collector.uncaughtExceptions.length === 0 && !has5xxErrors;

    result.duration = Date.now() - startTime;
  } catch (error) {
    console.error(`[examy] Test error for persona ${persona.id}:`, error);

    // Capture failure screenshot if page is still open
    if (browser) {
      try {
        const context = browser.contexts()[0];
        if (context) {
          const pages = await context.pages();
          const page = pages[0];
          if (page) {
            const screenshot = await captureFailureScreenshot(page, persona.id, "error");
            result.screenshots.push(screenshot);
          }
        }
      } catch (screenshotError) {
        console.error("[examy] Failed to capture error screenshot:", screenshotError);
      }
    }

    result.uncaughtExceptions.push({
      timestamp: new Date().toISOString(),
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });

    result.duration = Date.now() - startTime;
  } finally {
    // ALWAYS close browser to prevent zombies
    if (browser) {
      await browser.close();
    }
  }

  return result;
}

// ── Main Test Orchestration ────────────────────────────────────────────────

export async function runExamyTest(
  personaFilter: string | undefined,
  resultPath: string,
  updateBaselines: boolean = false,
): Promise<void> {
  const startTime = new Date().toISOString();

  // Load personas
  const allPersonas = loadPersonas();
  const selectedPersonas = personaFilter
    ? allPersonas.filter((p) => p.id === personaFilter)
    : allPersonas;

  if (selectedPersonas.length === 0) {
    throw new Error(`No personas found matching filter: ${personaFilter}`);
  }

  // Create test config from env vars
  const config: TestConfig = {
    username: process.env.EXAMY_USERNAME || "",
    password: process.env.EXAMY_PASSWORD || "",
    anthropicApiKey: process.env.ANTHROPIC_API_KEY || process.env.OPENCLAW_GATEWAY_TOKEN || "",
    proxyBaseUrl: "https://127.0.0.1:18790",
  };

  if (!config.username || !config.password) {
    throw new Error("Missing EXAMY_USERNAME or EXAMY_PASSWORD environment variables");
  }
  if (!config.anthropicApiKey) {
    throw new Error("Missing ANTHROPIC_API_KEY environment variable");
  }

  // Run personas sequentially
  const results: PersonaResult[] = [];

  for (const persona of selectedPersonas) {
    try {
      console.log(`[examy] Starting test for persona: ${persona.id}`);
      const result = await runPersonaTest(persona, config);
      results.push(result);
      console.log(`[examy] Completed test for persona: ${persona.id} (${result.passed ? "PASS" : "FAIL"})`);
    } catch (error) {
      console.error(`[examy] Failed to run test for persona ${persona.id}:`, error);
      // Continue with remaining personas even if one fails
      results.push({
        persona: persona.id,
        passed: false,
        transcript: [],
        consoleErrors: [],
        networkErrors: [],
        uncaughtExceptions: [{
          timestamp: new Date().toISOString(),
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        }],
        screenshots: [],
        duration: 0,
      });
    }
  }

  // Visual regression check
  let visualResults: VisualCheckResult[] = [];
  try {
    console.log("[examy] Running visual regression checks...");
    // Launch a separate browser for visual regression
    process.env.TMPDIR = "/opt/lobsec/logs/examy";
    const visualBrowser = await chromium.launch({
      executablePath: "/opt/lobsec/browsers/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell",
      headless: true,
      args: [
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-software-rasterizer",
        "--no-sandbox",
        "--disable-crashpad",
        "--disable-crash-reporter",
        "--crash-dumps-dir=/opt/lobsec/logs/examy",
      ],
    });

    const visualPage = await visualBrowser.newPage();

    // Login for visual regression
    const loginSuccess = await login(visualPage, config.username, config.password);
    if (loginSuccess) {
      visualResults = await compareVisualBaselines(visualPage, updateBaselines);
      console.log(`[examy] Visual regression checks complete: ${visualResults.length} checkpoints`);
    } else {
      console.warn("[examy] Visual regression skipped: login failed");
    }

    await visualBrowser.close();
  } catch (visualError) {
    console.error("[examy] Visual regression error:", visualError);
    // Continue without visual results
  }

  // Reporting pipeline
  const reporting = await reportResults(results, visualResults);

  // Build final result
  const testResult: TestResult = {
    status: "complete",
    startTime,
    endTime: new Date().toISOString(),
    results,
    summary: formatSummary(results, visualResults, reporting),
    resultPath,
    visualRegression: visualResults.length > 0 ? visualResults : undefined,
    reporting,
  };

  // Write results to file
  mkdirSync(dirname(resultPath), { recursive: true });

  // Sanitize credentials before writing results to disk (all from env vars, never hardcoded)
  const resultJson = JSON.stringify(testResult, null, 2);
  const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  let sanitizedJson = resultJson;
  const sensitiveEnvVars: [string | undefined, string][] = [
    [process.env.EXAMY_PASSWORD, "[EXAMY-PASSWORD-REDACTED]"],
    [process.env.GMAIL_USER, "[EMAIL-REDACTED]"],
    [process.env.GITHUB_PAT, "[GITHUB-PAT-REDACTED]"],
    [process.env.GMAIL_APP_PASSWORD, "[GMAIL-PASSWORD-REDACTED]"],
    [process.env.EXAMY_USERNAME, "[EXAMY-USERNAME-REDACTED]"],
  ];
  for (const [value, replacement] of sensitiveEnvVars) {
    if (value) {
      sanitizedJson = sanitizedJson.replace(new RegExp(escapeRe(value), "g"), replacement);
    }
  }
  writeFileSync(resultPath, sanitizedJson);

  console.log(`[examy] Test complete. Results written to ${resultPath}`);
}
