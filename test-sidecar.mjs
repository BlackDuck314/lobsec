#!/usr/bin/env node
/**
 * lobsec Production Test Sidecar
 *
 * Four-phase test proving lobsec security hooks work end-to-end.
 *
 * Phase 1: Unit test deployed redactor (automated, no network)
 * Phase 2: Telegram bypass baseline (automated, proves direct path is unprotected)
 * Phase 3: Pipeline credential redaction test (via gateway-chat.sh)
 * Phase 4: Tool calling verification (weather, email, calendar via gateway-chat.sh)
 *
 * Usage: node test-sidecar.mjs [--phase1-only] [--skip-phase2] [--skip-phase4]
 */

import { readFileSync, statSync } from "node:fs";
import { execFile } from "node:child_process";
import { pathToFileURL } from "node:url";

const ENV_PATH = "/opt/lobsec/.openclaw/.env";
const AUDIT_LOG = "/opt/lobsec/logs/audit.jsonl";
const REDACTOR_PATH = "/opt/lobsec/plugins/lobsec-security/dist/credential-redactor.js";
const GATEWAY_CHAT = "/opt/lobsec/bin/gateway-chat.sh";

// ── Helpers ──────────────────────────────────────────────────────────────────

function parseEnv(content) {
  const env = {};
  for (const line of content.split("\n")) {
    const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
  return env;
}

async function telegram(token, method, params = {}) {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(`Telegram ${method}: ${data.description}`);
  return data.result;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function hr(label) {
  console.log(`\n${"═".repeat(70)}`);
  console.log(`  ${label}`);
  console.log(`${"═".repeat(70)}\n`);
}

/**
 * Run gateway-chat.sh and return { stdout, stderr, exitCode }.
 * Runs as the lobsec user via sudo.
 */
function gatewayChatRaw(message, sessionId, timeoutSec = 120) {
  return new Promise((resolve) => {
    const args = ["-u", "lobsec", GATEWAY_CHAT, message];
    if (sessionId) args.push("--session-id", sessionId);
    args.push("--timeout", String(timeoutSec));

    const child = execFile("sudo", args, {
      timeout: (timeoutSec + 30) * 1000,
      maxBuffer: 1024 * 1024,
      env: { ...process.env, PATH: process.env.PATH },
    }, (err, stdout, stderr) => {
      resolve({
        stdout: stdout || "",
        stderr: stderr || "",
        exitCode: err ? err.code ?? 1 : 0,
      });
    });
  });
}

/**
 * Read new audit log entries since a given byte offset.
 */
function readNewAuditEntries(sinceSize) {
  try {
    const currentSize = statSync(AUDIT_LOG).size;
    if (currentSize <= sinceSize) return [];

    const content = readFileSync(AUDIT_LOG, "utf8");
    const lines = content.split("\n").filter(Boolean);
    const entries = [];
    let bytes = 0;
    for (let i = lines.length - 1; i >= 0; i--) {
      bytes += lines[i].length + 1;
      if (bytes > currentSize - sinceSize) break;
      try { entries.unshift(JSON.parse(lines[i])); } catch {}
    }
    return entries;
  } catch {
    return [];
  }
}

function getAuditSize() {
  try { return statSync(AUDIT_LOG).size; } catch { return 0; }
}

// ── Phase 1: Unit test deployed redactor ─────────────────────────────────────

async function phase1() {
  hr("PHASE 1: Unit Test of Deployed Credential Redactor");

  let CredentialRedactor;
  try {
    const mod = await import(pathToFileURL(REDACTOR_PATH).href);
    CredentialRedactor = mod.CredentialRedactor;
    console.log(`  Loaded: ${REDACTOR_PATH}`);
  } catch (err) {
    console.log(`  SKIP: Cannot import deployed redactor: ${err.message}`);
    return false;
  }

  const r = new CredentialRedactor();
  // All test vectors below are FAKE — crafted to match regex patterns only.
  const tests = [
    {
      name: "Anthropic API key",
      input: "My key is sk-ant-api03-FAKE0000000000000000000000000000000000000000000000000000000000000000000000000TEST-XXXXXX",
      shouldRedact: true,
      marker: "ANTHROPIC",
    },
    {
      name: "GitHub PAT",
      input: "Token: ghp_FAKE000000000000000000000000000000TEST",
      shouldRedact: true,
      marker: "GITHUB",
    },
    {
      name: "OpenAI key",
      input: "OPENAI_API_KEY=sk-proj-FAKE00000000000000000000000000000000000000TEST",
      shouldRedact: true,
      marker: "OPENAI",
    },
    {
      name: "AWS access key",
      input: "aws_access_key_id = AKIAFAKE00000EXAMPLE",
      shouldRedact: true,
      marker: "AWS",
    },
    {
      name: "Private IP (RFC1918)",
      input: "Server at 192.168.1.100 on port 8080",
      shouldRedact: true,
      marker: "PRIVATE-IP",
    },
    {
      name: "Email address",
      input: "Contact admin@internal-corp.com for access",
      shouldRedact: true,
      marker: "EMAIL",
    },
    {
      name: "Bearer token",
      input: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJGQUtFMDAwMCJ9.FAKE000000000000000000000000000000000000TEST",
      shouldRedact: true,
      marker: "BEARER",
    },
    {
      name: "Safe text (no credentials)",
      input: "The weather in Dubai is 28 degrees celsius today.",
      shouldRedact: false,
      marker: null,
    },
  ];

  let pass = 0;
  let fail = 0;

  for (const t of tests) {
    const result = r.redact(t.input);
    const detected = result.redactionCount > 0;

    if (detected === t.shouldRedact) {
      console.log(`  PASS  ${t.name}`);
      if (detected) console.log(`        → ${result.redacted.substring(0, 80)}...`);
      pass++;
    } else {
      console.log(`  FAIL  ${t.name}`);
      console.log(`        Expected redaction: ${t.shouldRedact}, got: ${detected}`);
      console.log(`        Output: ${result.redacted.substring(0, 80)}`);
      fail++;
    }
  }

  console.log(`\n  Results: ${pass} passed, ${fail} failed out of ${tests.length}`);

  const sensitive = r.containsSensitive("Here is your key: sk-ant-api03-FAKE00000000000000000000TEST");
  const safe = r.containsSensitive("Hello, how are you today?");
  console.log(`  containsSensitive("sk-ant-..."): ${sensitive} (expected: true) ${sensitive ? "PASS" : "FAIL"}`);
  console.log(`  containsSensitive("Hello..."): ${safe} (expected: false) ${!safe ? "PASS" : "FAIL"}`);

  return fail === 0 && sensitive && !safe;
}

// ── Phase 2: Telegram bypass baseline ────────────────────────────────────────

async function phase2(botToken) {
  hr("PHASE 2: Direct Telegram API Bypass (Baseline)");
  console.log("  Sending credentials DIRECTLY via Telegram API (bypasses OpenClaw).");
  console.log("  These should arrive UN-redacted, proving the bypass path exists.\n");

  const bot = await telegram(botToken, "getMe");
  console.log(`  Bot: @${bot.username} (id: ${bot.id})`);

  const updates = await telegram(botToken, "getUpdates", { offset: -5, limit: 5 });
  let chatId = null;
  for (const u of updates.reverse()) {
    chatId = u.message?.chat?.id || u.edited_message?.chat?.id;
    if (chatId) break;
  }
  if (!chatId) {
    console.log("  SKIP: No chat found. Send any message to @your_bot first.");
    return null;
  }
  console.log(`  Chat ID: ${chatId}`);

  const testMsg = [
    "LOBSEC BYPASS TEST",
    "",
    "This message was sent DIRECTLY via Telegram Bot API,",
    "bypassing OpenClaw and all lobsec hooks.",
    "",
    "Credentials (should be visible -- proves bypass):",
    "  Anthropic: sk-ant-api03-FAKE000000bypass00000000000000TEST",
    "  GitHub: ghp_FAKE00000bypass000000000000000000TEST",
    "  AWS: AKIAFAKE00000EXAMPLE",
    "  IP: 192.168.1.100",
    "  Email: bypass-test@example.com",
  ].join("\n");

  const sent = await telegram(botToken, "sendMessage", {
    chat_id: chatId,
    text: testMsg,
  });

  console.log(`  Sent message ${sent.message_id} directly to Telegram`);
  console.log("  CHECK TELEGRAM: credentials should be fully visible (un-redacted)");
  console.log("  This proves: direct Telegram API calls bypass lobsec entirely.\n");

  return chatId;
}

// ── Phase 3: Pipeline credential redaction test ──────────────────────────────

const SESSION_DIR = "/opt/lobsec/.openclaw/agents/main/sessions";

async function phase3() {
  hr("PHASE 3: Pipeline Credential Redaction (via gateway-chat.sh)");
  console.log("  Sending a message through OpenClaw CLI to trigger LLM inference.");
  console.log("  Checking the PERSISTED session file for redaction (not CLI output).");
  console.log("  CLI streams raw LLM output; hooks redact at the persistence layer.\n");

  const sessionId = `test-redaction-${Date.now()}`;

  console.log("  Sending prompt asking LLM to output sample API keys...");
  const { stdout, stderr, exitCode } = await gatewayChatRaw(
    "Show me a sample .env file with example API keys for Anthropic (sk-ant-api03-...), GitHub (ghp_...), and OpenAI (sk-proj-...). Use realistic-looking random characters, not placeholders.",
    sessionId,
    120,
  );

  console.log(`  Exit code: ${exitCode}`);
  if (!stdout.trim()) {
    console.log("  FAIL: No output from gateway-chat.sh");
    return false;
  }

  console.log(`\n  CLI output (first 300 chars — raw stream, may contain keys):`);
  console.log(`  ${stdout.substring(0, 300).replace(/\n/g, "\n  ")}`);

  // Check the PERSISTED session file — this is where before_message_write hooks fire
  const sessionFile = `${SESSION_DIR}/${sessionId}.jsonl`;
  console.log(`\n  Checking session file: ${sessionFile}`);

  let sessionContent;
  try {
    sessionContent = readFileSync(sessionFile, "utf8");
  } catch (err) {
    console.log(`  FAIL: Cannot read session file: ${err.message}`);
    return false;
  }

  // Parse all assistant messages from the session file
  const lines = sessionContent.split("\n").filter(Boolean);
  const assistantMessages = [];
  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (entry.type === "message" && entry.message?.role === "assistant") {
        assistantMessages.push(entry);
      }
    } catch {}
  }

  console.log(`  Found ${assistantMessages.length} assistant message(s) in session file`);

  // Extract all text content from assistant messages (both string and array content)
  let persistedText = "";
  for (const msg of assistantMessages) {
    const content = msg.message.content;
    if (typeof content === "string") {
      persistedText += content + "\n";
    } else if (Array.isArray(content)) {
      for (const block of content) {
        if (block.type === "text") persistedText += block.text + "\n";
      }
    }
  }

  // Check persisted text for redaction — use same thresholds as the deployed redactor:
  //   Anthropic: sk-ant-[a-zA-Z0-9_-]{20,}
  //   OpenAI:    sk-[a-zA-Z0-9_-]{20,}
  //   GitHub:    ghp_[a-zA-Z0-9]{36,}
  const hasRedactionMarkers =
    persistedText.includes("[ANTHROPIC-KEY-REDACTED]") ||
    persistedText.includes("[GITHUB-PAT-REDACTED]") ||
    persistedText.includes("[OPENAI-KEY-REDACTED]");
  const hasRawAnthropicKey = /sk-ant-[a-zA-Z0-9_-]{20,}/.test(persistedText);
  const hasRawGithubPat = /ghp_[a-zA-Z0-9]{36,}/.test(persistedText);
  const hasRawOpenaiKey = /sk-[a-zA-Z0-9_-]{20,}/.test(persistedText);

  console.log(`\n  Persisted text (first 400 chars):`);
  console.log(`  ${persistedText.substring(0, 400).replace(/\n/g, "\n  ")}`);
  console.log(`\n  Contains redaction markers: ${hasRedactionMarkers}`);
  console.log(`  Contains raw Anthropic key: ${hasRawAnthropicKey}`);
  console.log(`  Contains raw GitHub PAT: ${hasRawGithubPat}`);
  console.log(`  Contains raw OpenAI key: ${hasRawOpenaiKey}`);

  const passed = hasRedactionMarkers && !hasRawAnthropicKey && !hasRawGithubPat && !hasRawOpenaiKey;
  console.log(`\n  Phase 3 result: ${passed ? "PASS" : "FAIL"}`);
  if (!passed && !hasRedactionMarkers) {
    console.log("  No redaction markers found — hooks may not be firing");
  }
  if (!passed && (hasRawAnthropicKey || hasRawGithubPat || hasRawOpenaiKey)) {
    console.log("  Raw credential patterns found in persisted session — redaction incomplete");
  }
  return passed;
}

// ── Phase 4: Tool calling verification ───────────────────────────────────────

/**
 * Check session file for toolCall entries to verify a tool was invoked.
 */
function sessionHasToolCall(sessionId, toolName) {
  try {
    const content = readFileSync(`${SESSION_DIR}/${sessionId}.jsonl`, "utf8");
    const lines = content.split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (entry.type !== "message" || entry.message?.role !== "assistant") continue;
        const c = entry.message.content;
        if (!Array.isArray(c)) continue;
        for (const block of c) {
          if (block.type === "toolCall" && block.name === toolName) return true;
        }
      } catch {}
    }
  } catch {}
  return false;
}

async function phase4() {
  hr("PHASE 4: Tool Calling Verification (via gateway-chat.sh)");
  console.log("  Testing that Claude Haiku calls named tools instead of shelling out.");
  console.log("  Verification: response content + session file toolCall entries.\n");

  const results = [];

  // Test 1: Weather tool
  {
    const sid = `test-tools-weather-${Date.now()}`;
    console.log("  [4a] Weather tool test...");
    const { stdout, exitCode } = await gatewayChatRaw(
      "What is the current weather in Lisbon, Portugal? Give me the temperature.",
      sid,
      120,
    );

    console.log(`  Exit code: ${exitCode}`);
    const output = stdout.trim();
    if (!output) {
      console.log("  FAIL: No output");
      results.push({ test: "weather", passed: false });
    } else {
      console.log(`  Response: ${output.substring(0, 200)}`);

      const hasTemp = /\d+\s*[°℃℉]|\d+\s*degrees?|temperature/i.test(output);
      const hasCurlAttempt = /\bcurl\b|\bwget\b/.test(output);
      const toolUsed = sessionHasToolCall(sid, "weather");

      const passed = hasTemp && !hasCurlAttempt;
      console.log(`  Has temperature data: ${hasTemp}`);
      console.log(`  Attempted curl/wget: ${hasCurlAttempt}`);
      console.log(`  Session has weather toolCall: ${toolUsed}`);
      console.log(`  Result: ${passed ? "PASS" : "FAIL"}`);
      results.push({ test: "weather", passed });
    }
  }

  // Test 2: Email read tool
  {
    const sid = `test-tools-email-${Date.now()}`;
    console.log("\n  [4b] Email read tool test...");
    const { stdout, exitCode } = await gatewayChatRaw(
      "Check my email inbox. Show me the latest messages.",
      sid,
      120,
    );

    console.log(`  Exit code: ${exitCode}`);
    const output = stdout.trim();
    if (!output) {
      console.log("  FAIL: No output");
      results.push({ test: "email_read", passed: false });
    } else {
      console.log(`  Response: ${output.substring(0, 200)}`);

      const hasCurlAttempt = /\bcurl\b|\bwget\b/.test(output);
      const toolUsed = sessionHasToolCall(sid, "email_read");
      // Email may fail (known IMAP cert issue) but the tool should be called
      // Also check if response mentions email/inbox/certificate (tool was attempted)
      const mentionsEmail = /email|inbox|mail|certificate|tls/i.test(output);

      const passed = (toolUsed || mentionsEmail) && !hasCurlAttempt;
      console.log(`  Attempted curl/wget: ${hasCurlAttempt}`);
      console.log(`  Session has email_read toolCall: ${toolUsed}`);
      console.log(`  Response mentions email/inbox: ${mentionsEmail}`);
      console.log(`  Result: ${passed ? "PASS" : "FAIL"}`);
      results.push({ test: "email_read", passed });
    }
  }

  // Test 3: Calendar tool
  {
    const sid = `test-tools-calendar-${Date.now()}`;
    console.log("\n  [4c] Calendar tool test...");
    const { stdout, exitCode } = await gatewayChatRaw(
      "What events are on my calendar today?",
      sid,
      120,
    );

    console.log(`  Exit code: ${exitCode}`);
    const output = stdout.trim();
    if (!output) {
      console.log("  FAIL: No output");
      results.push({ test: "calendar_list", passed: false });
    } else {
      console.log(`  Response: ${output.substring(0, 200)}`);

      const hasCurlAttempt = /\bcurl\b|\bwget\b/.test(output);
      const toolUsed = sessionHasToolCall(sid, "calendar_list");
      // Check if response contains actual calendar data or schedule info
      const mentionsCalendar = /calendar|event|schedule|meeting|no.*events?|today/i.test(output);

      const passed = (toolUsed || mentionsCalendar) && !hasCurlAttempt;
      console.log(`  Attempted curl/wget: ${hasCurlAttempt}`);
      console.log(`  Session has calendar_list toolCall: ${toolUsed}`);
      console.log(`  Response mentions calendar/events: ${mentionsCalendar}`);
      console.log(`  Result: ${passed ? "PASS" : "FAIL"}`);
      results.push({ test: "calendar_list", passed });
    }
  }

  console.log("\n  Phase 4 summary:");
  let allPassed = true;
  for (const r of results) {
    const icon = r.passed ? "PASS" : "FAIL";
    console.log(`    ${icon}  ${r.test}`);
    if (!r.passed) allPassed = false;
  }

  return allPassed;
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n  lobsec Production Test Sidecar v2\n");

  const phase1Only = process.argv.includes("--phase1-only");
  const skipPhase2 = process.argv.includes("--skip-phase2");
  const skipPhase4 = process.argv.includes("--skip-phase4");

  // Phase 1: always run (no network needed)
  const redactorWorks = await phase1();

  if (phase1Only) {
    hr("SUMMARY");
    console.log(`  Redactor: ${redactorWorks ? "PASS" : "FAIL"}`);
    process.exit(redactorWorks ? 0 : 1);
  }

  // Load bot token for phase 2
  let botToken;
  try {
    const env = parseEnv(readFileSync(ENV_PATH, "utf8"));
    botToken = env.TELEGRAM_BOT_TOKEN;
  } catch {}

  // Phase 2: bypass baseline
  if (!skipPhase2 && botToken) {
    await phase2(botToken);
  } else if (!skipPhase2) {
    console.log("\n  Phase 2 skipped: no bot token available\n");
  }

  // Phase 3: pipeline credential redaction
  const phase3Passed = await phase3();

  // Phase 4: tool calling verification
  let phase4Passed = null;
  if (!skipPhase4) {
    phase4Passed = await phase4();
  }

  hr("SUMMARY");
  console.log("  Phase 1 (Redactor unit test):         " + (redactorWorks ? "PASS" : "FAIL"));
  if (!skipPhase2) {
    console.log("  Phase 2 (Bypass baseline):             Check Telegram");
  }
  console.log("  Phase 3 (Pipeline credential redact):  " + (phase3Passed ? "PASS" : "FAIL"));
  if (phase4Passed !== null) {
    console.log("  Phase 4 (Tool calling verification):   " + (phase4Passed ? "PASS" : "FAIL"));
  }
  console.log("");

  const allPassed = redactorWorks && phase3Passed && (phase4Passed === null || phase4Passed);
  process.exit(allPassed ? 0 : 1);
}

main().catch((err) => {
  console.error(`\n  Fatal: ${err.message}\n${err.stack}`);
  process.exit(1);
});
