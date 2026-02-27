#!/usr/bin/env node
/**
 * lobsec Production Test Sidecar
 *
 * Three-phase test proving lobsec security hooks work end-to-end.
 *
 * Phase 1: Unit test deployed redactor (automated, no network)
 * Phase 2: Telegram bypass baseline (automated, proves direct path is unprotected)
 * Phase 3: Pipeline test (automated send + audit log monitoring)
 *
 * Usage: node test-sidecar.mjs [--phase1-only] [--skip-phase2]
 */

import { readFileSync, watchFile, unwatchFile, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const ENV_PATH = "/opt/lobsec/.openclaw/.env";
const AUDIT_LOG = "/opt/lobsec/logs/audit.jsonl";
const REDACTOR_PATH = "/opt/lobsec/plugins/lobsec-security/dist/credential-redactor.js";

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
  // They are NOT real credentials. Prefixed/suffixed with FAKE/TEST/EXAMPLE.
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

  // Also test containsSensitive (used by message_sending hook)
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

  // Verify bot
  const bot = await telegram(botToken, "getMe");
  console.log(`  Bot: @${bot.username} (id: ${bot.id})`);

  // Find chat
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

  // Send credential-laden message directly (NOT through OpenClaw)
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

// ── Phase 3: Pipeline test ───────────────────────────────────────────────────

async function phase3(botToken, chatId) {
  hr("PHASE 3: OpenClaw Pipeline Test (Credential Redaction)");
  console.log("  Sending a message through OpenClaw to trigger LLM inference.");
  console.log("  The LLM response should pass through lobsec hooks.");
  console.log("  If redaction works, credential patterns will be replaced.\n");

  // Record audit log position before test
  let auditSize;
  try {
    auditSize = statSync(AUDIT_LOG).size;
  } catch {
    auditSize = 0;
  }

  // We can't send AS a user via the Bot API. But we CAN:
  // 1. Use the gateway WebSocket directly
  // 2. Or send a message that OpenClaw processes
  //
  // Attempt: connect to the OpenClaw WebSocket gateway.
  const gatewayToken = parseEnv(readFileSync(ENV_PATH, "utf8")).OPENCLAW_GATEWAY_TOKEN;

  if (!gatewayToken) {
    console.log("  SKIP: No OPENCLAW_GATEWAY_TOKEN in .env");
    return;
  }

  // Try WebSocket connection to gateway
  console.log("  Connecting to OpenClaw gateway WebSocket...");
  // TLS verification disabled for localhost-only self-signed cert.
  // This test sidecar ONLY connects to 127.0.0.1 -- never to external hosts.
  // The CA cert is at /opt/lobsec/config/tls/ca.crt but Node's built-in
  // WebSocket doesn't support per-connection CA pinning.
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

  let ws;
  let response = null;
  const wsUrl = "wss://127.0.0.1:18789";

  try {
    ws = new WebSocket(wsUrl, {
      headers: { Authorization: `Bearer ${gatewayToken}` },
    });
  } catch {
    // Node 22 built-in WebSocket doesn't support headers.
    // Try without auth header, send auth after connect.
    ws = new WebSocket(wsUrl);
  }

  const result = await new Promise((resolve) => {
    const timeout = setTimeout(() => {
      ws.close();
      resolve({ connected: false, reason: "timeout" });
    }, 15000);

    ws.addEventListener("open", () => {
      console.log("  Connected to gateway WebSocket");

      // Try authenticating
      ws.send(
        JSON.stringify({
          type: "auth",
          token: gatewayToken,
        })
      );

      // Send a test message that should trigger LLM inference
      // and produce credential-like patterns in the response
      setTimeout(() => {
        ws.send(
          JSON.stringify({
            type: "message",
            content:
              "Show me a one-line example of an Anthropic API key that starts with sk-ant-api03- followed by random characters. Just the key, nothing else.",
          })
        );
        console.log("  Sent test message via WebSocket");
      }, 2000);
    });

    ws.addEventListener("message", (event) => {
      const data = event.data?.toString() || event.data;
      try {
        const msg = JSON.parse(data);
        console.log(`  WS received: type=${msg.type || "?"}, keys=${Object.keys(msg).join(",")}`);

        // Capture any response content
        if (msg.content || msg.text || msg.message) {
          response = msg.content || msg.text || msg.message;
        }
      } catch {
        console.log(`  WS received (raw): ${String(data).substring(0, 100)}`);
      }
    });

    ws.addEventListener("error", (err) => {
      console.log(`  WS error: ${err.message || err.type || "unknown"}`);
      clearTimeout(timeout);
      resolve({ connected: false, reason: err.message || "connection error" });
    });

    ws.addEventListener("close", (event) => {
      clearTimeout(timeout);
      resolve({ connected: true, response, code: event.code, reason: event.reason });
    });
  });

  if (!result.connected) {
    console.log(`\n  WebSocket connection failed: ${result.reason}`);
    console.log("  This is expected -- OpenClaw's WebSocket protocol is undocumented.");
    console.log("  Falling back to audit log analysis.\n");
  }

  // Check if any new audit entries appeared
  console.log("  Checking audit log for new entries...");
  await sleep(3000);

  try {
    const currentSize = statSync(AUDIT_LOG).size;
    if (currentSize > auditSize) {
      const content = readFileSync(AUDIT_LOG, "utf8");
      const lines = content.split("\n").filter(Boolean);
      const newEntries = [];
      let bytes = 0;
      for (let i = lines.length - 1; i >= 0; i--) {
        bytes += lines[i].length + 1;
        if (bytes > currentSize - auditSize) break;
        newEntries.unshift(lines[i]);
      }

      for (const line of newEntries) {
        try {
          const entry = JSON.parse(line);
          const icon =
            entry.event === "credential_leak_blocked"
              ? "!!"
              : entry.event === "tool_denied"
                ? "XX"
                : "--";
          console.log(`  [${icon}] ${entry.event} (${entry.level})`);
          if (entry.patterns) console.log(`       patterns: ${JSON.stringify(entry.patterns)}`);
        } catch {}
      }
    } else {
      console.log("  No new audit entries (hooks may not have fired)");
    }
  } catch (err) {
    console.log(`  Cannot read audit log: ${err.message}`);
  }

  // Final: check if response was redacted
  if (response) {
    console.log("\n  Response received through pipeline:");
    console.log(`  "${response.substring(0, 200)}"`);

    const hasRedactionMarkers =
      response.includes("[ANTHROPIC-KEY-REDACTED]") ||
      response.includes("[REDACTED]") ||
      response.includes("REDACTED");
    const hasRawKeys = /sk-ant-api03-[a-zA-Z0-9]{20,}/.test(response);

    console.log(`  Contains redaction markers: ${hasRedactionMarkers}`);
    console.log(`  Contains raw credential patterns: ${hasRawKeys}`);
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n  lobsec Production Test Sidecar\n");

  const phase1Only = process.argv.includes("--phase1-only");
  const skipPhase2 = process.argv.includes("--skip-phase2");

  // Phase 1: always run (no network needed)
  const redactorWorks = await phase1();

  if (phase1Only) {
    hr("SUMMARY");
    console.log(`  Redactor: ${redactorWorks ? "PASS" : "FAIL"}`);
    process.exit(redactorWorks ? 0 : 1);
  }

  // Load bot token for phases 2-3
  let botToken;
  try {
    const env = parseEnv(readFileSync(ENV_PATH, "utf8"));
    botToken = env.TELEGRAM_BOT_TOKEN;
    if (!botToken) throw new Error("not found");
  } catch (err) {
    console.log(`\n  Cannot read bot token: ${err.message}`);
    console.log("  Phases 2-3 require access to /opt/lobsec/.openclaw/.env\n");
    process.exit(redactorWorks ? 0 : 1);
  }

  // Phase 2: bypass baseline
  let chatId = null;
  if (!skipPhase2) {
    chatId = await phase2(botToken);
  }

  // Phase 3: pipeline test
  await phase3(botToken, chatId);

  hr("SUMMARY");
  console.log("  Phase 1 (Redactor unit test): " + (redactorWorks ? "PASS" : "FAIL"));
  console.log("  Phase 2 (Bypass baseline):    Check Telegram for un-redacted credentials");
  console.log("  Phase 3 (Pipeline test):      Check audit log + Telegram for redacted response");
  console.log("");
  console.log("  Next step: Send this to @your_bot from Telegram:");
  console.log('  "Write a sample .env file with example Anthropic and GitHub API keys"');
  console.log("  Then check if the response has [REDACTED] markers.");
  console.log("");
}

main().catch((err) => {
  console.error(`\n  Fatal: ${err.message}\n${err.stack}`);
  process.exit(1);
});
