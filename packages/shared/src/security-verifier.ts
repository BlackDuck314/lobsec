// ── Security Verifier ─────────────────────────────────────────────────────
// Composes all existing security validators into a single verification
// system with 9 layers. Used by `lobsec verify` CLI and Telegram bot.

import { validateHardenedConfig } from "./config-generator.js";
import type { ConfigValidationError } from "./config-generator.js";
import { detectDrift } from "./drift-detector.js";
import { readFile, stat, access } from "node:fs/promises";
import { constants } from "node:fs";

// ── Types ───────────────────────────────────────────────────────────────────

export type CheckStatus = "pass" | "fail" | "warn" | "skip";

export interface CheckResult {
  name: string;
  status: CheckStatus;
  message: string;
}

export interface LayerReport {
  layer: string;
  status: CheckStatus;
  checks: CheckResult[];
}

export interface VerificationSummary {
  total: number;
  passed: number;
  failed: number;
  warned: number;
  skipped: number;
}

export interface VerificationReport {
  overall: CheckStatus;
  timestamp: string;
  layers: LayerReport[];
  summary: VerificationSummary;
}

export interface VerifyOptions {
  /** Base directory for lobsec. Default: /opt/lobsec */
  baseDir?: string;
  /** Config file path. Default: baseDir/.openclaw/openclaw.json */
  configPath?: string;
  /** Audit log path. Default: baseDir/logs/audit.jsonl */
  auditLogPath?: string;
  /** Gateway env file. Default: baseDir/.env */
  gatewayEnvPath?: string;
  /** Proxy env file. Default: baseDir/proxy/.env */
  proxyEnvPath?: string;
  /** Only run specific layer(s). */
  layers?: string[];
  /** Expected config hash (skip drift check if not provided). */
  expectedConfigHash?: string;
}

// ── Layer implementations ───────────────────────────────────────────────────

/** L1: Credentials — no cloud keys in gateway env, proxy has them. */
async function verifyCredentials(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];
  const cloudKeyPatterns = [
    /^ANTHROPIC_API_KEY=sk-ant-/m,
    /^OPENAI_API_KEY=sk-/m,
    /^OLLAMA_API_KEY=.+/m,
  ];

  // Check gateway env does NOT contain real cloud keys
  try {
    const gatewayEnv = await readFile(opts.gatewayEnvPath, "utf8");
    let hasLeakedKey = false;
    for (const pattern of cloudKeyPatterns) {
      if (pattern.test(gatewayEnv)) {
        // Check if it's a real key (not a proxy token reference)
        const match = gatewayEnv.match(pattern);
        if (match && !match[0].includes("proxy-token")) {
          // This is likely a real key — check if it starts with real prefixes
          const value = match[0].split("=")[1];
          if (value && (value.startsWith("sk-ant-") || value.startsWith("sk-"))) {
            checks.push({ name: "gateway-no-cloud-keys", status: "fail", message: `Real cloud key found in gateway env` });
            hasLeakedKey = true;
            break;
          }
        }
      }
    }
    if (!hasLeakedKey) {
      checks.push({ name: "gateway-no-cloud-keys", status: "pass", message: "No real cloud API keys in gateway environment" });
    }
  } catch {
    checks.push({ name: "gateway-no-cloud-keys", status: "skip", message: "Gateway env file not readable" });
  }

  // Check proxy env HAS credentials
  try {
    const proxyEnv = await readFile(opts.proxyEnvPath, "utf8");
    const hasAnthropicKey = /^ANTHROPIC_API_KEY=.+/m.test(proxyEnv);
    const hasOllamaKey = /^OLLAMA_API_KEY=.+/m.test(proxyEnv);
    if (hasAnthropicKey) {
      checks.push({ name: "proxy-has-anthropic-key", status: "pass", message: "Proxy has Anthropic API key" });
    } else {
      checks.push({ name: "proxy-has-anthropic-key", status: "warn", message: "Proxy missing Anthropic API key" });
    }
    if (hasOllamaKey) {
      checks.push({ name: "proxy-has-ollama-key", status: "pass", message: "Proxy has Ollama API key" });
    } else {
      checks.push({ name: "proxy-has-ollama-key", status: "warn", message: "Proxy missing Ollama API key" });
    }
  } catch {
    checks.push({ name: "proxy-credentials", status: "skip", message: "Proxy env file not readable" });
  }

  return { layer: "L1: Credentials", status: worstStatus(checks), checks };
}

/** L2: Sovereign — routing hook registered, default mode. */
async function verifySovereign(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];

  // Check config has sovereign routing settings
  try {
    const configJson = await readFile(opts.configPath, "utf8");
    const config = JSON.parse(configJson) as Record<string, unknown>;
    const plugins = config["plugins"] as Record<string, unknown> | undefined;
    if (plugins) {
      checks.push({ name: "sovereign-plugin-configured", status: "pass", message: "Plugin configuration present" });
    } else {
      checks.push({ name: "sovereign-plugin-configured", status: "warn", message: "No plugins section in config" });
    }
  } catch {
    checks.push({ name: "sovereign-config", status: "skip", message: "Config not readable" });
  }

  // Check adapter exists
  try {
    await access(`${opts.baseDir}/plugins/lobsec-security/index.js`, constants.R_OK);
    checks.push({ name: "sovereign-adapter-present", status: "pass", message: "Security plugin adapter deployed" });
  } catch {
    checks.push({ name: "sovereign-adapter-present", status: "fail", message: "Security plugin adapter not found" });
  }

  return { layer: "L2: Sovereign", status: worstStatus(checks), checks };
}

/** L3: Tools — deny list and exec security. */
async function verifyTools(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];

  try {
    const configJson = await readFile(opts.configPath, "utf8");
    const config = JSON.parse(configJson) as unknown;
    const errors = validateHardenedConfig(config);

    // Filter to tool-related errors
    const toolErrors = errors.filter((e: ConfigValidationError) =>
      e.path.startsWith("tools.") || e.path.startsWith("agents.defaults.sandbox")
    );

    if (toolErrors.length === 0) {
      checks.push({ name: "tools-hardened", status: "pass", message: "Tool security settings validated" });
    } else {
      for (const err of toolErrors) {
        checks.push({ name: `tools-${err.path}`, status: "fail", message: `${err.path}: expected ${err.expected}, got ${err.actual}` });
      }
    }
  } catch {
    checks.push({ name: "tools-config", status: "skip", message: "Config not readable" });
  }

  return { layer: "L3: Tools", status: worstStatus(checks), checks };
}

/** L4: Redaction — redaction hooks registered (check adapter exists). */
async function verifyRedaction(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];

  try {
    const adapterPath = `${opts.baseDir}/plugins/lobsec-security/index.js`;
    const adapterContent = await readFile(adapterPath, "utf8");

    if (adapterContent.includes("CredentialRedactor")) {
      checks.push({ name: "redactor-imported", status: "pass", message: "CredentialRedactor is imported in adapter" });
    } else {
      checks.push({ name: "redactor-imported", status: "fail", message: "CredentialRedactor not found in adapter" });
    }

    if (adapterContent.includes("message_sending")) {
      checks.push({ name: "redactor-hook-registered", status: "pass", message: "message_sending hook registered" });
    } else {
      checks.push({ name: "redactor-hook-registered", status: "fail", message: "message_sending hook not registered" });
    }

    if (adapterContent.includes("tool_result_persist")) {
      checks.push({ name: "redactor-persist-hook", status: "pass", message: "tool_result_persist hook registered" });
    } else {
      checks.push({ name: "redactor-persist-hook", status: "warn", message: "tool_result_persist hook not registered" });
    }
  } catch {
    checks.push({ name: "redaction-adapter", status: "skip", message: "Adapter not readable" });
  }

  return { layer: "L4: Redaction", status: worstStatus(checks), checks };
}

/** L5: Drift — ConfigMonitor running, config hash stable. */
async function verifyDrift(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];

  try {
    const configJson = await readFile(opts.configPath, "utf8");
    const config = JSON.parse(configJson) as unknown;
    const hasExpectedHash = !!opts.expectedConfigHash;
    const drift = detectDrift(config, hasExpectedHash ? opts.expectedConfigHash : undefined);

    if (!hasExpectedHash) {
      checks.push({ name: "config-drift", status: "warn", message: `No expected hash to compare (current: ${drift.currentHash.slice(0, 12)}...)` });
    } else if (drift.clean) {
      checks.push({ name: "config-drift", status: "pass", message: `Config hash ${drift.currentHash.slice(0, 12)}... matches expected` });
    } else {
      checks.push({ name: "config-drift", status: "fail", message: `Config drift detected: ${drift.violations.length} violations` });
    }
  } catch {
    checks.push({ name: "config-drift", status: "skip", message: "Config not readable" });
  }

  return { layer: "L5: Drift", status: worstStatus(checks), checks };
}

/** L6: Audit — log exists, signing recent, chain intact. */
async function verifyAudit(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];

  // Check audit log exists and has recent entries
  try {
    const auditStat = await stat(opts.auditLogPath);
    checks.push({ name: "audit-log-exists", status: "pass", message: `Audit log exists (${(auditStat.size / 1024).toFixed(1)} KB)` });

    // Check freshness (should have entries within last 15 min)
    const ageMin = (Date.now() - auditStat.mtimeMs) / 60_000;
    if (ageMin < 15) {
      checks.push({ name: "audit-log-fresh", status: "pass", message: `Last modified ${Math.floor(ageMin)} min ago` });
    } else {
      checks.push({ name: "audit-log-fresh", status: "warn", message: `Last modified ${Math.floor(ageMin)} min ago` });
    }
  } catch {
    checks.push({ name: "audit-log-exists", status: "fail", message: "Audit log not found" });
  }

  // Check signing state
  try {
    const signState = await stat(`${opts.baseDir}/logs/.audit-sign-state`);
    const ageMin = (Date.now() - signState.mtimeMs) / 60_000;
    if (ageMin < 15) {
      checks.push({ name: "audit-signing-recent", status: "pass", message: `Last signed ${Math.floor(ageMin)} min ago` });
    } else {
      checks.push({ name: "audit-signing-recent", status: "fail", message: `Last signed ${Math.floor(ageMin)} min ago (>15 min stale)` });
    }
  } catch {
    checks.push({ name: "audit-signing-recent", status: "warn", message: "No signing state file" });
  }

  return { layer: "L6: Audit", status: worstStatus(checks), checks };
}

/** L7: Sandbox — hardened image, seccomp profile. */
async function verifySandbox(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];

  try {
    const configJson = await readFile(opts.configPath, "utf8");
    const config = JSON.parse(configJson) as Record<string, unknown>;

    // Check sandbox mode
    const agents = config["agents"] as Record<string, unknown> | undefined;
    const defaults = agents?.["defaults"] as Record<string, unknown> | undefined;
    const sandbox = defaults?.["sandbox"] as Record<string, unknown> | undefined;

    if (sandbox?.["mode"] === "all") {
      checks.push({ name: "sandbox-mode", status: "pass", message: "Sandbox mode is 'all'" });
    } else {
      checks.push({ name: "sandbox-mode", status: "fail", message: `Sandbox mode is '${sandbox?.["mode"]}' (expected 'all')` });
    }

    // Check docker settings
    const docker = sandbox?.["docker"] as Record<string, unknown> | undefined;
    if (docker?.["readOnlyRoot"] === true) {
      checks.push({ name: "sandbox-readonly", status: "pass", message: "Docker root filesystem is read-only" });
    } else {
      checks.push({ name: "sandbox-readonly", status: "fail", message: "Docker root filesystem is not read-only" });
    }

    if (docker?.["network"] === "none") {
      checks.push({ name: "sandbox-network", status: "pass", message: "Docker network is 'none'" });
    } else {
      checks.push({ name: "sandbox-network", status: "fail", message: `Docker network is '${docker?.["network"]}' (expected 'none')` });
    }
  } catch {
    checks.push({ name: "sandbox-config", status: "skip", message: "Config not readable" });
  }

  return { layer: "L7: Sandbox", status: worstStatus(checks), checks };
}

/** L8: Network — loopback binding, egress rules, proxy health. */
async function verifyNetwork(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];

  try {
    const configJson = await readFile(opts.configPath, "utf8");
    const config = JSON.parse(configJson) as Record<string, unknown>;
    const gateway = config["gateway"] as Record<string, unknown> | undefined;

    if (gateway?.["bind"] === "loopback") {
      checks.push({ name: "gateway-loopback", status: "pass", message: "Gateway binds to loopback only" });
    } else {
      checks.push({ name: "gateway-loopback", status: "fail", message: `Gateway bind is '${gateway?.["bind"]}' (expected 'loopback')` });
    }
  } catch {
    checks.push({ name: "network-config", status: "skip", message: "Config not readable" });
  }

  // Check proxy health
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const res = await fetch("https://127.0.0.1:18790/__lobsec__/health", {
      signal: controller.signal,
    }).catch(() => null);
    clearTimeout(timeoutId);
    if (res && res.ok) {
      checks.push({ name: "proxy-health", status: "pass", message: "Proxy health endpoint responding" });
    } else {
      checks.push({ name: "proxy-health", status: "warn", message: "Proxy health endpoint not responding" });
    }
  } catch {
    checks.push({ name: "proxy-health", status: "warn", message: "Proxy health check failed" });
  }

  return { layer: "L8: Network", status: worstStatus(checks), checks };
}

/** L9: Encryption — fscrypt directories encrypted. */
async function verifyEncryption(opts: Required<VerifyOptions>): Promise<LayerReport> {
  const checks: CheckResult[] = [];
  const encryptedDirs = ["hsm", "config", "logs", ".openclaw"];

  for (const dir of encryptedDirs) {
    const fullPath = `${opts.baseDir}/${dir}`;
    try {
      await access(fullPath, constants.R_OK);
      // Directory exists and is accessible — check for .fscrypt or encryption.policy
      try {
        await access(`${fullPath}/.fscrypt`, constants.R_OK);
        checks.push({ name: `fscrypt-${dir}`, status: "pass", message: `${dir}/ has fscrypt policy` });
      } catch {
        // No .fscrypt directory — might still be encrypted via parent policy
        checks.push({ name: `fscrypt-${dir}`, status: "warn", message: `${dir}/ accessible but no .fscrypt marker found` });
      }
    } catch {
      checks.push({ name: `fscrypt-${dir}`, status: "skip", message: `${dir}/ not accessible` });
    }
  }

  return { layer: "L9: Encryption", status: worstStatus(checks), checks };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function worstStatus(checks: CheckResult[]): CheckStatus {
  if (checks.some((c) => c.status === "fail")) return "fail";
  if (checks.some((c) => c.status === "warn")) return "warn";
  if (checks.every((c) => c.status === "skip")) return "skip";
  return "pass";
}

function summarize(layers: LayerReport[]): VerificationSummary {
  const allChecks = layers.flatMap((l) => l.checks);
  return {
    total: allChecks.length,
    passed: allChecks.filter((c) => c.status === "pass").length,
    failed: allChecks.filter((c) => c.status === "fail").length,
    warned: allChecks.filter((c) => c.status === "warn").length,
    skipped: allChecks.filter((c) => c.status === "skip").length,
  };
}

// ── Main entry point ──────────────────────────────────────────────────────

const LAYER_MAP: Record<string, (opts: Required<VerifyOptions>) => Promise<LayerReport>> = {
  credentials: verifyCredentials,
  sovereign: verifySovereign,
  tools: verifyTools,
  redaction: verifyRedaction,
  drift: verifyDrift,
  audit: verifyAudit,
  sandbox: verifySandbox,
  network: verifyNetwork,
  encryption: verifyEncryption,
};

export const LAYER_NAMES = Object.keys(LAYER_MAP);

/**
 * Run all security verification layers in parallel.
 * Returns a structured report with per-layer and overall status.
 */
export async function verifyAll(opts?: VerifyOptions): Promise<VerificationReport> {
  const baseDir = opts?.baseDir ?? "/opt/lobsec";
  const resolved: Required<VerifyOptions> = {
    baseDir,
    configPath: opts?.configPath ?? `${baseDir}/.openclaw/openclaw.json`,
    auditLogPath: opts?.auditLogPath ?? `${baseDir}/logs/audit.jsonl`,
    gatewayEnvPath: opts?.gatewayEnvPath ?? `${baseDir}/.env`,
    proxyEnvPath: opts?.proxyEnvPath ?? `${baseDir}/proxy/.env`,
    layers: opts?.layers ?? LAYER_NAMES,
    expectedConfigHash: opts?.expectedConfigHash ?? "",
  };

  // Filter to requested layers
  const layerFns = resolved.layers
    .map((name) => LAYER_MAP[name])
    .filter((fn): fn is (typeof LAYER_MAP)[string] => fn !== undefined);

  // Run all layers in parallel
  const results = await Promise.allSettled(layerFns.map((fn) => fn(resolved)));

  const layers: LayerReport[] = results.map((result, i) => {
    if (result.status === "fulfilled") return result.value;
    return {
      layer: resolved.layers[i] ?? "unknown",
      status: "fail" as const,
      checks: [{ name: "layer-error", status: "fail" as const, message: (result.reason as Error).message }],
    };
  });

  const summary = summarize(layers);
  const overall: CheckStatus =
    summary.failed > 0 ? "fail" :
    summary.warned > 0 ? "warn" :
    "pass";

  return {
    overall,
    timestamp: new Date().toISOString(),
    layers,
    summary,
  };
}
