import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { validateHardenedConfig } from "./config-generator.js";
import type { ConfigValidationError } from "./config-generator.js";

// ── Types ───────────────────────────────────────────────────────────────────

export interface DriftResult {
  /** True if no drift detected. */
  clean: boolean;
  /** Security setting violations found. */
  violations: ConfigValidationError[];
  /** Hash of the current config on disk. */
  currentHash: string;
  /** Hash of the expected config (if provided). */
  expectedHash?: string;
  /** Timestamp of the check. */
  checkedAt: string;
}

export interface HeartbeatStatus {
  /** True if heartbeat file exists and matches expected hash. */
  valid: boolean;
  /** Current hash of the heartbeat file. */
  currentHash?: string;
  /** Expected hash. */
  expectedHash?: string;
  /** Whether the file was modified since last check. */
  modified: boolean;
  /** File modification time. */
  mtime?: string;
}

export interface AuditFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  rule: string;
  message: string;
  path?: string;
}

export interface SecurityAuditResult {
  /** True if no critical findings. */
  passesStartup: boolean;
  /** All findings from the audit. */
  findings: AuditFinding[];
  /** Count by severity. */
  counts: Record<string, number>;
}

// ── Hashing ─────────────────────────────────────────────────────────────────

/** Compute SHA-256 hash of a string. */
export function hashConfig(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/** Compute a canonical hash of a config object (sorted keys). */
export function canonicalHash(config: unknown): string {
  const canonical = JSON.stringify(config, Object.keys(config as object).sort());
  return hashConfig(canonical);
}

// ── Drift detection ─────────────────────────────────────────────────────────

/**
 * Compare a loaded config against hardened expectations.
 * Returns a DriftResult indicating whether the config has drifted.
 */
export function detectDrift(
  currentConfig: unknown,
  expectedHash?: string,
): DriftResult {
  const violations = validateHardenedConfig(currentConfig);
  const currentHash = canonicalHash(currentConfig);

  const hashMatch = expectedHash === undefined || currentHash === expectedHash;

  return {
    clean: violations.length === 0 && hashMatch,
    violations,
    currentHash,
    expectedHash,
    checkedAt: new Date().toISOString(),
  };
}

/**
 * Load a config file from disk and check for drift.
 */
export async function detectDriftFromFile(
  configPath: string,
  expectedHash?: string,
): Promise<DriftResult> {
  const content = await readFile(configPath, "utf8");
  const config = JSON.parse(content) as unknown;
  return detectDrift(config, expectedHash);
}

// ── HEARTBEAT.md monitoring ─────────────────────────────────────────────────

/**
 * Check whether a HEARTBEAT.md file has been tampered with.
 * This is a persistence detection mechanism (attack class 12).
 */
export async function checkHeartbeat(
  heartbeatPath: string,
  expectedHash?: string,
): Promise<HeartbeatStatus> {
  try {
    const content = await readFile(heartbeatPath, "utf8");
    const currentHash = hashConfig(content);
    const s = await stat(heartbeatPath);

    return {
      valid: expectedHash === undefined || currentHash === expectedHash,
      currentHash,
      expectedHash,
      modified: expectedHash !== undefined && currentHash !== expectedHash,
      mtime: s.mtime.toISOString(),
    };
  } catch {
    return {
      valid: false,
      modified: true,
    };
  }
}

// ── Security audit parsing ──────────────────────────────────────────────────

/**
 * Parse the JSON output from `openclaw security audit --json`.
 * Returns structured findings and whether startup should be blocked.
 */
export function parseSecurityAudit(auditJson: string): SecurityAuditResult {
  let raw: unknown;
  try {
    raw = JSON.parse(auditJson);
  } catch {
    return {
      passesStartup: false,
      findings: [
        {
          severity: "critical",
          rule: "parse-error",
          message: "Failed to parse security audit JSON output",
        },
      ],
      counts: { critical: 1 },
    };
  }

  const findings: AuditFinding[] = [];
  const counts: Record<string, number> = {};

  // Handle both array and object formats
  const items = Array.isArray(raw) ? raw : (raw as Record<string, unknown>).findings ?? [];

  if (Array.isArray(items)) {
    for (const item of items) {
      if (typeof item === "object" && item !== null) {
        const finding: AuditFinding = {
          severity: normalizeSeverity(String((item as Record<string, unknown>).severity ?? "info")),
          rule: String((item as Record<string, unknown>).rule ?? "unknown"),
          message: String((item as Record<string, unknown>).message ?? ""),
          path: (item as Record<string, unknown>).path as string | undefined,
        };
        findings.push(finding);
        counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
      }
    }
  }

  const hasCritical = (counts["critical"] ?? 0) > 0;

  return {
    passesStartup: !hasCritical,
    findings,
    counts,
  };
}

function normalizeSeverity(s: string): AuditFinding["severity"] {
  const lower = s.toLowerCase();
  if (lower === "critical") return "critical";
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "info";
}

// ── Cron persistence detection ──────────────────────────────────────────────

/** Known cron paths to check for unexpected entries. */
export const CRON_PATHS = [
  "/var/spool/cron/crontabs",
  "/etc/cron.d",
  "/etc/cron.daily",
  "/etc/cron.hourly",
] as const;

/**
 * Check a crontab content string for suspicious entries.
 * Returns an array of suspicious lines.
 */
export function detectSuspiciousCron(crontabContent: string): string[] {
  const suspicious: string[] = [];
  const lines = crontabContent.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    // Flag lines that reference known persistence patterns
    const suspiciousPatterns = [
      /curl\s+/i,
      /wget\s+/i,
      /python[23]?\s+-c/i,
      /bash\s+-c/i,
      /nc\s+/i,
      /ncat\s+/i,
      /\/tmp\//i,
      /\/dev\/shm\//i,
      /base64/i,
      /eval\s*\(/i,
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(trimmed)) {
        suspicious.push(trimmed);
        break;
      }
    }
  }

  return suspicious;
}
