import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdir, stat, rename } from "node:fs/promises";
import { dirname } from "node:path";
import type {
  LogLevel,
  LogEntry,
  AuditLogEntry,
  SecurityLayer,
  AuditEventType,
  AttackClass,
  Component,
  LogDestination,
  ErrorDetail,
} from "./types/log.js";

// ── Log level ordering ──────────────────────────────────────────────────────

const LOG_LEVEL_ORDER: Record<LogLevel, number> = {
  TRACE: 0,
  DEBUG: 1,
  INFO: 2,
  WARN: 3,
  ERROR: 4,
  CRITICAL: 5,
};

/** Returns true if `level` meets or exceeds `minLevel`. */
export function meetsLevel(level: LogLevel, minLevel: LogLevel): boolean {
  return LOG_LEVEL_ORDER[level] >= LOG_LEVEL_ORDER[minLevel];
}

// ── Correlation ID ──────────────────────────────────────────────────────────

/** Generate a new trace / correlation ID. */
export function newTraceId(): string {
  return `tr_${randomUUID().replace(/-/g, "").slice(0, 24)}`;
}

// ── Credential redaction ────────────────────────────────────────────────────

/** Default patterns that match common secrets. */
const DEFAULT_REDACT_PATTERNS = [
  // Generic "key=<value>" / "token=<value>" in URLs or config
  /(?<=[?&](?:key|token|secret|password|apikey|api_key)=)[^&\s"]+/gi,
  // Bearer tokens
  /(?<=Bearer\s+)[A-Za-z0-9._~+/=-]+/gi,
  // Hex strings ≥ 32 chars (likely keys)
  /\b[0-9a-f]{32,}\b/gi,
  // Base64 blobs ≥ 40 chars preceded by known labels
  /(?<=(?:key|token|secret|password|credential|signature)["']?\s*[:=]\s*["']?)[A-Za-z0-9+/=]{40,}/gi,
];

/** Redact sensitive values in a string. */
export function redact(input: string, extraPatterns: RegExp[] = []): string {
  let result = input;
  for (const pat of [...DEFAULT_REDACT_PATTERNS, ...extraPatterns]) {
    result = result.replace(pat, "[REDACTED]");
  }
  return result;
}

/** Deep-redact an object (returns a new object). */
function redactObject(obj: unknown, patterns: RegExp[]): unknown {
  if (typeof obj === "string") return redact(obj, patterns);
  if (Array.isArray(obj)) return obj.map((v) => redactObject(v, patterns));
  if (obj !== null && typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = redactObject(v, patterns);
    }
    return out;
  }
  return obj;
}

// ── Hash chain ──────────────────────────────────────────────────────────────

/** Compute SHA-256 hex digest of a serialised log entry. */
export function sha256(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/** Verify an audit log hash chain. Returns the index of the first broken link, or -1 if intact. */
export function verifyHashChain(entries: AuditLogEntry[]): number {
  for (let i = 1; i < entries.length; i++) {
    const prev = entries[i - 1]!;
    const expected = sha256(JSON.stringify(prev));
    if (entries[i]!.prevHash !== expected) return i;
  }
  return -1;
}

// ── Log rotation ────────────────────────────────────────────────────────────

async function rotateIfNeeded(
  filePath: string,
  maxSizeMb: number,
  maxFiles: number,
): Promise<void> {
  try {
    const s = await stat(filePath);
    if (s.size < maxSizeMb * 1024 * 1024) return;
  } catch {
    return; // file doesn't exist yet
  }

  // Shift existing rotated files: .9 → .10 (dropped), .8 → .9, … .1 → .2
  for (let i = maxFiles - 1; i >= 1; i--) {
    try {
      await rename(`${filePath}.${i}`, `${filePath}.${i + 1}`);
    } catch {
      /* ignore missing */
    }
  }
  await rename(filePath, `${filePath}.1`);
}

// ── Writer functions ────────────────────────────────────────────────────────

type Writer = (line: string) => void | Promise<void>;

function consoleWriter(format: "json" | "pretty"): Writer {
  if (format === "json") {
    return (line: string) => {
      process.stderr.write(line + "\n");
    };
  }
  return (line: string) => {
    try {
      const entry = JSON.parse(line) as LogEntry;
      const ts = entry.ts.slice(11, 23); // HH:mm:ss.SSS
      const lvl = entry.level.padEnd(8);
      process.stderr.write(`${ts} ${lvl} [${entry.component}/${entry.module}] ${entry.msg}\n`);
    } catch {
      process.stderr.write(line + "\n");
    }
  };
}

function fileWriter(dest: LogDestination): Writer {
  const filePath = dest.path!;
  const maxSizeMb = dest.rotation?.maxSizeMb ?? 100;
  const maxFiles = dest.rotation?.maxFiles ?? 10;
  let ensured = false;

  return async (line: string) => {
    if (!ensured) {
      await mkdir(dirname(filePath), { recursive: true });
      ensured = true;
    }
    await rotateIfNeeded(filePath, maxSizeMb, maxFiles);
    await appendFile(filePath, line + "\n", "utf8");
  };
}

// ── Logger configuration ────────────────────────────────────────────────────

export interface LoggerConfig {
  component: Component;
  destinations: LogDestination[];
  redactPatterns?: RegExp[];
}

// ── Logger class ────────────────────────────────────────────────────────────

export class Logger {
  private component: Component;
  private destinations: Array<{ dest: LogDestination; write: Writer }>;
  private redactPatterns: RegExp[];
  private lastAuditHash = "0".repeat(64); // genesis hash

  constructor(config: LoggerConfig) {
    this.component = config.component;
    this.redactPatterns = config.redactPatterns ?? [];
    this.destinations = config.destinations.map((dest) => ({
      dest,
      write:
        dest.type === "console"
          ? consoleWriter(dest.format)
          : fileWriter(dest),
    }));
  }

  /** Get the current chain head hash (for testing / verification). */
  get chainHead(): string {
    return this.lastAuditHash;
  }

  // ── Convenience level methods ───────────────────────────────────────────

  trace(module: string, fn: string, msg: string, ctx?: Record<string, unknown>): void {
    void this.log("TRACE", module, fn, msg, ctx);
  }

  debug(module: string, fn: string, msg: string, ctx?: Record<string, unknown>): void {
    void this.log("DEBUG", module, fn, msg, ctx);
  }

  info(module: string, fn: string, msg: string, ctx?: Record<string, unknown>): void {
    void this.log("INFO", module, fn, msg, ctx);
  }

  warn(module: string, fn: string, msg: string, ctx?: Record<string, unknown>): void {
    void this.log("WARN", module, fn, msg, ctx);
  }

  error(module: string, fn: string, msg: string, ctx?: Record<string, unknown>, err?: ErrorDetail): void {
    void this.log("ERROR", module, fn, msg, ctx, err);
  }

  critical(module: string, fn: string, msg: string, ctx?: Record<string, unknown>, err?: ErrorDetail): void {
    void this.log("CRITICAL", module, fn, msg, ctx, err);
  }

  // ── Audit entry (security events) ──────────────────────────────────────

  async audit(params: {
    layer: SecurityLayer;
    event: AuditEventType;
    module: string;
    fn: string;
    msg: string;
    traceId?: string;
    attackClass?: AttackClass[];
    context?: Record<string, unknown>;
    durationMs?: number;
    error?: ErrorDetail;
  }): Promise<AuditLogEntry> {
    const entry: AuditLogEntry = {
      ts: new Date().toISOString(),
      level: params.event === "deny" || params.event === "alert" ? "WARN" : "INFO",
      component: this.component,
      module: params.module,
      fn: params.fn,
      msg: params.msg,
      traceId: params.traceId ?? newTraceId(),
      context: params.context ?? {},
      durationMs: params.durationMs,
      error: params.error,
      layer: params.layer,
      event: params.event,
      attackClass: params.attackClass,
      prevHash: this.lastAuditHash,
    };

    // Compute hash chain
    const serialised = JSON.stringify(entry);
    this.lastAuditHash = sha256(serialised);

    // Redact before writing
    const redacted = JSON.stringify(redactObject(entry, this.redactPatterns));

    // Write to all qualifying destinations
    const writes: Array<void | Promise<void>> = [];
    for (const { dest, write } of this.destinations) {
      if (meetsLevel(entry.level, dest.minLevel)) {
        writes.push(write(redacted));
      }
    }
    await Promise.all(writes);

    return entry;
  }

  // ── General log entry ──────────────────────────────────────────────────

  private async log(
    level: LogLevel,
    module: string,
    fn: string,
    msg: string,
    context?: Record<string, unknown>,
    error?: ErrorDetail,
    traceId?: string,
    durationMs?: number,
  ): Promise<void> {
    const entry: LogEntry = {
      ts: new Date().toISOString(),
      level,
      component: this.component,
      module,
      fn,
      msg,
      traceId: traceId ?? newTraceId(),
      context: context ?? {},
      durationMs,
      error,
    };

    const redacted = JSON.stringify(redactObject(entry, this.redactPatterns));

    const writes: Array<void | Promise<void>> = [];
    for (const { dest, write } of this.destinations) {
      if (meetsLevel(level, dest.minLevel)) {
        writes.push(write(redacted));
      }
    }
    await Promise.all(writes);
  }
}
