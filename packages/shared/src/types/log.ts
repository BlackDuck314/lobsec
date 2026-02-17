/** Log levels from most to least verbose */
export type LogLevel = "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" | "CRITICAL";

/** Security layers L1-L9 */
export type SecurityLayer = "L1" | "L2" | "L3" | "L4" | "L5" | "L6" | "L7" | "L8" | "L9";

/** Audit event outcomes */
export type AuditEventType = "allow" | "deny" | "alert" | "error";

/** Attack class IDs (1-12) */
export type AttackClass = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;

/** The three lobsec components */
export type Component = "lobsec-cli" | "lobsec-plugin" | "lobsec-proxy";

/** Base log entry -- every log line has these fields */
export interface LogEntry {
  /** ISO-8601 timestamp with millisecond precision */
  ts: string;
  level: LogLevel;
  component: Component;
  module: string;
  fn: string;
  msg: string;
  traceId: string;
  context: Record<string, unknown>;
  durationMs?: number;
  error?: ErrorDetail;
}

export interface ErrorDetail {
  message: string;
  stack?: string;
  code?: string;
}

/** Audit log entry -- extends LogEntry with security metadata */
export interface AuditLogEntry extends LogEntry {
  layer: SecurityLayer;
  event: AuditEventType;
  attackClass?: AttackClass[];
  prevHash: string;
  hsmSignature?: string;
}

/** Log destination configuration */
export interface LogDestination {
  type: "console" | "file" | "audit";
  minLevel: LogLevel;
  format: "json" | "pretty";
  path?: string;
  rotation?: LogRotation;
}

export interface LogRotation {
  maxSizeMb: number;
  maxFiles: number;
  compress: boolean;
}
