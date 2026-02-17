// ── Tool Call Validator ──────────────────────────────────────────────────────
// Validates tool calls before execution: path containment, symlink resolution,
// tools.deny enforcement, command consistency, and audit logging.

import { REQUIRED_TOOLS_DENY } from "@lobsec/shared";
import { resolve, relative, isAbsolute } from "node:path";

// ── Types ───────────────────────────────────────────────────────────────────

export interface ToolCallRequest {
  tool: string;
  args: Record<string, unknown>;
  rawCommand?: string;
  commandParts?: string[];
  filePath?: string;
  traceId: string;
}

export type ValidationAction = "allow" | "deny";

export interface ValidationResult {
  action: ValidationAction;
  tool: string;
  reasons: string[];
  attackClasses: number[];
  traceId: string;
  checkedAt: string;
  durationMs: number;
}

export interface ToolValidatorConfig {
  /** Workspace root (all file operations must stay within). */
  workspaceRoot: string;
  /** Additional denied tools beyond REQUIRED_TOOLS_DENY. */
  additionalDenyList: string[];
  /** Dangerous command patterns to block. */
  dangerousPatterns: RegExp[];
  /** Callback for validation events. */
  onValidation?: (result: ValidationResult) => void;
  /** Custom path resolver (for testing). */
  resolvePath?: (p: string) => string;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Default dangerous command patterns. */
export const DEFAULT_DANGEROUS_PATTERNS: RegExp[] = [
  /\brm\s+-rf\s+\/(?!\w)/,      // rm -rf / (root delete)
  /\bchmod\s+777\b/,             // world-writable permissions
  /\bcurl\s+.*\|\s*(?:bash|sh)/, // curl pipe to shell
  /\bwget\s+.*\|\s*(?:bash|sh)/, // wget pipe to shell
  /\beval\b/,                    // eval command
  /\bdd\s+.*of=\/dev\//,         // dd to raw device
  /\bnc\s+-[el]/,                // netcat listener
  /\bpython.*-c.*import\s+os/,   // python os import inline
  /\bsudo\b/,                    // sudo usage
  /\bchown\s+root/,              // chown to root
];

// ── Path Validation ─────────────────────────────────────────────────────────

/** Canonicalize a path and check workspace containment. */
export function validatePath(
  filePath: string,
  workspaceRoot: string,
  resolvePath: (p: string) => string = resolve,
): { valid: boolean; canonicalPath: string; reason?: string } {
  // Resolve to absolute
  const canonical = resolvePath(filePath);
  const rootResolved = resolvePath(workspaceRoot);

  // Check containment
  const rel = relative(rootResolved, canonical);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    return {
      valid: false,
      canonicalPath: canonical,
      reason: `Path escapes workspace: ${canonical} is outside ${rootResolved}`,
    };
  }

  // Check for null bytes
  if (filePath.includes("\0")) {
    return {
      valid: false,
      canonicalPath: canonical,
      reason: "Path contains null byte",
    };
  }

  return { valid: true, canonicalPath: canonical };
}

/** Resolve symlinks and validate the real path. */
export function validateSymlink(
  filePath: string,
  workspaceRoot: string,
  realPath: string,
): { valid: boolean; reason?: string } {
  const rootResolved = resolve(workspaceRoot);
  const resolvedRealPath = resolve(realPath);

  const rel = relative(rootResolved, resolvedRealPath);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    return {
      valid: false,
      reason: `Symlink target escapes workspace: ${resolvedRealPath} is outside ${rootResolved}`,
    };
  }

  return { valid: true };
}

// ── Tool Deny List ──────────────────────────────────────────────────────────

/** Check if a tool is on the deny list. */
export function isToolDenied(
  tool: string,
  additionalDenyList: string[] = [],
): { denied: boolean; reason?: string } {
  const fullDenyList = [...REQUIRED_TOOLS_DENY, ...additionalDenyList];

  for (const pattern of fullDenyList) {
    if (tool === pattern || tool.includes(pattern)) {
      return { denied: true, reason: `Tool matches deny pattern: ${pattern}` };
    }
  }

  return { denied: false };
}

// ── Command Validation ──────────────────────────────────────────────────────

/** Validate rawCommand matches commandParts (detect injection). */
export function validateCommandConsistency(
  rawCommand: string | undefined,
  commandParts: string[] | undefined,
): { consistent: boolean; reason?: string } {
  if (!rawCommand || !commandParts || commandParts.length === 0) {
    return { consistent: true }; // Can't validate without both
  }

  // Check that all parts appear in the raw command
  const allPartsPresent = commandParts.every((part) => rawCommand.includes(part));
  if (!allPartsPresent) {
    return {
      consistent: false,
      reason: `rawCommand "${rawCommand}" doesn't match command parts [${commandParts.join(", ")}]`,
    };
  }

  return { consistent: true };
}

/** Check a command string against dangerous patterns. */
export function checkDangerousCommand(
  command: string,
  patterns: RegExp[] = DEFAULT_DANGEROUS_PATTERNS,
): { dangerous: boolean; matchedPatterns: string[] } {
  const matched: string[] = [];
  for (const pattern of patterns) {
    if (pattern.test(command)) {
      matched.push(pattern.source);
    }
  }
  return { dangerous: matched.length > 0, matchedPatterns: matched };
}

// ── Full Validator ──────────────────────────────────────────────────────────

export class ToolValidator {
  private config: ToolValidatorConfig;

  constructor(config: ToolValidatorConfig) {
    this.config = config;
  }

  /** Validate a tool call. Returns allow/deny with reasons. */
  validate(request: ToolCallRequest): ValidationResult {
    const start = Date.now();
    const reasons: string[] = [];
    const attackClasses: number[] = [];
    let action: ValidationAction = "allow";

    // 1. Check deny list
    const denyCheck = isToolDenied(request.tool, this.config.additionalDenyList);
    if (denyCheck.denied) {
      action = "deny";
      reasons.push(denyCheck.reason!);
      attackClasses.push(4); // Attack class 4: tool abuse
    }

    // 2. Validate file path if present
    if (request.filePath) {
      const pathCheck = validatePath(
        request.filePath,
        this.config.workspaceRoot,
        this.config.resolvePath,
      );
      if (!pathCheck.valid) {
        action = "deny";
        reasons.push(pathCheck.reason!);
        attackClasses.push(5); // Attack class 5: path traversal
      }
    }

    // 3. Validate command consistency
    const cmdCheck = validateCommandConsistency(request.rawCommand, request.commandParts);
    if (!cmdCheck.consistent) {
      action = "deny";
      reasons.push(cmdCheck.reason!);
      attackClasses.push(6); // Attack class 6: command injection
    }

    // 4. Check dangerous command patterns
    if (request.rawCommand) {
      const dangerCheck = checkDangerousCommand(request.rawCommand, this.config.dangerousPatterns);
      if (dangerCheck.dangerous) {
        action = "deny";
        reasons.push(`Dangerous command pattern: ${dangerCheck.matchedPatterns.join(", ")}`);
        attackClasses.push(6); // Attack class 6: command injection
      }
    }

    if (action === "allow") {
      reasons.push("all checks passed");
    }

    const result: ValidationResult = {
      action,
      tool: request.tool,
      reasons,
      attackClasses: [...new Set(attackClasses)],
      traceId: request.traceId,
      checkedAt: new Date().toISOString(),
      durationMs: Date.now() - start,
    };

    this.config.onValidation?.(result);
    return result;
  }
}
