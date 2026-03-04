// ── Credential Redactor ─────────────────────────────────────────────────────
// Scans and redacts credentials, API keys, and PII from tool outputs,
// messages, and any content before persistence or delivery.

// ── Types ───────────────────────────────────────────────────────────────────

export interface RedactionPattern {
  name: string;
  pattern: RegExp;
  replacement: string;
  category: "credential" | "pii" | "internal";
}

export interface RedactionResult {
  original: string;
  redacted: string;
  redactionCount: number;
  redactedPatterns: string[];
  traceId?: string;
}

export interface RedactionEvent {
  traceId: string;
  patternName: string;
  category: string;
  count: number;
  timestamp: string;
}

// ── Patterns ────────────────────────────────────────────────────────────────

/** Credential patterns to redact. */
export const CREDENTIAL_PATTERNS: RedactionPattern[] = [
  {
    name: "anthropic-api-key",
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    replacement: "[ANTHROPIC-KEY-REDACTED]",
    category: "credential",
  },
  {
    name: "openai-api-key",
    pattern: /sk-[a-zA-Z0-9_-]{20,}/g,
    replacement: "[OPENAI-KEY-REDACTED]",
    category: "credential",
  },
  {
    name: "github-pat",
    pattern: /ghp_[a-zA-Z0-9]{36,}/g,
    replacement: "[GITHUB-PAT-REDACTED]",
    category: "credential",
  },
  {
    name: "github-oauth",
    pattern: /gho_[a-zA-Z0-9]{36,}/g,
    replacement: "[GITHUB-OAUTH-REDACTED]",
    category: "credential",
  },
  {
    name: "slack-bot-token",
    pattern: /xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+/g,
    replacement: "[SLACK-BOT-REDACTED]",
    category: "credential",
  },
  {
    name: "slack-user-token",
    pattern: /xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+/g,
    replacement: "[SLACK-USER-REDACTED]",
    category: "credential",
  },
  {
    name: "bearer-token",
    pattern: /Bearer\s+[a-zA-Z0-9._~+/=-]{20,}/g,
    replacement: "Bearer [TOKEN-REDACTED]",
    category: "credential",
  },
  {
    name: "aws-access-key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    replacement: "[AWS-KEY-REDACTED]",
    category: "credential",
  },
  {
    name: "aws-secret-key",
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}/g,
    replacement: "[AWS-SECRET-REDACTED]",
    category: "credential",
  },
  {
    name: "perplexity-api-key",
    pattern: /pplx-[a-zA-Z0-9]{32,}/g,
    replacement: "[PERPLEXITY-KEY-REDACTED]",
    category: "credential",
  },
  {
    name: "gmail-app-password",
    pattern: /(?:password|GMAIL_APP_PASSWORD|app[_\s-]?pass(?:word)?|smtp[_\s-]?pass(?:word)?)\s*[=:"']+\s*[a-z]{4}\s[a-z]{4}\s[a-z]{4}\s[a-z]{4}/gi,
    replacement: "[GMAIL-APP-PASSWORD-REDACTED]",
    category: "credential",
  },
  {
    name: "tomorrow-io-api-key",
    pattern: /(?:tomorrow[._-]?io[._-]?(?:api[._-]?)?key|TOMORROW_IO_API_KEY)\s*[=:]\s*[a-zA-Z0-9]{20,}/gi,
    replacement: "[TOMORROW-IO-KEY-REDACTED]",
    category: "credential",
  },
  {
    name: "generic-api-key-header",
    pattern: /(?:x-api-key|api[_-]key|apikey)\s*[=:]\s*[a-zA-Z0-9_-]{16,}/gi,
    replacement: "[API-KEY-REDACTED]",
    category: "credential",
  },
];

/** PII patterns to redact. Order matters: IPs before phones to avoid false matches. */
export const PII_PATTERNS: RedactionPattern[] = [
  {
    name: "email",
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    replacement: "[EMAIL-REDACTED]",
    category: "pii",
  },
  {
    name: "rfc1918-ip",
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    replacement: "[IP-REDACTED]",
    category: "pii",
  },
  {
    name: "phone-international",
    pattern: /\+[1-9]\d{1,2}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}/g,
    replacement: "[PHONE-REDACTED]",
    category: "pii",
  },
];

/** All patterns combined. */
export const ALL_PATTERNS: RedactionPattern[] = [
  ...CREDENTIAL_PATTERNS,
  ...PII_PATTERNS,
];

// ── Redactor ────────────────────────────────────────────────────────────────

export class CredentialRedactor {
  private patterns: RedactionPattern[];
  private eventLog: RedactionEvent[] = [];
  private onEvent?: (event: RedactionEvent) => void;

  constructor(
    patterns: RedactionPattern[] = ALL_PATTERNS,
    onEvent?: (event: RedactionEvent) => void,
  ) {
    this.patterns = patterns;
    this.onEvent = onEvent;
  }

  /** Redact all matching patterns from a string. */
  redact(input: string, traceId?: string): RedactionResult {
    let redacted = input;
    let totalCount = 0;
    const matched: string[] = [];

    for (const pat of this.patterns) {
      // Reset regex state (global flag)
      pat.pattern.lastIndex = 0;
      const matches = redacted.match(pat.pattern);

      if (matches && matches.length > 0) {
        const count = matches.length;
        totalCount += count;
        matched.push(pat.name);

        // Reset again before replace
        pat.pattern.lastIndex = 0;
        redacted = redacted.replace(pat.pattern, pat.replacement);

        if (traceId) {
          const event: RedactionEvent = {
            traceId,
            patternName: pat.name,
            category: pat.category,
            count,
            timestamp: new Date().toISOString(),
          };
          this.eventLog.push(event);
          this.onEvent?.(event);
        }
      }
    }

    return {
      original: input,
      redacted,
      redactionCount: totalCount,
      redactedPatterns: matched,
      traceId,
    };
  }

  /** Redact credentials from a structured object (deep). */
  redactObject(obj: unknown, traceId?: string): unknown {
    if (typeof obj === "string") {
      return this.redact(obj, traceId).redacted;
    }
    if (Array.isArray(obj)) {
      return obj.map((item) => this.redactObject(item, traceId));
    }
    if (obj !== null && typeof obj === "object") {
      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this.redactObject(value, traceId);
      }
      return result;
    }
    return obj;
  }

  /** Check if a string contains any credentials or PII. */
  containsSensitive(input: string): boolean {
    for (const pat of this.patterns) {
      pat.pattern.lastIndex = 0;
      if (pat.pattern.test(input)) {
        return true;
      }
    }
    return false;
  }

  /** Get event log. */
  getEventLog(): RedactionEvent[] {
    return [...this.eventLog];
  }

  /** Clear event log. */
  clearEventLog(): void {
    this.eventLog = [];
  }
}
