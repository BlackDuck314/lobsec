import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  CredentialRedactor,
  ALL_PATTERNS,
} from "./credential-redactor.js";
import type { RedactionEvent } from "./credential-redactor.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeRedactor(events: RedactionEvent[] = []) {
  return new CredentialRedactor(ALL_PATTERNS, (e) => events.push(e));
}

// ── Unit: Credential pattern redaction ──────────────────────────────────────

describe("Credential pattern redaction", () => {
  it("redacts Anthropic API key", () => {
    const r = makeRedactor();
    const result = r.redact("Key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456");
    expect(result.redacted).toContain("[ANTHROPIC-KEY-REDACTED]");
    expect(result.redacted).not.toContain("sk-ant-");
    expect(result.redactionCount).toBe(1);
  });

  it("redacts OpenAI API key", () => {
    const r = makeRedactor();
    const result = r.redact("Key: sk-proj-abcdefghijklmnopqrstuvwxyz");
    expect(result.redacted).toContain("[OPENAI-KEY-REDACTED]");
    expect(result.redacted).not.toContain("sk-proj-");
  });

  it("redacts GitHub PAT", () => {
    const r = makeRedactor();
    const result = r.redact("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234");
    expect(result.redacted).toContain("[GITHUB-PAT-REDACTED]");
    expect(result.redacted).not.toContain("ghp_");
  });

  it("redacts Slack bot token", () => {
    const r = makeRedactor();
    const result = r.redact("Token: xoxb-123456-789012-abcdef123456");
    expect(result.redacted).toContain("[SLACK-BOT-REDACTED]");
    expect(result.redacted).not.toContain("xoxb-");
  });

  it("redacts Bearer token", () => {
    const r = makeRedactor();
    const result = r.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0");
    expect(result.redacted).toContain("Bearer [TOKEN-REDACTED]");
  });

  it("redacts AWS access key", () => {
    const r = makeRedactor();
    const result = r.redact("AWS: AKIAIOSFODNN7EXAMPLE");
    expect(result.redacted).toContain("[AWS-KEY-REDACTED]");
    expect(result.redacted).not.toContain("AKIA");
  });

  it("redacts multiple credentials in one string", () => {
    const r = makeRedactor();
    const input = "API: sk-proj-abcdefghijklmnopqrstuvwxyz, Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234";
    const result = r.redact(input);
    expect(result.redactionCount).toBeGreaterThanOrEqual(2);
    expect(result.redacted).not.toContain("sk-proj-");
    expect(result.redacted).not.toContain("ghp_");
  });

  it("redacts Perplexity API key", () => {
    const r = makeRedactor();
    const result = r.redact("Key: pplx-00000000000000000000000000000000FAKEFAKE00000000");
    expect(result.redacted).toContain("[PERPLEXITY-KEY-REDACTED]");
    expect(result.redacted).not.toContain("pplx-");
  });

  it("redacts Gmail app password pattern with context", () => {
    const r = makeRedactor();
    const result = r.redact("Password: enjl ftyn kdzz lzqe");
    expect(result.redacted).toContain("[GMAIL-APP-PASSWORD-REDACTED]");
    expect(result.redacted).not.toContain("enjl ftyn kdzz lzqe");
  });

  it("redacts Gmail app password in env var format", () => {
    const r = makeRedactor();
    const result = r.redact('GMAIL_APP_PASSWORD="enjl ftyn kdzz lzqe"');
    expect(result.redacted).toContain("[GMAIL-APP-PASSWORD-REDACTED]");
  });

  it("does NOT false-positive on normal English four-letter words", () => {
    const r = makeRedactor();
    // These are four groups of 4-letter lowercase words — old pattern matched them
    const falsePositives = [
      "sent your test mail",
      "this will send from",
      "want some more help",
      "have been done with",
    ];
    for (const text of falsePositives) {
      const result = r.redact(text);
      expect(result.redacted).toBe(text);
      expect(result.redactionCount).toBe(0);
    }
  });

  it("redacts Tomorrow.io API key in context", () => {
    const r = makeRedactor();
    const result = r.redact("TOMORROW_IO_API_KEY=FAKE0tomorrow0key00000000000000AB");
    expect(result.redacted).toContain("[TOMORROW-IO-KEY-REDACTED]");
    expect(result.redacted).not.toContain("FAKE0tomorrow0key00000000000000AB");
  });
});

// ── Unit: PII pattern redaction ─────────────────────────────────────────────

describe("PII pattern redaction", () => {
  it("redacts email addresses", () => {
    const r = makeRedactor();
    const result = r.redact("Contact: user@example.com");
    expect(result.redacted).toContain("[EMAIL-REDACTED]");
    expect(result.redacted).not.toContain("user@example.com");
  });

  it("redacts RFC1918 IPs (10.x)", () => {
    const r = makeRedactor();
    const result = r.redact("Server: 10.0.0.1");
    expect(result.redacted).toContain("[IP-REDACTED]");
    expect(result.redacted).not.toContain("10.0.0.1");
  });

  it("redacts RFC1918 IPs (172.16.x)", () => {
    const r = makeRedactor();
    const result = r.redact("Host: 172.16.0.5");
    expect(result.redacted).toContain("[IP-REDACTED]");
  });

  it("redacts RFC1918 IPs (192.168.x)", () => {
    const r = makeRedactor();
    const result = r.redact("LAN: 192.168.1.100");
    expect(result.redacted).toContain("[IP-REDACTED]");
  });

  it("does not redact public IPs", () => {
    const r = makeRedactor();
    const result = r.redact("Server: 8.8.8.8");
    expect(result.redacted).toBe("Server: 8.8.8.8");
  });
});

// ── Unit: Object redaction ──────────────────────────────────────────────────

describe("Object redaction", () => {
  it("redacts nested object strings", () => {
    const r = makeRedactor();
    const obj = {
      result: {
        output: "Found key: sk-proj-abcdefghijklmnopqrstuvwxyz",
        metadata: { ip: "10.0.0.1" },
      },
    };
    const redacted = r.redactObject(obj) as Record<string, unknown>;
    const output = JSON.stringify(redacted);
    expect(output).not.toContain("sk-proj-");
    expect(output).not.toContain("10.0.0.1");
  });

  it("redacts arrays of strings", () => {
    const r = makeRedactor();
    const arr = ["safe text", "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"];
    const redacted = r.redactObject(arr) as string[];
    expect(redacted[1]).toContain("[GITHUB-PAT-REDACTED]");
  });

  it("leaves non-string values intact", () => {
    const r = makeRedactor();
    const obj = { count: 42, active: true, empty: null };
    const redacted = r.redactObject(obj);
    expect(redacted).toEqual(obj);
  });
});

// ── Unit: containsSensitive ─────────────────────────────────────────────────

describe("containsSensitive", () => {
  it("detects credentials", () => {
    const r = makeRedactor();
    expect(r.containsSensitive("sk-proj-abcdefghijklmnopqrstuvwxyz")).toBe(true);
  });

  it("detects PII", () => {
    const r = makeRedactor();
    expect(r.containsSensitive("user@example.com")).toBe(true);
  });

  it("returns false for safe text", () => {
    const r = makeRedactor();
    expect(r.containsSensitive("Hello world, this is safe text")).toBe(false);
  });
});

// ── Unit: Event logging ─────────────────────────────────────────────────────

describe("Redaction event logging", () => {
  it("logs redaction events with trace ID", () => {
    const events: RedactionEvent[] = [];
    const r = makeRedactor(events);
    r.redact("Key: sk-proj-abcdefghijklmnopqrstuvwxyz", "tr_test");

    expect(events.length).toBeGreaterThan(0);
    expect(events[0]!.traceId).toBe("tr_test");
    expect(events[0]!.patternName).toBeDefined();
    expect(events[0]!.count).toBeGreaterThan(0);
  });

  it("event log never contains redacted values", () => {
    const events: RedactionEvent[] = [];
    const r = makeRedactor(events);
    const secret = "sk-proj-supersecretapikey12345678";
    r.redact(`API: ${secret}`, "tr_test");

    const logStr = JSON.stringify(events);
    expect(logStr).not.toContain(secret);
  });
});

// ── Property 24: Credential pattern redaction ───────────────────────────────

describe("Property 24: Credential pattern redaction", () => {
  it("all known credential formats are always redacted", () => {
    const r = makeRedactor();
    const credentialSamples = [
      "sk-ant-api03-" + "a".repeat(30),
      "sk-proj-" + "b".repeat(30),
      "ghp_" + "c".repeat(40),
      "xoxb-111-222-abc123",
      "Bearer " + "d".repeat(40),
      "AKIAIOSFODNN7EXAMPLE",
    ];

    fc.assert(
      fc.property(
        fc.constantFrom(...credentialSamples),
        fc.string({ minLength: 0, maxLength: 50 }),
        (credential, prefix) => {
          const input = `${prefix} ${credential} end`;
          const result = r.redact(input);
          expect(result.redacted).not.toContain(credential);
          expect(result.redactionCount).toBeGreaterThan(0);
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 25: PII pattern redaction ──────────────────────────────────────

describe("Property 25: PII pattern redaction", () => {
  it("email addresses are always redacted", () => {
    const r = makeRedactor();

    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z]{3,10}$/),
        fc.constantFrom("gmail.com", "example.com", "company.org"),
        (user, domain) => {
          const email = `${user}@${domain}`;
          const result = r.redact(`Contact: ${email}`);
          expect(result.redacted).not.toContain(email);
          expect(result.redacted).toContain("[EMAIL-REDACTED]");
        },
      ),
      { numRuns: 20 },
    );
  });

  it("RFC1918 IPs are always redacted", () => {
    const r = makeRedactor();

    fc.assert(
      fc.property(
        fc.constantFrom(
          "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
          "192.168.0.1", "192.168.255.255",
        ),
        (ip) => {
          const result = r.redact(`Server at ${ip}`);
          expect(result.redacted).not.toContain(ip);
          expect(result.redacted).toContain("[IP-REDACTED]");
        },
      ),
      { numRuns: 10 },
    );
  });
});

// ── Property 26: Redaction before persistence ───────────────────────────────

describe("Property 26: Redaction before persistence", () => {
  it("redacted output never contains original credentials", () => {
    const r = makeRedactor();

    fc.assert(
      fc.property(
        fc.string({ minLength: 5, maxLength: 100 }),
        (context) => {
          // Inject a known credential into context
          const credential = "sk-ant-api03-" + "x".repeat(30);
          const input = `${context} ${credential} ${context}`;
          const result = r.redact(input);

          // Redacted output must not contain the credential
          expect(result.redacted).not.toContain(credential);

          // Original is preserved in result for comparison
          expect(result.original).toContain(credential);
        },
      ),
      { numRuns: 20 },
    );
  });

  it("deep object redaction catches nested credentials", () => {
    const r = makeRedactor();

    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 5 }),
        (depth) => {
          const credential = "ghp_" + "A".repeat(40);
          let obj: unknown = `Secret: ${credential}`;

          // Wrap in nested objects
          for (let i = 0; i < depth; i++) {
            obj = { [`level${i}`]: obj };
          }

          const redacted = r.redactObject(obj);
          const serialized = JSON.stringify(redacted);
          expect(serialized).not.toContain(credential);
          expect(serialized).toContain("[GITHUB-PAT-REDACTED]");
        },
      ),
      { numRuns: 10 },
    );
  });
});
