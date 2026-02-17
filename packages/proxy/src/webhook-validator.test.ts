import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import * as fc from "fast-check";
import {
  validateTelegram,
  validateSlack,
  validateTwilio,
  validateWhatsApp,
  isTimestampFresh,
  validateStartupGate,
} from "./webhook-validator.js";
import type { WebhookRequest, WebhookValidationResult, ChannelType, ChannelConfig } from "./webhook-validator.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function slackSign(body: string, secret: string, timestamp: number): { signature: string; timestamp: string } {
  const basestring = `v0:${timestamp}:${body}`;
  const sig = "v0=" + createHmac("sha256", secret).update(basestring).digest("hex");
  return { signature: sig, timestamp: String(timestamp) };
}

function whatsAppSign(body: string, secret: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

function twilioSign(url: string, body: string, token: string): string {
  let dataString = url;
  try {
    const params = new URLSearchParams(body);
    const sorted = [...params.entries()].sort(([a], [b]) => a.localeCompare(b));
    for (const [key, value] of sorted) {
      dataString += key + value;
    }
  } catch { /* empty */ }
  return createHmac("sha1", token).update(dataString).digest("base64");
}

// ── Unit: isTimestampFresh ────────────────────────────────────────────────

describe("isTimestampFresh", () => {
  it("accepts current timestamp", () => {
    expect(isTimestampFresh(nowSec())).toBe(true);
  });

  it("accepts timestamp 4 minutes ago", () => {
    expect(isTimestampFresh(nowSec() - 240)).toBe(true);
  });

  it("rejects timestamp 6 minutes ago", () => {
    expect(isTimestampFresh(nowSec() - 360)).toBe(false);
  });

  it("rejects future timestamp", () => {
    expect(isTimestampFresh(nowSec() + 60)).toBe(false);
  });
});

// ── Unit: validateTelegram ────────────────────────────────────────────────

describe("validateTelegram", () => {
  const secret = "my-telegram-secret";

  it("accepts valid token", () => {
    const req: WebhookRequest = {
      headers: { "x-telegram-bot-api-secret-token": secret },
      body: '{"update_id": 1}',
    };
    expect(validateTelegram(req, secret).valid).toBe(true);
  });

  it("rejects missing header", () => {
    const req: WebhookRequest = { headers: {}, body: '{}' };
    const result = validateTelegram(req, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("missing");
  });

  it("rejects wrong token", () => {
    const req: WebhookRequest = {
      headers: { "x-telegram-bot-api-secret-token": "wrong" },
      body: '{}',
    };
    expect(validateTelegram(req, secret).valid).toBe(false);
  });
});

// ── Unit: validateSlack ───────────────────────────────────────────────────

describe("validateSlack", () => {
  const signingSecret = "slack-signing-secret-123";

  it("accepts valid signature", () => {
    const body = '{"text":"hello"}';
    const ts = nowSec();
    const { signature, timestamp } = slackSign(body, signingSecret, ts);

    const req: WebhookRequest = {
      headers: { "x-slack-signature": signature, "x-slack-request-timestamp": timestamp },
      body,
      receivedAt: Date.now(),
    };
    expect(validateSlack(req, signingSecret).valid).toBe(true);
  });

  it("rejects missing headers", () => {
    const req: WebhookRequest = { headers: {}, body: '{}' };
    expect(validateSlack(req, signingSecret).valid).toBe(false);
  });

  it("rejects old timestamp", () => {
    const body = '{"text":"hello"}';
    const ts = nowSec() - 600; // 10 minutes ago
    const { signature, timestamp } = slackSign(body, signingSecret, ts);

    const req: WebhookRequest = {
      headers: { "x-slack-signature": signature, "x-slack-request-timestamp": timestamp },
      body,
      receivedAt: Date.now(),
    };
    const result = validateSlack(req, signingSecret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("replay");
  });

  it("rejects wrong signature", () => {
    const body = '{"text":"hello"}';
    const ts = nowSec();
    const req: WebhookRequest = {
      headers: {
        "x-slack-signature": "v0=" + "a".repeat(64),
        "x-slack-request-timestamp": String(ts),
      },
      body,
      receivedAt: Date.now(),
    };
    expect(validateSlack(req, signingSecret).valid).toBe(false);
  });
});

// ── Unit: validateWhatsApp ────────────────────────────────────────────────

describe("validateWhatsApp", () => {
  const appSecret = "whatsapp-app-secret";

  it("accepts valid signature", () => {
    const body = '{"entry":[]}';
    const signature = whatsAppSign(body, appSecret);
    const req: WebhookRequest = {
      headers: { "x-hub-signature-256": signature },
      body,
    };
    expect(validateWhatsApp(req, appSecret).valid).toBe(true);
  });

  it("rejects missing header", () => {
    const req: WebhookRequest = { headers: {}, body: '{}' };
    expect(validateWhatsApp(req, appSecret).valid).toBe(false);
  });

  it("rejects wrong signature", () => {
    const req: WebhookRequest = {
      headers: { "x-hub-signature-256": "sha256=" + "b".repeat(64) },
      body: '{}',
    };
    expect(validateWhatsApp(req, appSecret).valid).toBe(false);
  });
});

// ── Unit: validateTwilio ──────────────────────────────────────────────────

describe("validateTwilio", () => {
  const authToken = "twilio-auth-token-123";
  const requestUrl = "https://example.com/webhook/twilio";

  it("accepts valid signature", () => {
    const body = "Body=Hello&From=%2B1234567890";
    const signature = twilioSign(requestUrl, body, authToken);
    const req: WebhookRequest = {
      headers: { "x-twilio-signature": signature },
      body,
    };
    expect(validateTwilio(req, authToken, requestUrl).valid).toBe(true);
  });

  it("rejects missing header", () => {
    const req: WebhookRequest = { headers: {}, body: "" };
    expect(validateTwilio(req, authToken, requestUrl).valid).toBe(false);
  });

  it("rejects wrong signature", () => {
    const req: WebhookRequest = {
      headers: { "x-twilio-signature": "wrong-base64==" },
      body: "Body=test",
    };
    expect(validateTwilio(req, authToken, requestUrl).valid).toBe(false);
  });
});

// ── Unit: validateStartupGate ─────────────────────────────────────────────

describe("validateStartupGate", () => {
  it("passes when all enabled channels have secrets", () => {
    const channels: ChannelConfig[] = [
      { type: "telegram", enabled: true, hasSecret: true },
      { type: "slack", enabled: true, hasSecret: true },
      { type: "discord", enabled: false, hasSecret: false },
    ];
    expect(validateStartupGate(channels)).toEqual([]);
  });

  it("fails for enabled channel without secret", () => {
    const channels: ChannelConfig[] = [
      { type: "telegram", enabled: true, hasSecret: false },
      { type: "slack", enabled: true, hasSecret: true },
    ];
    expect(validateStartupGate(channels)).toEqual(["telegram"]);
  });

  it("ignores disabled channels without secrets", () => {
    const channels: ChannelConfig[] = [
      { type: "telegram", enabled: false, hasSecret: false },
    ];
    expect(validateStartupGate(channels)).toEqual([]);
  });

  it("reports multiple missing", () => {
    const channels: ChannelConfig[] = [
      { type: "telegram", enabled: true, hasSecret: false },
      { type: "slack", enabled: true, hasSecret: false },
      { type: "discord", enabled: true, hasSecret: false },
    ];
    expect(validateStartupGate(channels)).toEqual(["telegram", "slack", "discord"]);
  });
});

// ── Property 27: Webhook signature verification ──────────────────────────

describe("Property 27: Webhook signature verification", () => {
  it("correctly signed Slack messages always validate", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 200 }),
        fc.string({ minLength: 8, maxLength: 64 }),
        (body, secret) => {
          const ts = nowSec();
          const { signature, timestamp } = slackSign(body, secret, ts);
          const req: WebhookRequest = {
            headers: { "x-slack-signature": signature, "x-slack-request-timestamp": timestamp },
            body,
            receivedAt: Date.now(),
          };
          expect(validateSlack(req, secret).valid).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("correctly signed WhatsApp messages always validate", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 200 }),
        fc.string({ minLength: 8, maxLength: 64 }),
        (body, secret) => {
          const signature = whatsAppSign(body, secret);
          const req: WebhookRequest = {
            headers: { "x-hub-signature-256": signature },
            body,
          };
          expect(validateWhatsApp(req, secret).valid).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("Telegram with correct token always validates", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        (secret) => {
          const req: WebhookRequest = {
            headers: { "x-telegram-bot-api-secret-token": secret },
            body: '{}',
          };
          expect(validateTelegram(req, secret).valid).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("wrong secret always fails (Slack)", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 200 }),
        fc.string({ minLength: 8, maxLength: 64 }),
        fc.string({ minLength: 8, maxLength: 64 }),
        (body, correctSecret, wrongSecret) => {
          fc.pre(correctSecret !== wrongSecret);
          const ts = nowSec();
          const { signature, timestamp } = slackSign(body, correctSecret, ts);
          const req: WebhookRequest = {
            headers: { "x-slack-signature": signature, "x-slack-request-timestamp": timestamp },
            body,
            receivedAt: Date.now(),
          };
          expect(validateSlack(req, wrongSecret).valid).toBe(false);
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 28: Webhook timestamp validation ────────────────────────────

describe("Property 28: Webhook timestamp validation", () => {
  it("timestamps within 5 minutes are always fresh", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 299 }),
        (ageSec) => {
          const now = Date.now();
          const ts = Math.floor(now / 1000) - ageSec;
          expect(isTimestampFresh(ts, now)).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("timestamps older than 5 minutes are always stale", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 301, max: 86400 }),
        (ageSec) => {
          const now = Date.now();
          const ts = Math.floor(now / 1000) - ageSec;
          expect(isTimestampFresh(ts, now)).toBe(false);
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ── Property 29: Webhook verification logging ────────────────────────────

describe("Property 29: Webhook verification logging", () => {
  it("every validation result has a channel field", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<ChannelType>("telegram", "slack", "whatsapp"),
        fc.string({ minLength: 1, maxLength: 50 }),
        (channel, body) => {
          const req: WebhookRequest = { headers: {}, body };
          let result: WebhookValidationResult;
          switch (channel) {
            case "telegram":
              result = validateTelegram(req, "secret");
              break;
            case "slack":
              result = validateSlack(req, "secret");
              break;
            case "whatsapp":
              result = validateWhatsApp(req, "secret");
              break;
          }
          expect(result!.channel).toBe(channel);
          expect(typeof result!.valid).toBe("boolean");
        },
      ),
      { numRuns: 30 },
    );
  });

  it("failed validations always have a reason", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<ChannelType>("telegram", "slack", "whatsapp"),
        (channel) => {
          const req: WebhookRequest = { headers: {}, body: "{}" };
          let result: WebhookValidationResult;
          switch (channel) {
            case "telegram":
              result = validateTelegram(req, "secret");
              break;
            case "slack":
              result = validateSlack(req, "secret");
              break;
            case "whatsapp":
              result = validateWhatsApp(req, "secret");
              break;
          }
          if (!result!.valid) {
            expect(result!.reason).toBeDefined();
            expect(result!.reason!.length).toBeGreaterThan(0);
          }
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Property 30: Webhook secret startup gate ─────────────────────────────

describe("Property 30: Webhook secret startup gate", () => {
  const channelTypeArb = fc.constantFrom<ChannelType>("telegram", "slack", "discord", "twilio", "whatsapp");

  it("enabled channels without secrets always fail the gate", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            type: channelTypeArb,
            enabled: fc.constant(true),
            hasSecret: fc.constant(false),
          }),
          { minLength: 1, maxLength: 5 },
        ),
        (channels) => {
          const missing = validateStartupGate(channels);
          expect(missing.length).toBe(channels.length);
        },
      ),
      { numRuns: 30 },
    );
  });

  it("all channels with secrets always pass the gate", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            type: channelTypeArb,
            enabled: fc.boolean(),
            hasSecret: fc.constant(true),
          }),
          { minLength: 0, maxLength: 5 },
        ),
        (channels) => {
          expect(validateStartupGate(channels)).toEqual([]);
        },
      ),
      { numRuns: 30 },
    );
  });

  it("disabled channels never appear in missing list", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            type: channelTypeArb,
            enabled: fc.constant(false),
            hasSecret: fc.boolean(),
          }),
          { minLength: 0, maxLength: 5 },
        ),
        (channels) => {
          expect(validateStartupGate(channels)).toEqual([]);
        },
      ),
      { numRuns: 30 },
    );
  });
});
