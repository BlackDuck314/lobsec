// ── Webhook Validation (L3) ─────────────────────────────────────────────────
// Per-channel signature verification, replay protection, and startup gating.

import { createHmac, timingSafeEqual } from "node:crypto";

// ── Types ───────────────────────────────────────────────────────────────────

export type ChannelType = "telegram" | "slack" | "discord" | "twilio" | "whatsapp";

export interface WebhookValidationResult {
  valid: boolean;
  channel: ChannelType;
  reason?: string;
}

export interface WebhookRequest {
  headers: Record<string, string | undefined>;
  body: string;
  receivedAt?: number; // epoch ms
}

// ── Replay protection ───────────────────────────────────────────────────────

/** Maximum age of a webhook request in milliseconds (5 minutes). */
export const MAX_WEBHOOK_AGE_MS = 5 * 60 * 1000;

/**
 * Check if a timestamp is too old (replay protection).
 * Returns true if the timestamp is within the acceptable window.
 */
export function isTimestampFresh(
  timestampSec: number,
  nowMs: number = Date.now(),
): boolean {
  const ageMs = nowMs - timestampSec * 1000;
  return ageMs >= 0 && ageMs <= MAX_WEBHOOK_AGE_MS;
}

// ── Telegram ────────────────────────────────────────────────────────────────

/**
 * Validate a Telegram webhook.
 * Telegram uses X-Telegram-Bot-Api-Secret-Token header (plain token comparison).
 */
export function validateTelegram(
  req: WebhookRequest,
  secret: string,
): WebhookValidationResult {
  const token = req.headers["x-telegram-bot-api-secret-token"];
  if (!token) {
    return { valid: false, channel: "telegram", reason: "missing secret token header" };
  }

  const tokenBuf = Buffer.from(token);
  const secretBuf = Buffer.from(secret);

  if (tokenBuf.length !== secretBuf.length) {
    return { valid: false, channel: "telegram", reason: "invalid secret token" };
  }

  if (!timingSafeEqual(tokenBuf, secretBuf)) {
    return { valid: false, channel: "telegram", reason: "invalid secret token" };
  }

  return { valid: true, channel: "telegram" };
}

// ── Slack ────────────────────────────────────────────────────────────────────

/**
 * Validate a Slack webhook.
 * Slack uses HMAC-SHA256 with v0:<timestamp>:<body> format.
 */
export function validateSlack(
  req: WebhookRequest,
  signingSecret: string,
): WebhookValidationResult {
  const signature = req.headers["x-slack-signature"];
  const timestamp = req.headers["x-slack-request-timestamp"];

  if (!signature || !timestamp) {
    return { valid: false, channel: "slack", reason: "missing signature or timestamp" };
  }

  const ts = parseInt(timestamp, 10);
  if (isNaN(ts) || !isTimestampFresh(ts, req.receivedAt)) {
    return { valid: false, channel: "slack", reason: "timestamp too old (replay)" };
  }

  const basestring = `v0:${timestamp}:${req.body}`;
  const expected = "v0=" + createHmac("sha256", signingSecret)
    .update(basestring)
    .digest("hex");

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);

  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    return { valid: false, channel: "slack", reason: "invalid signature" };
  }

  return { valid: true, channel: "slack" };
}

// ── Discord ─────────────────────────────────────────────────────────────────

/**
 * Validate a Discord webhook.
 * Discord uses Ed25519 signatures (timestamp + body signed with public key).
 * NOTE: Ed25519 verification requires the `tweetnacl` package or Node.js built-in.
 * For Phase 2 we provide the validation interface; full Ed25519 is Phase 3.
 */
export function validateDiscord(
  req: WebhookRequest,
  publicKey: string,
): WebhookValidationResult {
  const signature = req.headers["x-signature-ed25519"];
  const timestamp = req.headers["x-signature-timestamp"];

  if (!signature || !timestamp) {
    return { valid: false, channel: "discord", reason: "missing signature or timestamp" };
  }

  // Ed25519 verification
  // Node.js 22 has crypto.verify with Ed25519 support
  try {
    const { verify, createPublicKey } = require("node:crypto");
    const message = Buffer.from(timestamp + req.body);
    const sig = Buffer.from(signature, "hex");
    const key = createPublicKey({
      key: Buffer.from(publicKey, "hex"),
      format: "der",
      type: "spki",
    });

    const isValid = verify(null, message, key, sig);
    if (!isValid) {
      return { valid: false, channel: "discord", reason: "invalid Ed25519 signature" };
    }
  } catch {
    // If Ed25519 verification fails due to key format or missing support,
    // we reject the request and log the error
    return { valid: false, channel: "discord", reason: "Ed25519 verification error" };
  }

  return { valid: true, channel: "discord" };
}

// ── Twilio ──────────────────────────────────────────────────────────────────

/**
 * Validate a Twilio webhook.
 * Twilio uses HMAC-SHA1 of the full URL + sorted POST params.
 */
export function validateTwilio(
  req: WebhookRequest,
  authToken: string,
  requestUrl: string,
): WebhookValidationResult {
  const signature = req.headers["x-twilio-signature"];

  if (!signature) {
    return { valid: false, channel: "twilio", reason: "missing signature" };
  }

  // Build the data string: URL + sorted params
  let dataString = requestUrl;
  try {
    const params = new URLSearchParams(req.body);
    const sorted = [...params.entries()].sort(([a], [b]) => a.localeCompare(b));
    for (const [key, value] of sorted) {
      dataString += key + value;
    }
  } catch {
    // If body isn't form-encoded, just use the URL
  }

  const expected = createHmac("sha1", authToken)
    .update(dataString)
    .digest("base64");

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);

  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    return { valid: false, channel: "twilio", reason: "invalid signature" };
  }

  return { valid: true, channel: "twilio" };
}

// ── WhatsApp ────────────────────────────────────────────────────────────────

/**
 * Validate a WhatsApp webhook (via Meta/Facebook).
 * Uses HMAC-SHA256 of the body with the app secret.
 */
export function validateWhatsApp(
  req: WebhookRequest,
  appSecret: string,
): WebhookValidationResult {
  const signature = req.headers["x-hub-signature-256"];

  if (!signature) {
    return { valid: false, channel: "whatsapp", reason: "missing signature" };
  }

  const expected = "sha256=" + createHmac("sha256", appSecret)
    .update(req.body)
    .digest("hex");

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);

  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    return { valid: false, channel: "whatsapp", reason: "invalid signature" };
  }

  return { valid: true, channel: "whatsapp" };
}

// ── Startup gate ────────────────────────────────────────────────────────────

export interface ChannelConfig {
  type: ChannelType;
  enabled: boolean;
  hasSecret: boolean;
}

/**
 * Validate that all enabled channels have their webhook secrets configured.
 * Returns list of channels missing secrets (empty = all good).
 */
export function validateStartupGate(channels: ChannelConfig[]): string[] {
  const missing: string[] = [];
  for (const ch of channels) {
    if (ch.enabled && !ch.hasSecret) {
      missing.push(ch.type);
    }
  }
  return missing;
}
