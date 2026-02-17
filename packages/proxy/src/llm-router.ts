// ── LLM Routing Proxy (L8) ──────────────────────────────────────────────────
// Receives LLM API requests from OpenClaw, validates proxy token,
// injects real API key, forwards to cloud provider.

import { timingSafeEqual } from "node:crypto";
import type { CredentialStore } from "./credential-store.js";

// ── Types ───────────────────────────────────────────────────────────────────

export interface LlmRequest {
  /** HTTP method. */
  method: string;
  /** Request path (e.g., /v1/chat/completions). */
  path: string;
  /** Request headers. */
  headers: Record<string, string | undefined>;
  /** Request body (JSON string). */
  body: string;
}

export interface LlmRouteResult {
  /** Whether the request is authorized and routable. */
  allowed: boolean;
  /** Reason for denial (if not allowed). */
  reason?: string;
  /** Target backend URL. */
  targetUrl?: string;
  /** Authorization header value for the target. */
  targetAuth?: string;
  /** Provider name for audit logging. */
  provider?: string;
  /** Model name extracted from the request. */
  model?: string;
  /** Estimated token count (from request body). */
  estimatedTokens?: number;
}

export interface LlmAuditEntry {
  provider: string;
  model: string;
  estimatedTokens: number;
  backend: "cloud" | "sovereign";
  latencyMs?: number;
  traceId: string;
  statusCode?: number;
}

// ── Provider detection ──────────────────────────────────────────────────────

interface ProviderConfig {
  name: string;
  credentialLabel: string;
  baseUrl: string;
  authPrefix: string;
}

const PROVIDERS: ProviderConfig[] = [
  {
    name: "anthropic",
    credentialLabel: "anthropic-api-key",
    baseUrl: "https://api.anthropic.com",
    authPrefix: "x-api-key",
  },
  {
    name: "openai",
    credentialLabel: "openai-api-key",
    baseUrl: "https://api.openai.com",
    authPrefix: "Bearer",
  },
];

/** Detect provider from the request path or a hint header. */
export function detectProvider(req: LlmRequest): ProviderConfig | undefined {
  // Check X-LLM-Provider header first
  const hint = req.headers["x-llm-provider"]?.toLowerCase();
  if (hint) {
    return PROVIDERS.find((p) => p.name === hint);
  }

  // Detect from path patterns
  if (req.path.includes("/v1/messages")) return PROVIDERS.find((p) => p.name === "anthropic");
  if (req.path.includes("/v1/chat/completions")) return PROVIDERS.find((p) => p.name === "openai");
  if (req.path.includes("/v1/completions")) return PROVIDERS.find((p) => p.name === "openai");
  if (req.path.includes("/v1/embeddings")) return PROVIDERS.find((p) => p.name === "openai");

  return undefined;
}

// ── Token estimation ────────────────────────────────────────────────────────

/** Rough token estimate from a JSON body (4 chars per token). */
export function estimateTokens(body: string): number {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    // Look for messages array (chat completions)
    const messages = parsed["messages"];
    if (Array.isArray(messages)) {
      let charCount = 0;
      for (const msg of messages) {
        if (typeof msg === "object" && msg !== null) {
          const content = (msg as Record<string, unknown>)["content"];
          if (typeof content === "string") charCount += content.length;
        }
      }
      return Math.ceil(charCount / 4);
    }
    // Fallback: estimate from full body
    return Math.ceil(body.length / 4);
  } catch {
    return Math.ceil(body.length / 4);
  }
}

// ── Model extraction ────────────────────────────────────────────────────────

/** Extract model name from request body. */
export function extractModel(body: string): string | undefined {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    const model = parsed["model"];
    return typeof model === "string" ? model : undefined;
  } catch {
    return undefined;
  }
}

// ── Proxy token validation ──────────────────────────────────────────────────

/**
 * Validate the LOBSEC_PROXY_TOKEN from the incoming request.
 * Uses timing-safe comparison.
 */
export function validateProxyToken(
  req: LlmRequest,
  expectedToken: string,
): boolean {
  // Try Authorization: Bearer <token> first (OpenAI-style)
  let token: string | undefined;
  const auth = req.headers["authorization"];
  if (auth) {
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (match) token = match[1]!;
  }
  // Fall back to x-api-key header (Anthropic-style)
  if (!token) {
    token = req.headers["x-api-key"];
  }
  if (!token) return false;

  const tokenBuf = Buffer.from(token);
  const expectedBuf = Buffer.from(expectedToken);

  if (tokenBuf.length !== expectedBuf.length) return false;
  return timingSafeEqual(tokenBuf, expectedBuf);
}

// ── Route request ───────────────────────────────────────────────────────────

/**
 * Route an LLM request: validate proxy token, detect provider,
 * inject real API key, return target URL.
 */
export function routeRequest(
  req: LlmRequest,
  proxyToken: string,
  credentials: CredentialStore,
): LlmRouteResult {
  // 1. Validate proxy token
  if (!validateProxyToken(req, proxyToken)) {
    return { allowed: false, reason: "invalid or missing proxy token" };
  }

  // 2. Detect provider
  const provider = detectProvider(req);
  if (!provider) {
    return { allowed: false, reason: "unable to detect LLM provider" };
  }

  // 3. Get real API key from credential store
  const apiKey = credentials.get(provider.credentialLabel);
  if (!apiKey) {
    return { allowed: false, reason: `API key not found for provider ${provider.name}` };
  }

  // 4. Build target URL and auth
  const targetUrl = provider.baseUrl + req.path;
  const targetAuth =
    provider.authPrefix === "Bearer"
      ? `Bearer ${apiKey}`
      : apiKey; // For Anthropic, it's just the key value in x-api-key

  // 5. Extract metadata for audit
  const model = extractModel(req.body);
  const estimatedTokens = estimateTokens(req.body);

  return {
    allowed: true,
    targetUrl,
    targetAuth,
    provider: provider.name,
    model,
    estimatedTokens,
  };
}
