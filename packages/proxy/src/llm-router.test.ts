import { describe, it, expect, beforeEach } from "vitest";
import {
  detectProvider,
  estimateTokens,
  extractModel,
  validateProxyToken,
  routeRequest,
} from "./llm-router.js";
import { CredentialStore } from "./credential-store.js";
import type { LlmRequest } from "./llm-router.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

const PROXY_TOKEN = "lobsec-proxy-test-token-abc123";

function makeReq(overrides: Partial<LlmRequest> = {}): LlmRequest {
  return {
    method: "POST",
    path: "/v1/chat/completions",
    headers: {
      authorization: `Bearer ${PROXY_TOKEN}`,
    },
    body: JSON.stringify({
      model: "gpt-4",
      messages: [{ role: "user", content: "Hello world" }],
    }),
    ...overrides,
  };
}

// ── Unit: detectProvider ──────────────────────────────────────────────────

describe("detectProvider", () => {
  it("detects OpenAI from /v1/chat/completions", () => {
    const provider = detectProvider(makeReq({ path: "/v1/chat/completions" }));
    expect(provider?.name).toBe("openai");
  });

  it("detects Anthropic from /v1/messages", () => {
    const provider = detectProvider(makeReq({ path: "/v1/messages" }));
    expect(provider?.name).toBe("anthropic");
  });

  it("detects from X-LLM-Provider header", () => {
    const provider = detectProvider(
      makeReq({ headers: { "x-llm-provider": "anthropic" } }),
    );
    expect(provider?.name).toBe("anthropic");
  });

  it("returns undefined for unknown path", () => {
    expect(detectProvider(makeReq({ path: "/unknown" }))).toBeUndefined();
  });

  it("routes /v1/embeddings to Ollama for memory search", () => {
    const provider = detectProvider(makeReq({ path: "/v1/embeddings" }));
    expect(provider?.name).toBe("ollama");
  });

  it("routes /v1/embeddings to specified provider via header override", () => {
    const provider = detectProvider(makeReq({
      path: "/v1/embeddings",
      headers: { "x-llm-provider": "openai" },
    }));
    expect(provider?.name).toBe("openai");
  });
});

// ── Unit: estimateTokens ──────────────────────────────────────────────────

describe("estimateTokens", () => {
  it("estimates from messages array", () => {
    const body = JSON.stringify({
      model: "gpt-4",
      messages: [
        { role: "user", content: "Hello world, this is a test message" },
      ],
    });
    const tokens = estimateTokens(body);
    expect(tokens).toBeGreaterThan(0);
    // "Hello world, this is a test message" = 35 chars ÷ 4 = ~9
    expect(tokens).toBeLessThan(20);
  });

  it("falls back to body length for non-JSON", () => {
    const tokens = estimateTokens("not json at all");
    expect(tokens).toBeGreaterThan(0);
  });

  it("handles empty messages", () => {
    const body = JSON.stringify({ model: "gpt-4", messages: [] });
    const tokens = estimateTokens(body);
    expect(tokens).toBe(0);
  });
});

// ── Unit: extractModel ────────────────────────────────────────────────────

describe("extractModel", () => {
  it("extracts model from request body", () => {
    const body = JSON.stringify({ model: "claude-3-opus-20240229" });
    expect(extractModel(body)).toBe("claude-3-opus-20240229");
  });

  it("returns undefined for missing model", () => {
    expect(extractModel(JSON.stringify({}))).toBeUndefined();
  });

  it("returns undefined for invalid JSON", () => {
    expect(extractModel("not json")).toBeUndefined();
  });
});

// ── Unit: validateProxyToken ──────────────────────────────────────────────

describe("validateProxyToken", () => {
  it("accepts valid token", () => {
    const req = makeReq();
    expect(validateProxyToken(req, PROXY_TOKEN)).toBe(true);
  });

  it("rejects wrong token", () => {
    const req = makeReq({
      headers: { authorization: "Bearer wrong-token" },
    });
    expect(validateProxyToken(req, PROXY_TOKEN)).toBe(false);
  });

  it("rejects missing authorization header", () => {
    const req = makeReq({ headers: {} });
    expect(validateProxyToken(req, PROXY_TOKEN)).toBe(false);
  });

  it("rejects non-Bearer auth", () => {
    const req = makeReq({
      headers: { authorization: `Basic ${PROXY_TOKEN}` },
    });
    expect(validateProxyToken(req, PROXY_TOKEN)).toBe(false);
  });
});

// ── Unit: routeRequest ────────────────────────────────────────────────────

describe("routeRequest", () => {
  let creds: CredentialStore;

  beforeEach(() => {
    creds = new CredentialStore();
    creds.load("openai-api-key", "llm-api-key", "sk-real-openai-key");
    creds.load("anthropic-api-key", "llm-api-key", "sk-ant-real-key");
  });

  it("routes OpenAI request successfully", () => {
    const req = makeReq();
    const result = routeRequest(req, PROXY_TOKEN, creds);

    expect(result.allowed).toBe(true);
    expect(result.provider).toBe("openai");
    expect(result.targetUrl).toBe("https://api.openai.com/v1/chat/completions");
    expect(result.targetAuth).toBe("Bearer sk-real-openai-key");
    expect(result.model).toBe("gpt-4");
    expect(result.estimatedTokens).toBeGreaterThan(0);
  });

  it("routes Anthropic request successfully", () => {
    const req = makeReq({
      path: "/v1/messages",
      body: JSON.stringify({
        model: "claude-3-opus-20240229",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });
    const result = routeRequest(req, PROXY_TOKEN, creds);

    expect(result.allowed).toBe(true);
    expect(result.provider).toBe("anthropic");
    expect(result.targetUrl).toBe("https://api.anthropic.com/v1/messages");
    expect(result.targetAuth).toBe("sk-ant-real-key");
  });

  it("rejects invalid proxy token", () => {
    const req = makeReq({
      headers: { authorization: "Bearer wrong" },
    });
    const result = routeRequest(req, PROXY_TOKEN, creds);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("proxy token");
  });

  it("rejects unknown provider", () => {
    const req = makeReq({ path: "/unknown/endpoint" });
    const result = routeRequest(req, PROXY_TOKEN, creds);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("provider");
  });

  it("rejects when API key not in credential store", () => {
    const emptyCreds = new CredentialStore();
    const req = makeReq();
    const result = routeRequest(req, PROXY_TOKEN, emptyCreds);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("API key not found");
  });

  it("never exposes proxy token in target auth", () => {
    const req = makeReq();
    const result = routeRequest(req, PROXY_TOKEN, creds);

    expect(result.targetAuth).not.toContain(PROXY_TOKEN);
  });

  it("never returns proxy token in any field", () => {
    const req = makeReq();
    const result = routeRequest(req, PROXY_TOKEN, creds);
    const json = JSON.stringify(result);
    expect(json).not.toContain(PROXY_TOKEN);
  });
});
