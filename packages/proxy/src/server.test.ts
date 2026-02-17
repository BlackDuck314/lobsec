import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createProxyServer, type ProxyServerConfig } from "./server.js";
import { CredentialStore } from "./credential-store.js";
import type { LlmAuditEntry } from "./llm-router.js";
import type { Server } from "node:http";

// ── Helpers ─────────────────────────────────────────────────────────────────

const TEST_PORT = 18799;
const TEST_TOKEN = "test-proxy-token-abc123";
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

function makeCredentials(): CredentialStore {
  const store = new CredentialStore();
  store.load("anthropic-api-key", "llm-api-key", "sk-ant-test-key");
  store.load("openai-api-key", "llm-api-key", "sk-test-openai-key");
  return store;
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("Proxy server", () => {
  let server: Server;
  const auditLog: LlmAuditEntry[] = [];

  beforeAll(() => {
    const config: ProxyServerConfig = {
      port: TEST_PORT,
      host: "127.0.0.1",
      proxyToken: TEST_TOKEN,
      credentials: makeCredentials(),
      onAudit: (entry) => auditLog.push(entry),
    };
    server = createProxyServer(config);
    return new Promise<void>((resolve) => {
      server.listen(TEST_PORT, "127.0.0.1", resolve);
    });
  });

  afterAll(() => {
    return new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it("returns health check", async () => {
    const res = await fetch(`${BASE_URL}/__lobsec__/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, string>;
    expect(body["status"]).toBe("ok");
    expect(body["proxy"]).toBe("lobsec");
  });

  it("rejects non-POST methods", async () => {
    const res = await fetch(`${BASE_URL}/v1/messages`, { method: "GET" });
    expect(res.status).toBe(405);
  });

  it("rejects missing proxy token", async () => {
    const res = await fetch(`${BASE_URL}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: "claude-3-haiku", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, string>;
    expect(body["error"]).toContain("invalid or missing proxy token");
  });

  it("rejects wrong proxy token", async () => {
    const res = await fetch(`${BASE_URL}/v1/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer wrong-token",
      },
      body: JSON.stringify({ model: "claude-3-haiku", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(403);
  });

  it("rejects unknown provider path", async () => {
    const res = await fetch(`${BASE_URL}/v2/unknown-endpoint`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${TEST_TOKEN}`,
      },
      body: JSON.stringify({ model: "test" }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, string>;
    expect(body["error"]).toContain("unable to detect LLM provider");
  });

  // Note: we can't test actual forwarding without a real backend,
  // but the routing + auth + egress logic is validated above.
  // The forwarding to cloud providers is an integration test.
});
