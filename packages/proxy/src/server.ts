// ── lobsec Proxy Server ─────────────────────────────────────────────────────
// HTTP reverse proxy that sits between OpenClaw and LLM backends.
// Validates proxy token, detects provider, injects real API key, enforces
// egress rules, and forwards requests to the appropriate backend.
//
// Usage:
//   LOBSEC_PROXY_TOKEN=xxx LOBSEC_PROXY_PORT=18790 node server.js
//
// OpenClaw should be configured with baseUrl pointing to this proxy.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { CredentialStore } from "./credential-store.js";
import { routeRequest, type LlmRequest, type LlmAuditEntry } from "./llm-router.js";
import { checkEgress, DEFAULT_ALLOWLIST } from "./egress-firewall.js";

// ── Types ───────────────────────────────────────────────────────────────────

export interface ProxyServerConfig {
  /** Port to listen on. Default: 18790. */
  port: number;
  /** Bind address. Default: "127.0.0.1" (loopback only). */
  host: string;
  /** Proxy token for authenticating incoming requests from OpenClaw. */
  proxyToken: string;
  /** Credentials to inject into outgoing requests. */
  credentials: CredentialStore;
  /** Callback for audit log entries. */
  onAudit?: (entry: LlmAuditEntry) => void;
  /** Callback for errors. */
  onError?: (err: Error, context: string) => void;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const MAX_BODY = 10 * 1024 * 1024; // 10 MB

    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        req.destroy();
        reject(new Error("request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(json),
  });
  res.end(json);
}

function toLlmRequest(req: IncomingMessage, body: string): LlmRequest {
  const headers: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    headers[key] = Array.isArray(value) ? value.join(", ") : value;
  }
  return {
    method: req.method ?? "GET",
    path: req.url ?? "/",
    headers,
    body,
  };
}

// ── Server ──────────────────────────────────────────────────────────────────

export function createProxyServer(config: ProxyServerConfig): ReturnType<typeof createServer> {
  const { proxyToken, credentials, onAudit, onError } = config;

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // Health check endpoint
    if (req.url === "/__lobsec__/health") {
      sendJson(res, 200, { status: "ok", proxy: "lobsec", timestamp: new Date().toISOString() });
      return;
    }

    // Only accept POST for LLM API calls
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "method not allowed" });
      return;
    }

    const startTime = Date.now();
    let body: string;

    try {
      body = await readBody(req);
    } catch (err) {
      sendJson(res, 413, { error: "request body too large" });
      return;
    }

    const llmReq = toLlmRequest(req, body);

    // Route the request (validates proxy token, detects provider, injects API key)
    const route = routeRequest(llmReq, proxyToken, credentials);

    if (!route.allowed) {
      sendJson(res, 403, { error: route.reason ?? "request denied" });
      return;
    }

    // Egress check: verify target URL is not private/metadata IP
    try {
      const url = new URL(route.targetUrl!);
      const egressCheck = checkEgress(url.hostname, parseInt(url.port) || 443, undefined, DEFAULT_ALLOWLIST);
      if (!egressCheck.allowed) {
        sendJson(res, 403, { error: `egress blocked: ${egressCheck.reason}` });
        return;
      }
    } catch (err) {
      sendJson(res, 502, { error: "invalid target URL" });
      return;
    }

    // Forward request to the real backend
    try {
      const targetUrl = new URL(route.targetUrl!);

      // Build outgoing headers: copy safe headers, replace auth
      const outHeaders: Record<string, string> = {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(body)),
      };

      // Inject provider-specific auth
      if (route.provider === "anthropic") {
        outHeaders["x-api-key"] = route.targetAuth!;
        // Preserve anthropic-version header if present
        const version = llmReq.headers["anthropic-version"];
        if (version) outHeaders["anthropic-version"] = version;
      } else {
        // targetAuth already includes "Bearer " prefix for Bearer providers
        outHeaders["authorization"] = route.targetAuth!;
      }

      // Inject extra headers (e.g. CF-Access for Jetson)
      if (route.extraHeaders) {
        Object.assign(outHeaders, route.extraHeaders);
      }

      const fetchRes = await fetch(route.targetUrl!, {
        method: "POST",
        headers: outHeaders,
        body,
      });

      const latencyMs = Date.now() - startTime;

      // Audit log
      if (onAudit) {
        onAudit({
          provider: route.provider!,
          model: route.model ?? "unknown",
          estimatedTokens: route.estimatedTokens ?? 0,
          backend: "cloud",
          latencyMs,
          traceId: llmReq.headers["x-trace-id"] ?? crypto.randomUUID(),
          statusCode: fetchRes.status,
        });
      }

      // Stream response back to caller
      res.writeHead(fetchRes.status, {
        "Content-Type": fetchRes.headers.get("content-type") ?? "application/json",
      });

      if (fetchRes.body) {
        const reader = fetchRes.body.getReader();
        const pump = async (): Promise<void> => {
          const { done, value } = await reader.read();
          if (done) { res.end(); return; }
          res.write(value);
          return pump();
        };
        await pump();
      } else {
        const responseBody = await fetchRes.text();
        res.end(responseBody);
      }
    } catch (err) {
      const latencyMs = Date.now() - startTime;
      onError?.(err as Error, `forwarding to ${route.targetUrl}`);

      if (onAudit) {
        onAudit({
          provider: route.provider!,
          model: route.model ?? "unknown",
          estimatedTokens: route.estimatedTokens ?? 0,
          backend: "cloud",
          latencyMs,
          traceId: llmReq.headers["x-trace-id"] ?? crypto.randomUUID(),
          statusCode: 502,
        });
      }

      if (!res.headersSent) {
        sendJson(res, 502, { error: "backend unavailable" });
      }
    }
  });

  return server;
}

// ── CLI entry point ─────────────────────────────────────────────────────────

export function startProxyFromEnv(): void {
  const port = parseInt(process.env["LOBSEC_PROXY_PORT"] ?? "18790", 10);
  const host = process.env["LOBSEC_PROXY_HOST"] ?? "127.0.0.1";
  const proxyToken = process.env["LOBSEC_PROXY_TOKEN"]
    ?? process.env["OPENCLAW_GATEWAY_TOKEN"];

  if (!proxyToken) {
    console.error("ERROR: LOBSEC_PROXY_TOKEN or OPENCLAW_GATEWAY_TOKEN is required");
    process.exit(1);
  }

  // Load credentials from environment
  const creds = new CredentialStore();
  const envMappings: [string, string][] = [
    ["ANTHROPIC_API_KEY", "anthropic-api-key"],
    ["OPENAI_API_KEY", "openai-api-key"],
    ["OLLAMA_API_KEY", "ollama-api-key"],
  ];

  for (const [envVar, label] of envMappings) {
    creds.loadFromEnv(label, "llm-api-key", envVar);
  }

  const server = createProxyServer({
    port,
    host,
    proxyToken,
    credentials: creds,
    onAudit: (entry) => {
      const ts = new Date().toISOString();
      console.log(JSON.stringify({ ts, level: "INFO", event: "llm_request", ...entry }));
    },
    onError: (err, context) => {
      console.error(JSON.stringify({
        ts: new Date().toISOString(),
        level: "ERROR",
        event: "proxy_error",
        context,
        error: err.message,
      }));
    },
  });

  server.listen(port, host, () => {
    console.log(JSON.stringify({
      ts: new Date().toISOString(),
      level: "INFO",
      event: "proxy_start",
      host,
      port,
      backends: envMappings.filter(([env]) => process.env[env]).map(([, label]) => label),
    }));
  });
}
