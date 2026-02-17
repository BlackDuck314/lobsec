import { describe, it, expect } from "vitest";
import {
  generateCaddyfile,
  generateCaddyDockerArgs,
  SECURITY_HEADERS,
} from "./caddy-config.js";

// ── Unit: SECURITY_HEADERS ────────────────────────────────────────────────

describe("SECURITY_HEADERS", () => {
  it("contains all required headers", () => {
    expect(SECURITY_HEADERS["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(SECURITY_HEADERS["X-Frame-Options"]).toBe("DENY");
    expect(SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
    expect(SECURITY_HEADERS["Strict-Transport-Security"]).toContain("max-age=63072000");
    expect(SECURITY_HEADERS["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
  });

  it("CSP blocks scripts from external sources", () => {
    const csp = SECURITY_HEADERS["Content-Security-Policy"]!;
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("default-src 'self'");
  });
});

// ── Unit: generateCaddyfile ───────────────────────────────────────────────

describe("generateCaddyfile", () => {
  const defaultConfig = {
    domain: "lobsec.local",
    tls: "self-signed" as const,
  };

  it("generates valid Caddyfile structure", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("lobsec.local {");
    expect(cf).toContain("admin off");
    expect(cf).toContain("tls internal");
  });

  it("enforces TLS 1.3", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("protocols tls1.3");
  });

  it("includes all security headers", () => {
    const cf = generateCaddyfile(defaultConfig);
    for (const key of Object.keys(SECURITY_HEADERS)) {
      expect(cf).toContain(key);
    }
  });

  it("removes Server header", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("header -Server");
  });

  it("includes rate limiting", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("rate_limit");
    expect(cf).toContain("60r/m");
  });

  it("custom rate limit", () => {
    const cf = generateCaddyfile({ ...defaultConfig, rateLimitPerMinute: 30 });
    expect(cf).toContain("30r/m");
  });

  it("includes request body size limit", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("max_size 10MB");
  });

  it("custom body size", () => {
    const cf = generateCaddyfile({ ...defaultConfig, maxBodySize: "5MB" });
    expect(cf).toContain("max_size 5MB");
  });

  it("includes WebSocket origin validation", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("header Upgrade websocket");
    expect(cf).toContain("respond @invalid_ws 403");
  });

  it("custom allowed origins", () => {
    const cf = generateCaddyfile({
      ...defaultConfig,
      allowedOrigins: ["https://app.example.com", "https://admin.example.com"],
    });
    expect(cf).toContain("header Origin https://app.example.com");
    expect(cf).toContain("header Origin https://admin.example.com");
  });

  it("reverse proxy to upstream", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("reverse_proxy 127.0.0.1:18789");
  });

  it("custom upstream", () => {
    const cf = generateCaddyfile({ ...defaultConfig, upstream: "10.0.0.5:9000" });
    expect(cf).toContain("reverse_proxy 10.0.0.5:9000");
  });

  it("removes X-Powered-By from response", () => {
    const cf = generateCaddyfile(defaultConfig);
    expect(cf).toContain("header_down -X-Powered-By");
  });

  it("uses custom TLS cert paths", () => {
    const cf = generateCaddyfile({
      domain: "example.com",
      tls: "custom",
      certPath: "/certs/cert.pem",
      keyPath: "/certs/key.pem",
    });
    expect(cf).toContain("tls /certs/cert.pem /certs/key.pem");
  });

  it("uses ACME email", () => {
    const cf = generateCaddyfile({
      domain: "example.com",
      tls: "acme",
      acmeEmail: "admin@example.com",
    });
    expect(cf).toContain("tls admin@example.com");
  });
});

// ── Unit: generateCaddyDockerArgs ─────────────────────────────────────────

describe("generateCaddyDockerArgs", () => {
  const defaultDockerConfig = {
    caddyfilePath: "/etc/lobsec/config/Caddyfile",
  };

  it("generates valid docker run args", () => {
    const args = generateCaddyDockerArgs(defaultDockerConfig);
    expect(args).toContain("--read-only");
    expect(args).toContain("--name");
    expect(args).toContain("lobsec-caddy");
  });

  it("mounts Caddyfile as read-only", () => {
    const args = generateCaddyDockerArgs(defaultDockerConfig);
    const mountIdx = args.indexOf("-v");
    expect(args[mountIdx + 1]).toContain(":ro");
    expect(args[mountIdx + 1]).toContain("Caddyfile");
  });

  it("drops all capabilities", () => {
    const args = generateCaddyDockerArgs(defaultDockerConfig);
    const capDropIdx = args.indexOf("--cap-drop");
    expect(args[capDropIdx + 1]).toBe("ALL");
  });

  it("adds only NET_BIND_SERVICE", () => {
    const args = generateCaddyDockerArgs(defaultDockerConfig);
    const capAddIdx = args.indexOf("--cap-add");
    expect(args[capAddIdx + 1]).toBe("NET_BIND_SERVICE");
  });

  it("uses lobsec-internal network", () => {
    const args = generateCaddyDockerArgs(defaultDockerConfig);
    const netIdx = args.indexOf("--network");
    expect(args[netIdx + 1]).toBe("lobsec-internal");
  });

  it("enables no-new-privileges", () => {
    const args = generateCaddyDockerArgs(defaultDockerConfig);
    expect(args).toContain("no-new-privileges");
  });

  it("mounts certs when provided", () => {
    const args = generateCaddyDockerArgs({
      ...defaultDockerConfig,
      certsPath: "/etc/lobsec/certs",
    });
    const certMount = args.find((a) => a.includes("/etc/caddy/certs"));
    expect(certMount).toContain(":ro");
  });

  it("uses tmpfs for data and config", () => {
    const args = generateCaddyDockerArgs(defaultDockerConfig);
    const tmpfsMounts = args.filter((_, i) => args[i - 1] === "--tmpfs");
    expect(tmpfsMounts.some((t) => t.includes("/data"))).toBe(true);
    expect(tmpfsMounts.some((t) => t.includes("/config"))).toBe(true);
  });

  it("custom container name", () => {
    const args = generateCaddyDockerArgs({
      ...defaultDockerConfig,
      containerName: "my-caddy",
    });
    const nameIdx = args.indexOf("--name");
    expect(args[nameIdx + 1]).toBe("my-caddy");
  });
});
