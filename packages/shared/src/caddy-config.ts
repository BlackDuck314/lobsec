// ── Caddy Reverse Proxy Configuration (L2) ─────────────────────────────────
// Generates Caddyfile and Docker configuration for the TLS-terminating proxy.

// ── Types ───────────────────────────────────────────────────────────────────

export interface CaddyConfig {
  /** Domain name or localhost. */
  domain: string;
  /** TLS mode. */
  tls: "self-signed" | "acme" | "custom";
  /** Path to custom TLS cert (when tls=custom). */
  certPath?: string;
  /** Path to custom TLS key (when tls=custom). */
  keyPath?: string;
  /** ACME email (when tls=acme). */
  acmeEmail?: string;
  /** Upstream address (where OpenClaw gateway listens). */
  upstream?: string;
  /** Allowed WebSocket origins. */
  allowedOrigins?: string[];
  /** Rate limit requests per minute per IP. */
  rateLimitPerMinute?: number;
  /** Max request body size. */
  maxBodySize?: string;
}

// ── Security headers ────────────────────────────────────────────────────────

export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

// ── Caddyfile generation ────────────────────────────────────────────────────

/**
 * Generate a Caddyfile for lobsec's Caddy reverse proxy.
 * - TLS 1.3 only
 * - Security headers
 * - WebSocket origin validation
 * - Rate limiting
 * - Request size limit
 */
export function generateCaddyfile(config: CaddyConfig): string {
  const upstream = config.upstream ?? "127.0.0.1:18789";
  const rateLimit = config.rateLimitPerMinute ?? 60;
  const maxBody = config.maxBodySize ?? "10MB";
  const origins = config.allowedOrigins ?? [`https://${config.domain}`];

  const lines: string[] = [];

  // Global options
  lines.push("{");
  lines.push("  # lobsec Caddy configuration — generated, do not edit manually");
  lines.push("  admin off");
  lines.push("  servers {");
  lines.push("    protocols h1 h2");
  lines.push("  }");
  lines.push("}");
  lines.push("");

  // Site block
  lines.push(`${config.domain} {`);

  // TLS configuration
  switch (config.tls) {
    case "self-signed":
      lines.push("  tls internal");
      break;
    case "custom":
      lines.push(`  tls ${config.certPath ?? "/etc/caddy/certs/cert.pem"} ${config.keyPath ?? "/etc/caddy/certs/key.pem"}`);
      break;
    case "acme":
      if (config.acmeEmail) {
        lines.push(`  tls ${config.acmeEmail}`);
      }
      break;
  }

  lines.push("");

  // TLS protocol version
  lines.push("  # Enforce TLS 1.3 minimum");
  lines.push("  tls {");
  lines.push("    protocols tls1.3");
  lines.push("  }");
  lines.push("");

  // Remove server header
  lines.push("  header -Server");
  lines.push("");

  // Security headers
  lines.push("  # Security headers");
  lines.push("  header {");
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    lines.push(`    ${key} "${value}"`);
  }
  lines.push("  }");
  lines.push("");

  // Rate limiting
  lines.push("  # Rate limiting");
  lines.push(`  rate_limit {remote_host} ${rateLimit}r/m`);
  lines.push("");

  // Request body size limit
  lines.push("  # Max request body size");
  lines.push(`  request_body {`);
  lines.push(`    max_size ${maxBody}`);
  lines.push(`  }`);
  lines.push("");

  // WebSocket origin validation
  lines.push("  # WebSocket origin validation");
  lines.push("  @websocket {");
  lines.push("    header Connection *Upgrade*");
  lines.push("    header Upgrade websocket");
  lines.push("  }");
  lines.push("");

  // Origin check for WebSocket
  const originMatcher = origins.map((o) => `header Origin ${o}`).join("\n    ");
  lines.push("  @valid_ws_origin {");
  lines.push(`    ${originMatcher}`);
  lines.push("  }");
  lines.push("");

  lines.push("  # Block WebSocket with invalid origin");
  lines.push("  @invalid_ws {");
  lines.push("    header Connection *Upgrade*");
  lines.push("    header Upgrade websocket");
  lines.push("    not {");
  lines.push(`      ${originMatcher}`);
  lines.push("    }");
  lines.push("  }");
  lines.push("  respond @invalid_ws 403");
  lines.push("");

  // Reverse proxy
  lines.push(`  reverse_proxy ${upstream} {`);
  lines.push("    header_up X-Forwarded-Proto {scheme}");
  lines.push("    header_up X-Real-IP {remote_host}");
  lines.push("    header_down -X-Powered-By");
  lines.push("  }");

  lines.push("}");
  lines.push("");

  return lines.join("\n");
}

// ── Docker configuration ────────────────────────────────────────────────────

export interface CaddyDockerConfig {
  /** Container name. */
  containerName?: string;
  /** Caddy image tag. */
  imageTag?: string;
  /** Path to Caddyfile on host. */
  caddyfilePath: string;
  /** Path to TLS certs directory on host. */
  certsPath?: string;
  /** Network name. */
  networkName?: string;
}

/**
 * Generate Docker run arguments for the Caddy container.
 * Returns an array of strings suitable for `docker run`.
 */
export function generateCaddyDockerArgs(config: CaddyDockerConfig): string[] {
  const containerName = config.containerName ?? "lobsec-caddy";
  const imageTag = config.imageTag ?? "caddy:2-alpine";
  const networkName = config.networkName ?? "lobsec-internal";

  const args: string[] = [
    "--name", containerName,
    "--network", networkName,
    "--restart", "unless-stopped",
    "--read-only",
    "--cap-drop", "ALL",
    "--cap-add", "NET_BIND_SERVICE",
    "--security-opt", "no-new-privileges",
    "-v", `${config.caddyfilePath}:/etc/caddy/Caddyfile:ro`,
    "-p", "443:443",
    "-p", "80:80",
  ];

  if (config.certsPath) {
    args.push("-v", `${config.certsPath}:/etc/caddy/certs:ro`);
  }

  // Tmpfs for Caddy data/config (since read-only root)
  args.push("--tmpfs", "/data:size=50m");
  args.push("--tmpfs", "/config:size=10m");

  args.push(imageTag);

  return args;
}
