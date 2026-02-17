// ── Network Perimeter Security (L1) ─────────────────────────────────────────
// Generates nftables rules, validates port exposure, suppresses mDNS.

// ── Types ───────────────────────────────────────────────────────────────────

export interface NftablesConfig {
  /** SSH port (default 22). */
  sshPort?: number;
  /** WireGuard port (default 51820). */
  wireguardPort?: number;
  /** Extra allowed inbound TCP ports (e.g., Tailscale). */
  extraTcpPorts?: number[];
  /** Extra allowed inbound UDP ports. */
  extraUdpPorts?: number[];
  /** Gateway port that must always be blocked externally (default 18789). */
  gatewayPort?: number;
}

export interface PortExposure {
  port: number;
  protocol: "tcp" | "udp";
  bindAddress: string;
  source: string; // e.g., "docker", "gateway", "process"
}

export interface PerimeterValidation {
  valid: boolean;
  exposures: PortExposure[];
  errors: string[];
}

// ── nftables rule generation ────────────────────────────────────────────────

/** The OpenClaw gateway port that must never be exposed externally. */
export const GATEWAY_PORT = 18789;

/** mDNS port to block. */
export const MDNS_PORT = 5353;

/**
 * Generate nftables ruleset for lobsec perimeter security.
 * Default-deny on input, allow only SSH + WireGuard + loopback.
 */
export function generateNftablesRules(config: NftablesConfig = {}): string {
  const ssh = config.sshPort ?? 22;
  const wg = config.wireguardPort ?? 51820;
  const gw = config.gatewayPort ?? GATEWAY_PORT;
  const extraTcp = config.extraTcpPorts ?? [];
  const extraUdp = config.extraUdpPorts ?? [];

  const lines: string[] = [
    "#!/usr/sbin/nft -f",
    "",
    "# lobsec perimeter firewall — generated, do not edit manually",
    "# Policy: default-deny inbound, allow established, SSH, WireGuard, loopback",
    "",
    "flush ruleset",
    "",
    "table inet lobsec {",
    "  chain input {",
    "    type filter hook input priority 0; policy drop;",
    "",
    "    # Allow loopback",
    "    iif lo accept",
    "",
    "    # Allow established/related connections",
    "    ct state established,related accept",
    "",
    "    # Allow ICMP (ping)",
    "    ip protocol icmp accept",
    "    ip6 nexthdr icmpv6 accept",
    "",
    `    # Allow SSH (port ${ssh})`,
    `    tcp dport ${ssh} accept`,
    "",
    `    # Allow WireGuard (port ${wg})`,
    `    udp dport ${wg} accept`,
    "",
  ];

  // Extra allowed ports
  for (const port of extraTcp) {
    lines.push(`    # Extra allowed TCP port`);
    lines.push(`    tcp dport ${port} accept`);
    lines.push("");
  }

  for (const port of extraUdp) {
    lines.push(`    # Extra allowed UDP port`);
    lines.push(`    udp dport ${port} accept`);
    lines.push("");
  }

  lines.push(
    `    # Block gateway port explicitly (belt and suspenders)`,
    `    tcp dport ${gw} drop`,
    "",
    `    # Block mDNS`,
    `    udp dport ${MDNS_PORT} drop`,
    "",
    "    # Log and drop everything else",
    '    log prefix "lobsec-drop: " drop',
    "  }",
    "",
    "  chain forward {",
    "    type filter hook forward priority 0; policy drop;",
    "",
    "    # Allow established/related",
    "    ct state established,related accept",
    "",
    "    # Drop all other forwarded traffic",
    "    drop",
    "  }",
    "",
    "  chain output {",
    "    type filter hook output priority 0; policy accept;",
    "",
    `    # Block outbound mDNS`,
    `    udp dport ${MDNS_PORT} drop`,
    "  }",
    "}",
    "",
  );

  return lines.join("\n");
}

// ── mDNS suppression ────────────────────────────────────────────────────────

/**
 * Environment variables to set for mDNS suppression.
 * These should be injected into the OpenClaw process environment.
 */
export const MDNS_SUPPRESS_ENV: Record<string, string> = {
  OPENCLAW_DISABLE_BONJOUR: "1",
};

// ── Port exposure validation ────────────────────────────────────────────────

/**
 * Parse `docker ps --format` output to find published ports.
 * Input format: lines of "0.0.0.0:8080->8080/tcp" or ":::8080->8080/tcp".
 */
export function parseDockerPorts(dockerPsOutput: string): PortExposure[] {
  const exposures: PortExposure[] = [];
  const portRegex = /(\d+\.\d+\.\d+\.\d+|:::?):(\d+)->(\d+)\/(tcp|udp)/g;

  let match: RegExpExecArray | null;
  while ((match = portRegex.exec(dockerPsOutput)) !== null) {
    const bindAddress = match[1]!;
    const hostPort = parseInt(match[2]!, 10);
    const protocol = match[4] as "tcp" | "udp";

    exposures.push({
      port: hostPort,
      protocol,
      bindAddress,
      source: "docker",
    });
  }

  return exposures;
}

/**
 * Parse `ss -tlnp` output to find listening ports.
 * Returns ports bound to non-loopback addresses.
 */
export function parseListeningPorts(ssOutput: string): PortExposure[] {
  const exposures: PortExposure[] = [];
  const lines = ssOutput.split("\n");

  for (const line of lines) {
    // Match lines like: LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
    const match = line.match(/LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s+/);
    if (!match) continue;

    const bindAddress = match[1]!;
    const port = parseInt(match[2]!, 10);

    exposures.push({
      port,
      protocol: "tcp",
      bindAddress,
      source: "process",
    });
  }

  return exposures;
}

/**
 * Validate that no dangerous ports are exposed externally.
 * Returns a validation result with any exposures found.
 */
export function validatePerimeter(
  exposures: PortExposure[],
  allowedPorts: number[] = [],
  gatewayPort: number = GATEWAY_PORT,
): PerimeterValidation {
  const errors: string[] = [];
  const dangerous: PortExposure[] = [];

  for (const exp of exposures) {
    // Loopback is always OK
    if (exp.bindAddress === "127.0.0.1" || exp.bindAddress === "::1" || exp.bindAddress === "localhost") {
      continue;
    }

    // Gateway port must never be exposed externally
    if (exp.port === gatewayPort) {
      errors.push(
        `CRITICAL: Gateway port ${gatewayPort} exposed on ${exp.bindAddress} via ${exp.source}`,
      );
      dangerous.push(exp);
      continue;
    }

    // mDNS port must never be exposed
    if (exp.port === MDNS_PORT) {
      errors.push(
        `mDNS port ${MDNS_PORT} exposed on ${exp.bindAddress} via ${exp.source}`,
      );
      dangerous.push(exp);
      continue;
    }

    // Check if port is in allowed list
    if (!allowedPorts.includes(exp.port)) {
      errors.push(
        `Unexpected port ${exp.port}/${exp.protocol} exposed on ${exp.bindAddress} via ${exp.source}`,
      );
      dangerous.push(exp);
    }
  }

  return {
    valid: errors.length === 0,
    exposures: dangerous,
    errors,
  };
}
