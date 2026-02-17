import { describe, it, expect } from "vitest";
import {
  generateNftablesRules,
  parseDockerPorts,
  parseListeningPorts,
  validatePerimeter,
  GATEWAY_PORT,
  MDNS_PORT,
  MDNS_SUPPRESS_ENV,
} from "./network-perimeter.js";

// ── Unit: generateNftablesRules ───────────────────────────────────────────

describe("generateNftablesRules", () => {
  it("generates valid nftables ruleset with defaults", () => {
    const rules = generateNftablesRules();

    expect(rules).toContain("flush ruleset");
    expect(rules).toContain("table inet lobsec");
    expect(rules).toContain("policy drop");
    expect(rules).toContain("iif lo accept");
    expect(rules).toContain("ct state established,related accept");
    expect(rules).toContain("tcp dport 22 accept");
    expect(rules).toContain("udp dport 51820 accept");
    expect(rules).toContain(`tcp dport ${GATEWAY_PORT} drop`);
    expect(rules).toContain(`udp dport ${MDNS_PORT} drop`);
  });

  it("allows custom SSH port", () => {
    const rules = generateNftablesRules({ sshPort: 2222 });
    expect(rules).toContain("tcp dport 2222 accept");
    expect(rules).not.toContain("tcp dport 22 accept");
  });

  it("allows custom WireGuard port", () => {
    const rules = generateNftablesRules({ wireguardPort: 12345 });
    expect(rules).toContain("udp dport 12345 accept");
  });

  it("includes extra TCP ports", () => {
    const rules = generateNftablesRules({ extraTcpPorts: [443, 8443] });
    expect(rules).toContain("tcp dport 443 accept");
    expect(rules).toContain("tcp dport 8443 accept");
  });

  it("includes extra UDP ports", () => {
    const rules = generateNftablesRules({ extraUdpPorts: [41641] });
    expect(rules).toContain("udp dport 41641 accept");
  });

  it("always blocks gateway port regardless of config", () => {
    const rules = generateNftablesRules({ extraTcpPorts: [GATEWAY_PORT] });
    // The gateway block rule should still be present
    expect(rules).toContain(`tcp dport ${GATEWAY_PORT} drop`);
  });

  it("blocks mDNS on output chain too", () => {
    const rules = generateNftablesRules();
    // Check output chain blocks mDNS
    const outputSection = rules.split("chain output")[1];
    expect(outputSection).toContain(`udp dport ${MDNS_PORT} drop`);
  });

  it("forward chain defaults to drop", () => {
    const rules = generateNftablesRules();
    const forwardSection = rules.split("chain forward")[1]!.split("chain output")[0]!;
    expect(forwardSection).toContain("policy drop");
  });
});

// ── Unit: parseDockerPorts ────────────────────────────────────────────────

describe("parseDockerPorts", () => {
  it("parses typical docker ps port output", () => {
    const output = "0.0.0.0:8080->8080/tcp, 0.0.0.0:8443->8443/tcp";
    const ports = parseDockerPorts(output);

    expect(ports).toHaveLength(2);
    expect(ports[0]).toEqual({
      port: 8080,
      protocol: "tcp",
      bindAddress: "0.0.0.0",
      source: "docker",
    });
    expect(ports[1]).toEqual({
      port: 8443,
      protocol: "tcp",
      bindAddress: "0.0.0.0",
      source: "docker",
    });
  });

  it("parses IPv6 bindings", () => {
    const output = ":::8080->8080/tcp";
    const ports = parseDockerPorts(output);
    expect(ports).toHaveLength(1);
    expect(ports[0]!.bindAddress).toBe("::");
  });

  it("parses loopback bindings", () => {
    const output = "127.0.0.1:8080->8080/tcp";
    const ports = parseDockerPorts(output);
    expect(ports).toHaveLength(1);
    expect(ports[0]!.bindAddress).toBe("127.0.0.1");
  });

  it("returns empty for no ports", () => {
    expect(parseDockerPorts("")).toEqual([]);
    expect(parseDockerPorts("no ports here")).toEqual([]);
  });

  it("parses mixed TCP/UDP", () => {
    const output = "0.0.0.0:53->53/udp, 0.0.0.0:80->80/tcp";
    const ports = parseDockerPorts(output);
    expect(ports).toHaveLength(2);
    expect(ports[0]!.protocol).toBe("udp");
    expect(ports[1]!.protocol).toBe("tcp");
  });
});

// ── Unit: parseListeningPorts ─────────────────────────────────────────────

describe("parseListeningPorts", () => {
  it("parses ss -tlnp output", () => {
    const output = `State  Recv-Q  Send-Q    Local Address:Port    Peer Address:Port  Process
LISTEN  0      128       0.0.0.0:22         0.0.0.0:*      users:(("sshd",pid=1234,fd=3))
LISTEN  0      128       127.0.0.1:18789    0.0.0.0:*      users:(("openclaw",pid=5678,fd=4))`;

    const ports = parseListeningPorts(output);
    expect(ports).toHaveLength(2);
    expect(ports[0]).toEqual({
      port: 22,
      protocol: "tcp",
      bindAddress: "0.0.0.0",
      source: "process",
    });
    expect(ports[1]).toEqual({
      port: 18789,
      protocol: "tcp",
      bindAddress: "127.0.0.1",
      source: "process",
    });
  });

  it("returns empty for no LISTEN lines", () => {
    expect(parseListeningPorts("State  Recv-Q  Send-Q")).toEqual([]);
  });
});

// ── Unit: validatePerimeter ───────────────────────────────────────────────

describe("validatePerimeter", () => {
  it("passes for loopback-only exposures", () => {
    const result = validatePerimeter([
      { port: GATEWAY_PORT, protocol: "tcp", bindAddress: "127.0.0.1", source: "gateway" },
      { port: 8080, protocol: "tcp", bindAddress: "::1", source: "docker" },
    ]);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("fails for gateway port on 0.0.0.0", () => {
    const result = validatePerimeter([
      { port: GATEWAY_PORT, protocol: "tcp", bindAddress: "0.0.0.0", source: "docker" },
    ]);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("CRITICAL");
    expect(result.errors[0]).toContain(String(GATEWAY_PORT));
  });

  it("fails for mDNS port exposed externally", () => {
    const result = validatePerimeter([
      { port: MDNS_PORT, protocol: "udp", bindAddress: "0.0.0.0", source: "process" },
    ]);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("mDNS");
  });

  it("allows explicitly permitted ports", () => {
    const result = validatePerimeter(
      [{ port: 22, protocol: "tcp", bindAddress: "0.0.0.0", source: "process" }],
      [22],
    );
    expect(result.valid).toBe(true);
  });

  it("flags unexpected ports", () => {
    const result = validatePerimeter(
      [{ port: 9999, protocol: "tcp", bindAddress: "0.0.0.0", source: "docker" }],
      [22],
    );
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("9999");
  });

  it("gateway port is never allowed even in allowed list", () => {
    const result = validatePerimeter(
      [{ port: GATEWAY_PORT, protocol: "tcp", bindAddress: "0.0.0.0", source: "docker" }],
      [GATEWAY_PORT],
    );
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("CRITICAL");
  });
});

// ── mDNS suppression ─────────────────────────────────────────────────────

describe("MDNS_SUPPRESS_ENV", () => {
  it("contains the disable bonjour flag", () => {
    expect(MDNS_SUPPRESS_ENV["OPENCLAW_DISABLE_BONJOUR"]).toBe("1");
  });
});
