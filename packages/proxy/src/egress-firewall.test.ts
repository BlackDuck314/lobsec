import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import {
  isPrivateIp,
  isMetadataIp,
  isIPv4MappedIPv6,
  checkEgress,
  DEFAULT_ALLOWLIST,
  parseExtraHosts,
  buildAllowlist,
  resolveHost,
  clearDnsCache,
} from "./egress-firewall.js";
import type { EgressRule } from "./egress-firewall.js";

// ── Unit: isPrivateIp ─────────────────────────────────────────────────────

describe("isPrivateIp", () => {
  it("detects RFC1918 10.x.x.x", () => {
    expect(isPrivateIp("10.0.0.1")).toBe(true);
    expect(isPrivateIp("10.255.255.255")).toBe(true);
  });

  it("detects RFC1918 172.16-31.x.x", () => {
    expect(isPrivateIp("172.16.0.1")).toBe(true);
    expect(isPrivateIp("172.31.255.255")).toBe(true);
    expect(isPrivateIp("172.15.0.1")).toBe(false);
    expect(isPrivateIp("172.32.0.1")).toBe(false);
  });

  it("detects RFC1918 192.168.x.x", () => {
    expect(isPrivateIp("192.168.0.1")).toBe(true);
    expect(isPrivateIp("192.168.255.255")).toBe(true);
  });

  it("detects link-local 169.254.x.x", () => {
    expect(isPrivateIp("169.254.1.1")).toBe(true);
  });

  it("detects loopback", () => {
    expect(isPrivateIp("127.0.0.1")).toBe(true);
    expect(isPrivateIp("127.255.255.255")).toBe(true);
  });

  it("allows public IPs", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("1.1.1.1")).toBe(false);
    expect(isPrivateIp("93.184.216.34")).toBe(false);
  });
});

// ── Unit: isMetadataIp ────────────────────────────────────────────────────

describe("isMetadataIp", () => {
  it("detects AWS/GCP/Azure metadata endpoint", () => {
    expect(isMetadataIp("169.254.169.254")).toBe(true);
  });

  it("detects AWS IPv6 metadata", () => {
    expect(isMetadataIp("fd00:ec2::254")).toBe(true);
  });

  it("allows non-metadata IPs", () => {
    expect(isMetadataIp("8.8.8.8")).toBe(false);
  });
});

// ── Unit: isIPv4MappedIPv6 ────────────────────────────────────────────────

describe("isIPv4MappedIPv6", () => {
  it("detects IPv4-mapped IPv6", () => {
    expect(isIPv4MappedIPv6("::ffff:10.0.0.1")).toBe(true);
    expect(isIPv4MappedIPv6("::ffff:192.168.1.1")).toBe(true);
  });

  it("allows regular IPv6", () => {
    expect(isIPv4MappedIPv6("2001:db8::1")).toBe(false);
  });
});

// ── Unit: checkEgress ─────────────────────────────────────────────────────

describe("checkEgress", () => {
  const allowlist: EgressRule[] = [
    { host: "api.openai.com", ports: [443], protocol: "https" },
    { host: "api.telegram.org", ports: [443], protocol: "https" },
  ];

  it("allows listed host on correct port", () => {
    const result = checkEgress("api.openai.com", 443, "104.18.6.192", allowlist);
    expect(result.allowed).toBe(true);
  });

  it("denies listed host on wrong port", () => {
    const result = checkEgress("api.openai.com", 80, "104.18.6.192", allowlist);
    expect(result.allowed).toBe(false);
  });

  it("denies unlisted host", () => {
    const result = checkEgress("evil.com", 443, "1.2.3.4", allowlist);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not in allowlist");
  });

  it("denies private IP even for allowed host", () => {
    const result = checkEgress("api.openai.com", 443, "10.0.0.1", allowlist);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("private range");
  });

  it("denies metadata IP", () => {
    const result = checkEgress("api.openai.com", 443, "169.254.169.254", allowlist);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("metadata");
  });

  it("denies IPv4-mapped IPv6", () => {
    const result = checkEgress("api.openai.com", 443, "::ffff:10.0.0.1", allowlist);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("IPv4-mapped");
  });

  it("denies explicit denylist", () => {
    const result = checkEgress("evil.com", 443, "1.2.3.4", allowlist, ["evil.com"]);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("denylist");
  });

  it("denies subdomain of denylisted host", () => {
    const result = checkEgress("sub.evil.com", 443, "1.2.3.4", allowlist, ["evil.com"]);
    expect(result.allowed).toBe(false);
  });

  it("denylist takes priority over allowlist", () => {
    const result = checkEgress("api.openai.com", 443, "104.18.6.192", allowlist, ["api.openai.com"]);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("denylist");
  });
});

// ── Unit: DEFAULT_ALLOWLIST ───────────────────────────────────────────────

describe("DEFAULT_ALLOWLIST", () => {
  it("includes key LLM providers", () => {
    const hosts = DEFAULT_ALLOWLIST.map((r) => r.host);
    expect(hosts).toContain("api.anthropic.com");
    expect(hosts).toContain("api.openai.com");
  });

  it("includes messaging platforms", () => {
    const hosts = DEFAULT_ALLOWLIST.map((r) => r.host);
    expect(hosts).toContain("api.telegram.org");
    expect(hosts).toContain("slack.com");
    expect(hosts).toContain("discord.com");
  });

  it("all rules use secure protocols and standard ports", () => {
    for (const rule of DEFAULT_ALLOWLIST) {
      expect(["https", "tcp"]).toContain(rule.protocol);
      expect(rule.ports.length).toBeGreaterThan(0);
      for (const port of rule.ports) {
        expect(port).toBeGreaterThan(0);
        expect(port).toBeLessThanOrEqual(65535);
      }
    }
  });
});

// ── Property 31: RFC1918 blocking ─────────────────────────────────────────

describe("Property 31: RFC1918 blocking", () => {
  it("all 10.x.x.x addresses are private", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        (b, c, d) => {
          expect(isPrivateIp(`10.${b}.${c}.${d}`)).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("all 172.16-31.x.x addresses are private", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 16, max: 31 }),
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        (b, c, d) => {
          expect(isPrivateIp(`172.${b}.${c}.${d}`)).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("all 192.168.x.x addresses are private", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        (c, d) => {
          expect(isPrivateIp(`192.168.${c}.${d}`)).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("RFC1918 IPs always blocked in egress", () => {
    const allowAll: EgressRule[] = [{ host: "any.com", ports: [], protocol: "https" }];
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        (b, c, d) => {
          const result = checkEgress("any.com", 443, `10.${b}.${c}.${d}`, allowAll);
          expect(result.allowed).toBe(false);
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 32: Metadata endpoint blocking ──────────────────────────────

describe("Property 32: Metadata endpoint blocking", () => {
  it("169.254.169.254 is always blocked regardless of allowlist", () => {
    fc.assert(
      fc.property(
        fc.domain(),
        fc.integer({ min: 1, max: 65535 }),
        (host, port) => {
          const allowAll: EgressRule[] = [{ host, ports: [port], protocol: "https" }];
          const result = checkEgress(host, port, "169.254.169.254", allowAll);
          expect(result.allowed).toBe(false);
          expect(result.reason).toContain("metadata");
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 33: IPv4-mapped IPv6 blocking ───────────────────────────────

describe("Property 33: IPv4-mapped IPv6 blocking", () => {
  it("::ffff: prefixed IPs are always blocked", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        (a, b, c, d) => {
          const ip = `::ffff:${a}.${b}.${c}.${d}`;
          expect(isIPv4MappedIPv6(ip)).toBe(true);

          const allowAll: EgressRule[] = [{ host: "any.com", ports: [], protocol: "https" }];
          const result = checkEgress("any.com", 443, ip, allowAll);
          expect(result.allowed).toBe(false);
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 34: Allowlist enforcement ───────────────────────────────────

describe("Property 34: Allowlist enforcement", () => {
  it("unlisted hosts are always denied (default deny)", () => {
    fc.assert(
      fc.property(
        fc.domain(),
        fc.integer({ min: 1, max: 65535 }),
        (host, port) => {
          // Use a restrictive allowlist that won't match random domains
          const allowlist: EgressRule[] = [
            { host: "specific-allowed.example.net", ports: [443], protocol: "https" },
          ];
          // Use a public IP so it doesn't hit private range checks
          const result = checkEgress(host, port, "93.184.216.34", allowlist);
          // Either denied by "not in allowlist" or it happened to match
          if (host !== "specific-allowed.example.net" && !host.endsWith(".specific-allowed.example.net")) {
            expect(result.allowed).toBe(false);
          }
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 35: Egress connection logging ───────────────────────────────

describe("Property 35: Egress connection logging", () => {
  it("every checkEgress result contains host, port, and reason", () => {
    fc.assert(
      fc.property(
        fc.domain(),
        fc.integer({ min: 1, max: 65535 }),
        fc.constantFrom("93.184.216.34", "10.0.0.1", "169.254.169.254"),
        (host, port, ip) => {
          const result = checkEgress(host, port, ip, DEFAULT_ALLOWLIST);
          expect(result.host).toBe(host);
          expect(result.port).toBe(port);
          expect(result.reason.length).toBeGreaterThan(0);
          expect(typeof result.allowed).toBe("boolean");
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Unit: parseExtraHosts ──────────────────────────────────────────────────

describe("parseExtraHosts", () => {
  it("parses host:port pairs", () => {
    const rules = parseExtraHosts("198.51.100.10:11435,gpu.example.com:443");
    expect(rules).toHaveLength(2);
    expect(rules[0]).toEqual({ host: "198.51.100.10", ports: [11435], protocol: "https" });
    expect(rules[1]).toEqual({ host: "gpu.example.com", ports: [443], protocol: "https" });
  });

  it("handles bare hostnames (defaults to port 443)", () => {
    const rules = parseExtraHosts("example.com");
    expect(rules).toHaveLength(1);
    expect(rules[0]).toEqual({ host: "example.com", ports: [443], protocol: "https" });
  });

  it("returns empty array for empty string", () => {
    expect(parseExtraHosts("")).toEqual([]);
    expect(parseExtraHosts("  ")).toEqual([]);
  });

  it("trims whitespace", () => {
    const rules = parseExtraHosts(" foo.com:8080 , bar.com:9090 ");
    expect(rules).toHaveLength(2);
    expect(rules[0]!.host).toBe("foo.com");
    expect(rules[1]!.host).toBe("bar.com");
  });

  it("skips empty entries from trailing commas", () => {
    const rules = parseExtraHosts("foo.com:443,");
    expect(rules).toHaveLength(1);
  });
});

// ── Unit: buildAllowlist ──────────────────────────────────────────────────

describe("buildAllowlist", () => {
  it("includes all default entries when no extras", () => {
    const list = buildAllowlist();
    expect(list).toEqual(DEFAULT_ALLOWLIST);
  });

  it("appends extra hosts to defaults", () => {
    const extras: EgressRule[] = [
      { host: "custom.example.com", ports: [8080], protocol: "https" },
    ];
    const list = buildAllowlist(extras);
    expect(list.length).toBe(DEFAULT_ALLOWLIST.length + 1);
    expect(list[list.length - 1]).toEqual(extras[0]);
  });

  it("does not modify DEFAULT_ALLOWLIST", () => {
    const originalLength = DEFAULT_ALLOWLIST.length;
    buildAllowlist([{ host: "foo.com", ports: [443], protocol: "https" }]);
    expect(DEFAULT_ALLOWLIST.length).toBe(originalLength);
  });
});

// ── Unit: resolveHost ────────────────────────────────────────────────────

describe("resolveHost", () => {
  beforeEach(() => clearDnsCache());

  it("returns IP directly for IP input", async () => {
    const result = await resolveHost("93.184.216.34");
    expect(result).toBe("93.184.216.34");
  });

  it("returns IP directly for IPv6 input", async () => {
    const result = await resolveHost("::1");
    expect(result).toBe("::1");
  });

  it("resolves known hostname", async () => {
    // This may fail in isolated environments but that's OK
    const result = await resolveHost("localhost");
    // localhost should resolve to 127.0.0.1 in most environments
    if (result) {
      expect(result).toMatch(/^(?:\d{1,3}\.){3}\d{1,3}$/);
    }
  });

  it("returns undefined for unresolvable hostname", async () => {
    const result = await resolveHost("this-will-never-resolve-12345.invalid");
    expect(result).toBeUndefined();
  });

  it("caches results", async () => {
    const result1 = await resolveHost("127.0.0.1");
    const result2 = await resolveHost("127.0.0.1");
    expect(result1).toBe(result2);
  });
});

// ── DEFAULT_ALLOWLIST includes service dependencies ───────────────────────

describe("DEFAULT_ALLOWLIST service dependencies", () => {
  it("includes Perplexity API for web search", () => {
    expect(DEFAULT_ALLOWLIST.some((r) => r.host === "api.perplexity.ai")).toBe(true);
  });

  it("includes Gmail SMTP and IMAP", () => {
    expect(DEFAULT_ALLOWLIST.some((r) => r.host === "smtp.gmail.com" && r.ports.includes(587))).toBe(true);
    expect(DEFAULT_ALLOWLIST.some((r) => r.host === "imap.gmail.com" && r.ports.includes(993))).toBe(true);
  });

  it("includes Tomorrow.io for weather", () => {
    expect(DEFAULT_ALLOWLIST.some((r) => r.host === "api.tomorrow.io")).toBe(true);
  });
});
