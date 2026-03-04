// ── Egress Firewall (L5) ────────────────────────────────────────────────────
// Allowlist/denylist enforcement for outbound connections.
// Denylist is checked AFTER DNS resolution to prevent DNS rebinding.

// ── Types ───────────────────────────────────────────────────────────────────

export interface EgressRule {
  host: string;
  ports: number[];
  protocol: "http" | "https" | "tcp";
}

export interface EgressCheckResult {
  allowed: boolean;
  reason: string;
  host: string;
  port: number;
  resolvedIp?: string;
}

// ── CIDR / IP matching ──────────────────────────────────────────────────────

interface CidrRange {
  network: number[];
  prefixLen: number;
  ipv6: boolean;
}

/** Parse an IPv4 address to 4-element array. */
function parseIPv4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => parseInt(p, 10));
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
  return nums;
}

/** Parse an IPv6 address to 16-element byte array. */
function parseIPv6(ip: string): number[] | null {
  // Handle IPv4-mapped IPv6
  if (ip.startsWith("::ffff:")) {
    const v4 = parseIPv4(ip.slice(7));
    if (v4) return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...v4];
  }

  // Expand :: notation
  let expanded = ip;
  if (expanded.includes("::")) {
    const parts = expanded.split("::");
    const left = parts[0] ? parts[0]!.split(":") : [];
    const right = parts[1] ? parts[1]!.split(":") : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill("0");
    expanded = [...left, ...middle, ...right].join(":");
  }

  const groups = expanded.split(":");
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const g of groups) {
    const val = parseInt(g, 16);
    if (isNaN(val) || val < 0 || val > 0xffff) return null;
    bytes.push((val >> 8) & 0xff, val & 0xff);
  }
  return bytes;
}

/** Parse a CIDR notation string. */
function parseCidr(cidr: string): CidrRange | null {
  const [addr, prefix] = cidr.split("/");
  if (!addr || !prefix) return null;
  const prefixLen = parseInt(prefix, 10);

  // Try IPv4
  const v4 = parseIPv4(addr);
  if (v4 && prefixLen >= 0 && prefixLen <= 32) {
    return { network: v4, prefixLen, ipv6: false };
  }

  // Try IPv6
  const v6 = parseIPv6(addr);
  if (v6 && prefixLen >= 0 && prefixLen <= 128) {
    return { network: v6, prefixLen, ipv6: true };
  }

  return null;
}

/** Check if an IP (as byte array) falls within a CIDR range. */
function ipInCidr(ip: number[], cidr: CidrRange): boolean {
  if (ip.length !== cidr.network.length) return false;

  const bitsPerByte = 8;
  const fullBytes = Math.floor(cidr.prefixLen / bitsPerByte);
  const remainBits = cidr.prefixLen % bitsPerByte;

  for (let i = 0; i < fullBytes; i++) {
    if (ip[i] !== cidr.network[i]) return false;
  }

  if (remainBits > 0 && fullBytes < ip.length) {
    const mask = (0xff << (bitsPerByte - remainBits)) & 0xff;
    if ((ip[fullBytes]! & mask) !== (cidr.network[fullBytes]! & mask)) return false;
  }

  return true;
}

// ── Default deny list (checked after DNS resolution) ────────────────────────

const DENY_CIDRS = [
  // RFC1918
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  // Link-local
  "169.254.0.0/16",
  "fe80::/10",
  // Cloud metadata
  "169.254.169.254/32",
  // Loopback
  "127.0.0.0/8",
  "::1/128",
  // IPv4-mapped IPv6
  "::ffff:0.0.0.0/96",
  // IPv6 unique local
  "fc00::/7",
].map(parseCidr).filter((c): c is CidrRange => c !== null);

/** Known cloud metadata IPs that must always be blocked. */
export const METADATA_IPS = [
  "169.254.169.254",  // AWS, GCP, Azure
  "fd00:ec2::254",    // AWS IPv6 metadata
] as const;

/** Check if an IP is in a private/denied range. */
export function isPrivateIp(ip: string): boolean {
  // Try IPv4
  const v4 = parseIPv4(ip);
  if (v4) {
    return DENY_CIDRS.some((cidr) => !cidr.ipv6 && ipInCidr(v4, cidr));
  }

  // Try IPv6
  const v6 = parseIPv6(ip);
  if (v6) {
    return DENY_CIDRS.some((cidr) => cidr.ipv6 && ipInCidr(v6, cidr));
  }

  return false;
}

/** Check if an IP is a cloud metadata endpoint. */
export function isMetadataIp(ip: string): boolean {
  return METADATA_IPS.includes(ip as typeof METADATA_IPS[number]);
}

/** Check if an IP is an IPv4-mapped IPv6 address. */
export function isIPv4MappedIPv6(ip: string): boolean {
  return ip.startsWith("::ffff:");
}

// ── Egress validation ───────────────────────────────────────────────────────

/**
 * Check if an egress connection to a host:port is allowed.
 * @param host - hostname or IP
 * @param port - destination port
 * @param resolvedIp - IP address after DNS resolution
 * @param allowlist - allowed hosts
 * @param denylist - additional denied hosts (checked before allowlist)
 */
export function checkEgress(
  host: string,
  port: number,
  resolvedIp: string | undefined,
  allowlist: EgressRule[],
  denylist: string[] = [],
): EgressCheckResult {
  const base = { host, port, resolvedIp };

  // 1. Check explicit denylist (hostnames)
  for (const denied of denylist) {
    if (host === denied || host.endsWith(`.${denied}`)) {
      return { ...base, allowed: false, reason: `host ${host} is in denylist` };
    }
  }

  // 2. Check resolved IP against private ranges (SSRF protection)
  if (resolvedIp) {
    if (isMetadataIp(resolvedIp)) {
      return { ...base, allowed: false, reason: `resolved IP ${resolvedIp} is a cloud metadata endpoint` };
    }

    if (isIPv4MappedIPv6(resolvedIp)) {
      return { ...base, allowed: false, reason: `resolved IP ${resolvedIp} is IPv4-mapped IPv6 (rebinding risk)` };
    }

    if (isPrivateIp(resolvedIp)) {
      return { ...base, allowed: false, reason: `resolved IP ${resolvedIp} is in private range` };
    }
  }

  // 3. Check allowlist
  for (const rule of allowlist) {
    if (host === rule.host || host.endsWith(`.${rule.host}`)) {
      if (rule.ports.length === 0 || rule.ports.includes(port)) {
        return { ...base, allowed: true, reason: `allowed by rule for ${rule.host}` };
      }
    }
  }

  // 4. Default deny
  return { ...base, allowed: false, reason: "host not in allowlist" };
}

// ── DNS resolution with TTL cache ─────────────────────────────────────────

import { promises as dns } from "node:dns";
import { isIP } from "node:net";

interface DnsCacheEntry {
  ip: string;
  expiresAt: number;
}

const dnsCache = new Map<string, DnsCacheEntry>();
const DNS_TTL_MS = 60_000; // 60 seconds

/**
 * Resolve a hostname to an IPv4 address.
 * Returns the IP directly if the input is already an IP.
 * Caches results for 60 seconds.
 */
export async function resolveHost(hostname: string): Promise<string | undefined> {
  // If already an IP, return as-is
  if (isIP(hostname)) return hostname;

  // Check cache
  const cached = dnsCache.get(hostname);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.ip;
  }

  try {
    const [address] = await dns.resolve4(hostname);
    if (address) {
      dnsCache.set(hostname, { ip: address, expiresAt: Date.now() + DNS_TTL_MS });
      return address;
    }
  } catch {
    // DNS resolution failed — return undefined
  }
  return undefined;
}

/** Clear the DNS cache (for testing). */
export function clearDnsCache(): void {
  dnsCache.clear();
}

// ── Extra hosts from environment ──────────────────────────────────────────

/**
 * Parse LOBSEC_EGRESS_EXTRA_HOSTS env var format: "host:port,host:port,..."
 * Supports "host:port" (HTTPS) or bare "host" (port 443 default).
 */
export function parseExtraHosts(envValue: string): EgressRule[] {
  if (!envValue.trim()) return [];
  const results: EgressRule[] = [];
  for (const entry of envValue.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.lastIndexOf(":");
    if (colonIdx > 0) {
      const host = trimmed.slice(0, colonIdx);
      const port = parseInt(trimmed.slice(colonIdx + 1), 10);
      if (!isNaN(port) && port > 0 && port <= 65535) {
        results.push({ host, ports: [port], protocol: "https" });
        continue;
      }
    }
    // Bare hostname — default to 443
    results.push({ host: trimmed, ports: [443], protocol: "https" });
  }
  return results;
}

/**
 * Build the full egress allowlist by merging defaults with extra hosts.
 */
export function buildAllowlist(extraHosts?: EgressRule[]): EgressRule[] {
  return [...DEFAULT_ALLOWLIST, ...(extraHosts ?? [])];
}

// ── Default allowlist ───────────────────────────────────────────────────────

export const DEFAULT_ALLOWLIST: EgressRule[] = [
  { host: "api.anthropic.com", ports: [443], protocol: "https" },
  { host: "api.openai.com", ports: [443], protocol: "https" },
  { host: "api.telegram.org", ports: [443], protocol: "https" },
  { host: "slack.com", ports: [443], protocol: "https" },
  { host: "discord.com", ports: [443], protocol: "https" },
  { host: "api.perplexity.ai", ports: [443], protocol: "https" },
  { host: "smtp.gmail.com", ports: [587], protocol: "tcp" },
  { host: "imap.gmail.com", ports: [993], protocol: "tcp" },
  { host: "api.tomorrow.io", ports: [443], protocol: "https" },
];
