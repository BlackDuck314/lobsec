import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  generateHardenedConfig,
  substituteCredentials,
  validateHardenedConfig,
} from "./config-generator.js";
import type { ConfigGeneratorOptions } from "./config-generator.js";
import { REQUIRED_TOOLS_DENY, BLOCKED_ENV_VARS } from "./types/openclaw-config.js";

// ── Unit: generateHardenedConfig ──────────────────────────────────────────

describe("generateHardenedConfig", () => {
  it("produces config with all 14 security settings", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "test-token" });

    expect(config.gateway.bind).toBe("loopback");
    expect(config.gateway.auth.mode).toBe("token");
    expect(config.gateway.auth.token).toBe("test-token");
    expect(config.gateway.controlUi.dangerouslyDisableDeviceAuth).toBe(false);
    expect(config.gateway.trustedProxies).toEqual(["127.0.0.1"]);

    expect(config.agents.defaults.sandbox.mode).toBe("all");
    expect(config.agents.defaults.sandbox.scope).toBe("agent");
    expect(config.agents.defaults.sandbox.docker.readOnlyRoot).toBe(true);
    expect(config.agents.defaults.sandbox.docker.capDrop).toEqual(["ALL"]);
    expect(config.agents.defaults.sandbox.docker.network).toBe("none");

    expect(config.browser.ssrfPolicy.dangerouslyAllowPrivateNetwork).toBe(false);

    expect(config.discovery.mdns.mode).toBe("off");

    expect(config.tools.deny).toEqual([...REQUIRED_TOOLS_DENY]);
    expect(config.tools.exec.security).toBe("deny");
    expect(config.tools.fs.workspaceOnly).toBe(true);
    expect(config.tools.elevated.enabled).toBe(false);

    expect(config.session.dmScope).toBe("per-channel-peer");
    expect(config.logging.redactSensitive).toBe(true);
    expect(config.update.auto.enabled).toBe(false);
    expect(config.plugins.allow).toEqual([]);
  });

  it("accepts custom options without overriding security settings", () => {
    const config = generateHardenedConfig({
      gatewayAuthToken: "${GATEWAY_TOKEN}",
      allowedOrigins: ["https://my-app.local"],
      hostnameAllowlist: ["api.openai.com"],
      defaultModel: "llama-3.3-70b",
      toolsProfile: "minimal",
      redactPatterns: ["custom-pattern"],
      allowedPlugins: ["my-plugin"],
    });

    expect(config.gateway.controlUi.allowedOrigins).toEqual(["https://my-app.local"]);
    expect(config.browser.ssrfPolicy.hostnameAllowlist).toEqual(["api.openai.com"]);
    expect(config.agents.defaults.model).toBe("llama-3.3-70b");
    expect(config.tools.profile).toBe("minimal");
    expect(config.logging.redactPatterns).toEqual(["custom-pattern"]);
    expect(config.plugins.allow).toEqual(["my-plugin"]);

    // Security settings still enforced
    expect(config.gateway.bind).toBe("loopback");
    expect(config.tools.elevated.enabled).toBe(false);
  });
});

// ── Unit: substituteCredentials ───────────────────────────────────────────

describe("substituteCredentials", () => {
  it("substitutes ${VAR} placeholders", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "${GATEWAY_TOKEN}" });
    const [json, unresolved] = substituteCredentials(config, {
      GATEWAY_TOKEN: "secret-abc-123",
    });

    expect(json).toContain("secret-abc-123");
    expect(json).not.toContain("${GATEWAY_TOKEN}");
    expect(unresolved).toEqual([]);
  });

  it("reports unresolved placeholders", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "${GATEWAY_TOKEN}" });
    const [json, unresolved] = substituteCredentials(config, {});

    expect(json).toContain("${GATEWAY_TOKEN}");
    expect(unresolved).toEqual(["GATEWAY_TOKEN"]);
  });

  it("handles multiple placeholders", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "${TOKEN_A}" });
    // Manually add another placeholder in redactPatterns
    config.logging.redactPatterns = ["${PATTERN_VAR}"];

    const [json, unresolved] = substituteCredentials(config, {
      TOKEN_A: "val-a",
      PATTERN_VAR: "val-b",
    });

    expect(json).toContain("val-a");
    expect(json).toContain("val-b");
    expect(unresolved).toEqual([]);
  });
});

// ── Unit: validateHardenedConfig ──────────────────────────────────────────

describe("validateHardenedConfig", () => {
  it("returns empty array for valid config", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    expect(validateHardenedConfig(config)).toEqual([]);
  });

  it("detects gateway.bind violation", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const tampered = { ...config, gateway: { ...config.gateway, bind: "0.0.0.0" as const } };
    const errors = validateHardenedConfig(tampered);
    expect(errors.some((e) => e.path === "gateway.bind")).toBe(true);
  });

  it("detects missing tools.deny entries", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const tampered = { ...config, tools: { ...config.tools, deny: ["gateway"] } };
    const errors = validateHardenedConfig(tampered);
    expect(errors.some((e) => e.path === "tools.deny")).toBe(true);
  });

  it("detects dangerously* flags set to true", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const tampered = JSON.parse(JSON.stringify(config));
    tampered.agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets = true;
    const errors = validateHardenedConfig(tampered);
    expect(errors.length).toBeGreaterThan(0);
  });

  it("detects auto-update enabled", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const tampered = JSON.parse(JSON.stringify(config));
    tampered.update.auto.enabled = true;
    const errors = validateHardenedConfig(tampered);
    expect(errors.some((e) => e.path === "update.auto.enabled")).toBe(true);
  });

  it("detects elevated tools enabled", () => {
    const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
    const tampered = JSON.parse(JSON.stringify(config));
    tampered.tools.elevated.enabled = true;
    const errors = validateHardenedConfig(tampered);
    expect(errors.some((e) => e.path === "tools.elevated.enabled")).toBe(true);
  });
});

// ── Property 7: Hardened configuration completeness ───────────────────────

describe("Property 7: Hardened configuration completeness", () => {
  const optionsArb: fc.Arbitrary<ConfigGeneratorOptions> = fc.record({
    gatewayAuthToken: fc.string({ minLength: 1, maxLength: 64 }),
    allowedOrigins: fc.option(
      fc.array(fc.webUrl(), { minLength: 0, maxLength: 3 }),
      { nil: undefined },
    ),
    hostnameAllowlist: fc.option(
      fc.array(fc.domain(), { minLength: 0, maxLength: 5 }),
      { nil: undefined },
    ),
    defaultModel: fc.option(
      fc.stringMatching(/^[a-z0-9-]+$/),
      { nil: undefined },
    ),
    toolsProfile: fc.option(
      fc.constantFrom("locked-down", "minimal", "standard"),
      { nil: undefined },
    ),
    redactPatterns: fc.option(
      fc.array(fc.string({ minLength: 1, maxLength: 30 }), { minLength: 0, maxLength: 3 }),
      { nil: undefined },
    ),
    allowedPlugins: fc.option(
      fc.array(fc.string({ minLength: 1, maxLength: 20 }), { minLength: 0, maxLength: 3 }),
      { nil: undefined },
    ),
  });

  it("all 14 security settings are correct regardless of input options", () => {
    fc.assert(
      fc.property(optionsArb, (opts) => {
        const config = generateHardenedConfig(opts);
        const errors = validateHardenedConfig(config);
        expect(errors).toEqual([]);
      }),
      { numRuns: 100 },
    );
  });

  it("gateway always binds to loopback", () => {
    fc.assert(
      fc.property(optionsArb, (opts) => {
        const config = generateHardenedConfig(opts);
        expect(config.gateway.bind).toBe("loopback");
      }),
      { numRuns: 50 },
    );
  });

  it("tools.deny always contains all required entries", () => {
    fc.assert(
      fc.property(optionsArb, (opts) => {
        const config = generateHardenedConfig(opts);
        for (const entry of REQUIRED_TOOLS_DENY) {
          expect(config.tools.deny).toContain(entry);
        }
      }),
      { numRuns: 50 },
    );
  });

  it("no dangerously* flag is ever true", () => {
    fc.assert(
      fc.property(optionsArb, (opts) => {
        const config = generateHardenedConfig(opts);
        expect(config.gateway.controlUi.dangerouslyDisableDeviceAuth).toBe(false);
        expect(config.browser.ssrfPolicy.dangerouslyAllowPrivateNetwork).toBe(false);
      }),
      { numRuns: 50 },
    );
  });
});

// ── Property 8: Credential field substitution ─────────────────────────────

describe("Property 8: Credential field substitution", () => {
  it("all provided placeholders are resolved", () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          fc.stringMatching(/^[A-Z][A-Z0-9_]{0,19}$/),
          fc.string({ minLength: 1, maxLength: 50 }),
          { minKeys: 1, maxKeys: 5 },
        ),
        (vars) => {
          // Use first key as the gateway token placeholder
          const keys = Object.keys(vars);
          const tokenKey = keys[0]!;
          const config = generateHardenedConfig({
            gatewayAuthToken: `\${${tokenKey}}`,
          });

          const [json, unresolved] = substituteCredentials(config, vars);
          expect(unresolved).toEqual([]);
          expect(json).toContain(vars[tokenKey]);
          expect(json).not.toContain(`\${${tokenKey}}`);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("missing values are reported as unresolved", () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[A-Z][A-Z0-9_]{2,15}$/),
        (varName) => {
          const config = generateHardenedConfig({
            gatewayAuthToken: `\${${varName}}`,
          });

          const [, unresolved] = substituteCredentials(config, {});
          expect(unresolved).toContain(varName);
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ── Property 9: Configuration schema validation ──────────────────────────

describe("Property 9: Configuration schema validation", () => {
  it("generated configs always pass validation", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 64 }),
        (token) => {
          const config = generateHardenedConfig({ gatewayAuthToken: token });
          const errors = validateHardenedConfig(config);
          expect(errors).toEqual([]);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("tampering with any security setting causes validation failure", () => {
    const tamperPaths = [
      (c: ReturnType<typeof generateHardenedConfig>) => { (c.gateway as Record<string, unknown>).bind = "0.0.0.0"; },
      (c: ReturnType<typeof generateHardenedConfig>) => { c.gateway.controlUi.dangerouslyDisableDeviceAuth = true as unknown as false; },
      (c: ReturnType<typeof generateHardenedConfig>) => { (c.agents.defaults.sandbox as Record<string, unknown>).mode = "none"; },
      (c: ReturnType<typeof generateHardenedConfig>) => { c.browser.ssrfPolicy.dangerouslyAllowPrivateNetwork = true as unknown as false; },
      (c: ReturnType<typeof generateHardenedConfig>) => { (c.discovery.mdns as Record<string, unknown>).mode = "on"; },
      (c: ReturnType<typeof generateHardenedConfig>) => { (c.tools.exec as Record<string, unknown>).security = "allow"; },
      (c: ReturnType<typeof generateHardenedConfig>) => { (c.tools.fs as Record<string, unknown>).workspaceOnly = false; },
      (c: ReturnType<typeof generateHardenedConfig>) => { c.tools.elevated.enabled = true as unknown as false; },
      (c: ReturnType<typeof generateHardenedConfig>) => { c.update.auto.enabled = true as unknown as false; },
      (c: ReturnType<typeof generateHardenedConfig>) => { c.tools.deny = []; },
      (c: ReturnType<typeof generateHardenedConfig>) => { (c.logging as Record<string, unknown>).redactSensitive = false; },
    ];

    for (const tamperFn of tamperPaths) {
      const config = generateHardenedConfig({ gatewayAuthToken: "tok" });
      tamperFn(config);
      const errors = validateHardenedConfig(config);
      expect(errors.length).toBeGreaterThan(0);
    }
  });
});

// ── BLOCKED_ENV_VARS ─────────────────────────────────────────────────────

describe("BLOCKED_ENV_VARS", () => {
  it("contains all required dangerous env vars", () => {
    expect(BLOCKED_ENV_VARS.length).toBeGreaterThanOrEqual(13);
    expect(BLOCKED_ENV_VARS).toContain("OPENCLAW_BROWSER_CONTROL_MODULE");
    expect(BLOCKED_ENV_VARS).toContain("OPENCLAW_AUTH_MODULE");
    expect(BLOCKED_ENV_VARS).toContain("OPENCLAW_GATEWAY_MODULE");
  });
});
