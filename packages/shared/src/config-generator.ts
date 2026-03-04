import type { HardenedOpenClawConfig } from "./types/openclaw-config.js";
import {
  REQUIRED_TOOLS_DENY,
  DANGEROUS_FLAGS,
  BLOCKED_ENV_VARS,
} from "./types/openclaw-config.js";

// ── Types ───────────────────────────────────────────────────────────────────

export interface ConfigGeneratorOptions {
  /** Auth token (or "${VAR}" placeholder for JIT substitution). */
  gatewayAuthToken: string;
  /** Allowed origins for the control UI. */
  allowedOrigins?: string[];
  /** Hostname allowlist for SSRF policy. */
  hostnameAllowlist?: string[];
  /** Model string for agent defaults. */
  defaultModel?: string;
  /** Tools profile name. */
  toolsProfile?: string;
  /** Redact patterns (regex strings). */
  redactPatterns?: string[];
  /** Allowed plugins. */
  allowedPlugins?: string[];
  /** Memory search config: baseUrl must point to the proxy, not directly to backends. */
  memorySearch?: {
    enabled: boolean;
    proxyBaseUrl: string;
    model: string;
  };
}

export interface ConfigValidationError {
  path: string;
  expected: string;
  actual: string;
}

// ── Generator ───────────────────────────────────────────────────────────────

/**
 * Generate a hardened OpenClaw configuration.
 * All 14 security settings are enforced; caller cannot override them.
 */
export function generateHardenedConfig(
  opts: ConfigGeneratorOptions,
): HardenedOpenClawConfig {
  return {
    gateway: {
      bind: "loopback",
      auth: { mode: "token", token: opts.gatewayAuthToken },
      controlUi: {
        dangerouslyDisableDeviceAuth: false,
        allowedOrigins: opts.allowedOrigins ?? ["https://localhost"],
      },
      trustedProxies: ["127.0.0.1"],
    },

    agents: {
      defaults: {
        model: opts.defaultModel ?? "default",
        sandbox: {
          mode: "all",
          scope: "agent",
          docker: {
            readOnlyRoot: true,
            capDrop: ["ALL"],
            network: "none",
          },
        },
      },
    },

    tools: {
      profile: opts.toolsProfile ?? "locked-down",
      deny: [...REQUIRED_TOOLS_DENY],
      exec: { security: "deny", ask: "always" },
      fs: { workspaceOnly: true },
      elevated: { enabled: false },
    },

    browser: {
      ssrfPolicy: {
        dangerouslyAllowPrivateNetwork: false,
        hostnameAllowlist: opts.hostnameAllowlist ?? [],
      },
    },

    discovery: { mdns: { mode: "off" } },
    session: { dmScope: "per-channel-peer" },
    logging: {
      redactSensitive: true,
      redactPatterns: opts.redactPatterns ?? [
        "Bearer\\s+[A-Za-z0-9._~+/=-]+",
        "[A-Za-z0-9]{32,}",
      ],
    },
    update: { auto: { enabled: false } },
    plugins: { allow: opts.allowedPlugins ?? [] },
    ...(opts.memorySearch ? {
      memorySearch: {
        enabled: opts.memorySearch.enabled,
        remote: {
          baseUrl: opts.memorySearch.proxyBaseUrl,
          model: opts.memorySearch.model,
        },
      },
    } : {}),
  };
}

// ── Substitution ────────────────────────────────────────────────────────────

/**
 * Substitute ${VAR_NAME} placeholders in the config with values from a map.
 * Returns [substituted config JSON, list of unresolved placeholders].
 */
export function substituteCredentials(
  config: HardenedOpenClawConfig,
  values: Record<string, string>,
): [string, string[]] {
  let json = JSON.stringify(config, null, 2);
  const unresolved: string[] = [];

  const placeholderRegex = /\$\{([A-Z_][A-Z0-9_]*)\}/g;
  json = json.replace(placeholderRegex, (match, varName: string) => {
    const val = values[varName];
    if (val !== undefined) return val;
    unresolved.push(varName);
    return match;
  });

  return [json, unresolved];
}

// ── Validation ──────────────────────────────────────────────────────────────

/** Deeply get a value from a nested object by dot-path. */
function getDeep(obj: unknown, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

/**
 * Validate that a config object satisfies all 14 hardened settings.
 * Returns an empty array if valid, otherwise a list of violations.
 */
export function validateHardenedConfig(
  config: unknown,
): ConfigValidationError[] {
  const errors: ConfigValidationError[] = [];

  function check(path: string, expected: unknown) {
    const actual = getDeep(config, path);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      errors.push({
        path,
        expected: JSON.stringify(expected),
        actual: JSON.stringify(actual),
      });
    }
  }

  // 1. Gateway bind
  check("gateway.bind", "loopback");

  // 2. Gateway auth mode
  check("gateway.auth.mode", "token");

  // 3. Disable device auth bypass
  check("gateway.controlUi.dangerouslyDisableDeviceAuth", false);

  // 4. Sandbox mode
  check("agents.defaults.sandbox.mode", "all");

  // 5. Sandbox scope
  check("agents.defaults.sandbox.scope", "agent");

  // 6. Docker read-only root
  check("agents.defaults.sandbox.docker.readOnlyRoot", true);

  // 7. Docker cap drop
  check("agents.defaults.sandbox.docker.capDrop", ["ALL"]);

  // 8. Docker network
  check("agents.defaults.sandbox.docker.network", "none");

  // 9. SSRF policy
  check("browser.ssrfPolicy.dangerouslyAllowPrivateNetwork", false);

  // 10. mDNS off
  check("discovery.mdns.mode", "off");

  // 11. Tool exec security
  check("tools.exec.security", "deny");

  // 12. Filesystem workspace-only
  check("tools.fs.workspaceOnly", true);

  // 13. Elevated tools disabled
  check("tools.elevated.enabled", false);

  // 14. Auto-update disabled
  check("update.auto.enabled", false);

  // 15. Session DM scope
  check("session.dmScope", "per-channel-peer");

  // 16. Redact sensitive
  check("logging.redactSensitive", true);

  // Validate tools.deny includes all required entries
  const toolsDeny = getDeep(config, "tools.deny");
  if (Array.isArray(toolsDeny)) {
    for (const required of REQUIRED_TOOLS_DENY) {
      if (!toolsDeny.includes(required)) {
        errors.push({
          path: "tools.deny",
          expected: `contains "${required}"`,
          actual: JSON.stringify(toolsDeny),
        });
      }
    }
  } else {
    errors.push({
      path: "tools.deny",
      expected: "array containing required deny entries",
      actual: JSON.stringify(toolsDeny),
    });
  }

  // Validate all dangerously* flags are false or absent
  for (const flagPath of DANGEROUS_FLAGS) {
    // These paths contain wildcards — for validation we check the known concrete paths
    // The concrete paths are already checked above (dangerouslyDisableDeviceAuth, dangerouslyAllowPrivateNetwork)
    // For the docker-related ones, check them explicitly
    if (flagPath.includes("dangerouslyAllowReservedContainerTargets")) {
      const val = getDeep(config, "agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets");
      if (val !== undefined && val !== false) {
        errors.push({
          path: flagPath,
          expected: "false or absent",
          actual: JSON.stringify(val),
        });
      }
    }
    if (flagPath.includes("dangerouslyAllowExternalBindSources")) {
      const val = getDeep(config, "agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources");
      if (val !== undefined && val !== false) {
        errors.push({
          path: flagPath,
          expected: "false or absent",
          actual: JSON.stringify(val),
        });
      }
    }
  }

  return errors;
}

/** List of environment variables that must be stripped from containers. */
export { BLOCKED_ENV_VARS };
