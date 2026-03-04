/**
 * The hardened openclaw.json shape that lobsec generates.
 * These are the security-relevant fields only.
 */
export interface HardenedOpenClawConfig {
  gateway: {
    bind: "loopback";
    auth: { mode: "token"; token: string };
    controlUi: {
      dangerouslyDisableDeviceAuth: false;
      allowedOrigins: string[];
    };
    trustedProxies: ["127.0.0.1"];
  };

  agents: {
    defaults: {
      model: string;
      sandbox: {
        mode: "all";
        scope: "agent";
        docker: {
          readOnlyRoot: true;
          capDrop: ["ALL"];
          network: "none";
        };
      };
    };
  };

  tools: {
    profile: string;
    deny: string[];
    exec: { security: "deny"; ask: "always" };
    fs: { workspaceOnly: true };
    elevated: { enabled: false };
  };

  browser: {
    ssrfPolicy: {
      dangerouslyAllowPrivateNetwork: false;
      hostnameAllowlist: string[];
    };
  };

  discovery: { mdns: { mode: "off" } };
  session: { dmScope: "per-channel-peer" };
  logging: { redactSensitive: true; redactPatterns: string[] };
  update: { auto: { enabled: false } };
  plugins: { allow: string[] };
  memorySearch?: {
    enabled: boolean;
    remote: { baseUrl: string; model: string };
  };
}

/** The required tools.deny list */
export const REQUIRED_TOOLS_DENY = [
  "gateway",
  "sessions_spawn",
  "sessions_send",
  "group:automation",
  "group:runtime",
] as const;

/** All dangerously* flags that must be false or absent */
export const DANGEROUS_FLAGS = [
  "agents.*.sandbox.docker.dangerouslyAllowReservedContainerTargets",
  "agents.*.sandbox.docker.dangerouslyAllowExternalBindSources",
  "gateway.controlUi.dangerouslyDisableDeviceAuth",
  "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork",
] as const;

/** Environment variables that must be stripped from containers (F7) */
export const BLOCKED_ENV_VARS = [
  "OPENCLAW_BROWSER_CONTROL_MODULE",
  "OPENCLAW_BUNDLED_PLUGINS_DIR",
  "OPENCLAW_BUNDLED_SKILLS_DIR",
  "OPENCLAW_BUNDLED_HOOKS_DIR",
  "OPENCLAW_LIVE_CLI_BACKEND",
  "OPENCLAW_BUNDLED_CHANNELS_DIR",
  "OPENCLAW_BUNDLED_TOOLS_DIR",
  "OPENCLAW_BUNDLED_SANDBOXES_DIR",
  "OPENCLAW_CONFIG_MODULE",
  "OPENCLAW_MEMORY_MODULE",
  "OPENCLAW_STORAGE_MODULE",
  "OPENCLAW_AUTH_MODULE",
  "OPENCLAW_GATEWAY_MODULE",
] as const;
