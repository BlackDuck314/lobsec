// ── Docker Container Orchestration ──────────────────────────────────────────
// Manages container lifecycle, networks, and security context.
// Six isolation domains: caddy, lobsec-proxy, gateway, sandbox-exec,
// sandbox-browser, lobsec-cli (host).

import { BLOCKED_ENV_VARS } from "./types/openclaw-config.js";

// ── Types ───────────────────────────────────────────────────────────────────

export type ContainerName =
  | "caddy"
  | "lobsec-proxy"
  | "openclaw-gateway"
  | "sandbox-exec"
  | "sandbox-browser";

export type NetworkName =
  | "lobsec-internal"
  | "lobsec-sandbox"
  | "lobsec-egress";

export interface DockerNetwork {
  name: NetworkName;
  internal: boolean;
  driver: "bridge";
  subnet?: string;
}

export interface VolumeMount {
  source: string;
  target: string;
  readOnly: boolean;
  type: "bind" | "tmpfs" | "volume";
}

export interface SecurityContext {
  capDrop: string[];
  capAdd: string[];
  noNewPrivileges: boolean;
  readOnlyRootfs: boolean;
  user: string;
  seccompProfile?: string;
  apparmorProfile?: string;
}

export interface ContainerConfig {
  name: ContainerName;
  image: string;
  networks: NetworkName[];
  ports: Array<{ host: number; container: number; protocol: "tcp" | "udp" }>;
  volumes: VolumeMount[];
  envVars: Record<string, string>;
  security: SecurityContext;
  healthCheck?: HealthCheck;
  dependsOn: ContainerName[];
}

export interface HealthCheck {
  test: string[];
  intervalSeconds: number;
  timeoutSeconds: number;
  retries: number;
  startPeriodSeconds: number;
}

export type ContainerStatus = "created" | "running" | "healthy" | "unhealthy" | "stopped" | "error";

export interface ContainerState {
  name: ContainerName;
  status: ContainerStatus;
  startedAt?: string;
  healthCheckPassed: boolean;
}

export interface OrchestrationEvent {
  action: "network-create" | "container-start" | "health-check" | "container-stop" | "container-restart";
  target: string;
  success: boolean;
  detail?: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Default security context for all containers. */
export const DEFAULT_SECURITY_CONTEXT: SecurityContext = {
  capDrop: ["ALL"],
  capAdd: [],
  noNewPrivileges: true,
  readOnlyRootfs: true,
  user: "1000:1000",
};

/** Required Docker networks. */
export const REQUIRED_NETWORKS: DockerNetwork[] = [
  { name: "lobsec-internal", internal: true, driver: "bridge", subnet: "172.28.0.0/24" },
  { name: "lobsec-sandbox", internal: true, driver: "bridge", subnet: "172.28.1.0/24" },
  { name: "lobsec-egress", internal: false, driver: "bridge", subnet: "172.28.2.0/24" },
];

/** Container startup order. */
export const CONTAINER_STARTUP_ORDER: ContainerName[] = [
  "caddy",
  "lobsec-proxy",
  "openclaw-gateway",
  "sandbox-exec",
  "sandbox-browser",
];

/** Shutdown is reverse of startup. */
export const CONTAINER_SHUTDOWN_ORDER: ContainerName[] = [...CONTAINER_STARTUP_ORDER].reverse();

// ── Network Validation ──────────────────────────────────────────────────────

/** Validate that networks satisfy isolation requirements. */
export function validateNetworks(networks: DockerNetwork[]): string[] {
  const errors: string[] = [];
  const names = new Set(networks.map((n) => n.name));

  // Must have all required networks
  for (const req of REQUIRED_NETWORKS) {
    if (!names.has(req.name)) {
      errors.push(`Missing required network: ${req.name}`);
    }
  }

  // Internal networks must be internal
  const internal = networks.find((n) => n.name === "lobsec-internal");
  if (internal && !internal.internal) {
    errors.push("lobsec-internal must be an internal network");
  }

  const sandbox = networks.find((n) => n.name === "lobsec-sandbox");
  if (sandbox && !sandbox.internal) {
    errors.push("lobsec-sandbox must be an internal network");
  }

  return errors;
}

// ── Container Configuration Builder ─────────────────────────────────────────

/** Build container configurations with security defaults. */
export function buildContainerConfig(
  name: ContainerName,
  overrides: Partial<Omit<ContainerConfig, "name">> = {},
): ContainerConfig {
  const defaults = getContainerDefaults(name);
  return {
    ...defaults,
    ...overrides,
    name,
    security: {
      ...DEFAULT_SECURITY_CONTEXT,
      ...defaults.security,
      ...overrides.security,
    },
    envVars: stripDangerousEnvVars({
      ...defaults.envVars,
      ...overrides.envVars,
    }),
  };
}

function getContainerDefaults(name: ContainerName): Omit<ContainerConfig, "name"> {
  switch (name) {
    case "caddy":
      return {
        image: "caddy:2-alpine",
        networks: ["lobsec-internal", "lobsec-egress"],
        ports: [{ host: 443, container: 443, protocol: "tcp" }],
        volumes: [
          { source: "/etc/lobsec/caddy/Caddyfile", target: "/etc/caddy/Caddyfile", readOnly: true, type: "bind" },
          { source: "", target: "/data", readOnly: false, type: "tmpfs" },
          { source: "", target: "/config", readOnly: false, type: "tmpfs" },
        ],
        envVars: {},
        security: {
          ...DEFAULT_SECURITY_CONTEXT,
          capAdd: ["NET_BIND_SERVICE"],
        },
        healthCheck: {
          test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:2019/config/"],
          intervalSeconds: 10,
          timeoutSeconds: 5,
          retries: 3,
          startPeriodSeconds: 10,
        },
        dependsOn: [],
      };

    case "lobsec-proxy":
      return {
        image: "lobsec-proxy:latest",
        networks: ["lobsec-internal"],
        ports: [],
        volumes: [
          { source: "/etc/lobsec/config", target: "/etc/lobsec/config", readOnly: true, type: "bind" },
          { source: "", target: "/run/lobsec/creds", readOnly: false, type: "tmpfs" },
        ],
        envVars: {},
        security: DEFAULT_SECURITY_CONTEXT,
        healthCheck: {
          test: ["CMD", "node", "-e", "process.exit(0)"],
          intervalSeconds: 10,
          timeoutSeconds: 5,
          retries: 3,
          startPeriodSeconds: 5,
        },
        dependsOn: ["caddy"],
      };

    case "openclaw-gateway":
      return {
        image: "openclaw-gateway:latest",
        networks: ["lobsec-internal", "lobsec-sandbox"],
        ports: [],
        volumes: [
          { source: "/etc/lobsec/config", target: "/etc/openclaw", readOnly: true, type: "bind" },
          { source: "", target: "/run/lobsec/creds", readOnly: false, type: "tmpfs" },
        ],
        envVars: {},
        security: DEFAULT_SECURITY_CONTEXT,
        healthCheck: {
          test: ["CMD", "node", "-e", "process.exit(0)"],
          intervalSeconds: 10,
          timeoutSeconds: 5,
          retries: 3,
          startPeriodSeconds: 15,
        },
        dependsOn: ["lobsec-proxy"],
      };

    case "sandbox-exec":
      return {
        image: "openclaw-sandbox:latest",
        networks: ["lobsec-sandbox"],
        ports: [],
        volumes: [
          { source: "", target: "/workspace", readOnly: false, type: "tmpfs" },
        ],
        envVars: {},
        security: {
          ...DEFAULT_SECURITY_CONTEXT,
          seccompProfile: "lobsec-sandbox.json",
          apparmorProfile: "lobsec-sandbox",
        },
        healthCheck: {
          test: ["CMD", "true"],
          intervalSeconds: 30,
          timeoutSeconds: 5,
          retries: 3,
          startPeriodSeconds: 5,
        },
        dependsOn: ["openclaw-gateway"],
      };

    case "sandbox-browser":
      return {
        image: "openclaw-browser:latest",
        networks: ["lobsec-sandbox"],
        ports: [],
        volumes: [],
        envVars: {},
        security: {
          ...DEFAULT_SECURITY_CONTEXT,
          seccompProfile: "lobsec-browser.json",
          apparmorProfile: "lobsec-browser",
        },
        dependsOn: ["openclaw-gateway"],
      };
  }
}

/** Strip dangerous environment variables that bypass security. */
export function stripDangerousEnvVars(envVars: Record<string, string>): Record<string, string> {
  const cleaned: Record<string, string> = {};
  for (const [key, value] of Object.entries(envVars)) {
    if (!(BLOCKED_ENV_VARS as readonly string[]).includes(key)) {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

// ── Security Validation ─────────────────────────────────────────────────────

/** Validate a container config meets security requirements. */
export function validateContainerSecurity(config: ContainerConfig): string[] {
  const errors: string[] = [];

  // Must drop ALL capabilities
  if (!config.security.capDrop.includes("ALL")) {
    errors.push(`${config.name}: must drop ALL capabilities`);
  }

  // Must have no-new-privileges
  if (!config.security.noNewPrivileges) {
    errors.push(`${config.name}: must set no-new-privileges`);
  }

  // Must have read-only root filesystem
  if (!config.security.readOnlyRootfs) {
    errors.push(`${config.name}: must have read-only root filesystem`);
  }

  // Must not run as root
  if (config.security.user === "0" || config.security.user === "root" || config.security.user === "0:0") {
    errors.push(`${config.name}: must not run as root`);
  }

  // Must not mount Docker socket
  for (const vol of config.volumes) {
    if (vol.source.includes("docker.sock")) {
      errors.push(`${config.name}: must not mount Docker socket`);
    }
  }

  // Must not have blocked env vars
  for (const envVar of BLOCKED_ENV_VARS) {
    if (envVar in config.envVars) {
      errors.push(`${config.name}: blocked env var ${envVar}`);
    }
  }

  // Sandbox containers must have seccomp
  if ((config.name === "sandbox-exec" || config.name === "sandbox-browser") && !config.security.seccompProfile) {
    errors.push(`${config.name}: sandbox containers must have seccomp profile`);
  }

  return errors;
}

/** Validate gateway network isolation (Property 13). */
export function validateGatewayIsolation(configs: ContainerConfig[]): string[] {
  const errors: string[] = [];

  const gateway = configs.find((c) => c.name === "openclaw-gateway");
  if (!gateway) return ["openclaw-gateway config not found"];

  // Gateway must NOT be on egress network
  if (gateway.networks.includes("lobsec-egress")) {
    errors.push("openclaw-gateway must not be on lobsec-egress network");
  }

  // Gateway must be on internal and sandbox only
  for (const net of gateway.networks) {
    if (net !== "lobsec-internal" && net !== "lobsec-sandbox") {
      errors.push(`openclaw-gateway on unexpected network: ${net}`);
    }
  }

  // Gateway must not expose any ports
  if (gateway.ports.length > 0) {
    errors.push("openclaw-gateway must not expose any ports");
  }

  return errors;
}

/** Validate Docker socket is never mounted (Property 14). */
export function validateDockerSocketIsolation(configs: ContainerConfig[]): string[] {
  const errors: string[] = [];
  for (const config of configs) {
    for (const vol of config.volumes) {
      if (vol.source.includes("docker.sock") || vol.target.includes("docker.sock")) {
        errors.push(`${config.name}: Docker socket mounted`);
      }
    }
  }
  return errors;
}

// ── Mock Container Orchestrator ─────────────────────────────────────────────

export class ContainerOrchestrator {
  private states = new Map<ContainerName, ContainerState>();
  private events: OrchestrationEvent[] = [];
  private onEvent?: (event: OrchestrationEvent) => void;

  constructor(onEvent?: (event: OrchestrationEvent) => void) {
    this.onEvent = onEvent;
    for (const name of CONTAINER_STARTUP_ORDER) {
      this.states.set(name, { name, status: "stopped", healthCheckPassed: false });
    }
  }

  /** Create required networks. */
  createNetworks(): OrchestrationEvent[] {
    const results: OrchestrationEvent[] = [];
    for (const net of REQUIRED_NETWORKS) {
      const event: OrchestrationEvent = {
        action: "network-create",
        target: net.name,
        success: true,
        detail: net.internal ? "internal" : "external",
      };
      results.push(event);
      this.events.push(event);
      this.onEvent?.(event);
    }
    return results;
  }

  /** Start containers in order, with health checks between stages. */
  startAll(configs: ContainerConfig[]): OrchestrationEvent[] {
    const results: OrchestrationEvent[] = [];

    for (const name of CONTAINER_STARTUP_ORDER) {
      const config = configs.find((c) => c.name === name);
      if (!config) continue;

      // Check dependencies
      const depsReady = config.dependsOn.every((dep) => {
        const state = this.states.get(dep);
        return state && (state.status === "running" || state.status === "healthy");
      });

      if (!depsReady) {
        const event: OrchestrationEvent = {
          action: "container-start",
          target: name,
          success: false,
          detail: "dependencies not ready",
        };
        results.push(event);
        this.events.push(event);
        this.onEvent?.(event);
        break;
      }

      // Start container
      const state = this.states.get(name)!;
      state.status = "running";
      state.startedAt = new Date().toISOString();

      const startEvent: OrchestrationEvent = {
        action: "container-start",
        target: name,
        success: true,
      };
      results.push(startEvent);
      this.events.push(startEvent);
      this.onEvent?.(startEvent);

      // Simulate health check
      if (config.healthCheck) {
        state.healthCheckPassed = true;
        state.status = "healthy";
        const healthEvent: OrchestrationEvent = {
          action: "health-check",
          target: name,
          success: true,
        };
        results.push(healthEvent);
        this.events.push(healthEvent);
        this.onEvent?.(healthEvent);
      }
    }

    return results;
  }

  /** Stop all containers in reverse order. */
  stopAll(): OrchestrationEvent[] {
    const results: OrchestrationEvent[] = [];

    for (const name of CONTAINER_SHUTDOWN_ORDER) {
      const state = this.states.get(name);
      if (!state || state.status === "stopped") continue;

      state.status = "stopped";
      state.healthCheckPassed = false;

      const event: OrchestrationEvent = {
        action: "container-stop",
        target: name,
        success: true,
      };
      results.push(event);
      this.events.push(event);
      this.onEvent?.(event);
    }

    return results;
  }

  /** Get current state of all containers. */
  getStates(): ContainerState[] {
    return [...this.states.values()];
  }

  /** Get state of a specific container. */
  getState(name: ContainerName): ContainerState | undefined {
    return this.states.get(name);
  }

  /** Get full event log. */
  getEventLog(): OrchestrationEvent[] {
    return [...this.events];
  }

  /** Check if all containers are healthy. */
  allHealthy(): boolean {
    return [...this.states.values()].every(
      (s) => s.status === "healthy" || s.status === "running",
    );
  }
}
