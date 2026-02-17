import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  buildContainerConfig,
  validateContainerSecurity,
  validateNetworks,
  validateGatewayIsolation,
  validateDockerSocketIsolation,
  stripDangerousEnvVars,
  ContainerOrchestrator,
  REQUIRED_NETWORKS,
  CONTAINER_STARTUP_ORDER,
  CONTAINER_SHUTDOWN_ORDER,
} from "./container-orchestrator.js";
import type { ContainerName } from "./container-orchestrator.js";
import { BLOCKED_ENV_VARS } from "./types/openclaw-config.js";

// ── Unit: Network validation ────────────────────────────────────────────────

describe("Network validation", () => {
  it("passes with all required networks", () => {
    const errors = validateNetworks(REQUIRED_NETWORKS);
    expect(errors).toEqual([]);
  });

  it("fails with missing network", () => {
    const networks = REQUIRED_NETWORKS.filter((n) => n.name !== "lobsec-internal");
    const errors = validateNetworks(networks);
    expect(errors.some((e) => e.includes("lobsec-internal"))).toBe(true);
  });

  it("fails when internal network is not internal", () => {
    const networks = REQUIRED_NETWORKS.map((n) =>
      n.name === "lobsec-internal" ? { ...n, internal: false } : n,
    );
    const errors = validateNetworks(networks);
    expect(errors.some((e) => e.includes("internal"))).toBe(true);
  });

  it("lobsec-sandbox must be internal", () => {
    const networks = REQUIRED_NETWORKS.map((n) =>
      n.name === "lobsec-sandbox" ? { ...n, internal: false } : n,
    );
    const errors = validateNetworks(networks);
    expect(errors.some((e) => e.includes("sandbox"))).toBe(true);
  });
});

// ── Unit: Container config builder ──────────────────────────────────────────

describe("Container config builder", () => {
  it("builds caddy config with security defaults", () => {
    const config = buildContainerConfig("caddy");
    expect(config.name).toBe("caddy");
    expect(config.security.capDrop).toContain("ALL");
    expect(config.security.noNewPrivileges).toBe(true);
    expect(config.security.readOnlyRootfs).toBe(true);
  });

  it("caddy has NET_BIND_SERVICE capability", () => {
    const config = buildContainerConfig("caddy");
    expect(config.security.capAdd).toContain("NET_BIND_SERVICE");
  });

  it("sandbox-exec has seccomp profile", () => {
    const config = buildContainerConfig("sandbox-exec");
    expect(config.security.seccompProfile).toBeDefined();
  });

  it("gateway is on internal and sandbox only", () => {
    const config = buildContainerConfig("openclaw-gateway");
    expect(config.networks).toContain("lobsec-internal");
    expect(config.networks).toContain("lobsec-sandbox");
    expect(config.networks).not.toContain("lobsec-egress");
  });

  it("strips dangerous env vars", () => {
    const config = buildContainerConfig("openclaw-gateway", {
      envVars: {
        "SAFE_VAR": "ok",
        "OPENCLAW_BROWSER_CONTROL_MODULE": "bad",
      },
    });
    expect(config.envVars["SAFE_VAR"]).toBe("ok");
    expect(config.envVars["OPENCLAW_BROWSER_CONTROL_MODULE"]).toBeUndefined();
  });
});

// ── Unit: Security validation ───────────────────────────────────────────────

describe("Container security validation", () => {
  it("all default configs pass validation", () => {
    for (const name of CONTAINER_STARTUP_ORDER) {
      const config = buildContainerConfig(name);
      const errors = validateContainerSecurity(config);
      expect(errors).toEqual([]);
    }
  });

  it("fails without cap_drop ALL", () => {
    const config = buildContainerConfig("caddy");
    config.security.capDrop = [];
    const errors = validateContainerSecurity(config);
    expect(errors.some((e) => e.includes("ALL"))).toBe(true);
  });

  it("fails without no-new-privileges", () => {
    const config = buildContainerConfig("caddy");
    config.security.noNewPrivileges = false;
    const errors = validateContainerSecurity(config);
    expect(errors.some((e) => e.includes("no-new-privileges"))).toBe(true);
  });

  it("fails with writable root", () => {
    const config = buildContainerConfig("caddy");
    config.security.readOnlyRootfs = false;
    const errors = validateContainerSecurity(config);
    expect(errors.some((e) => e.includes("read-only"))).toBe(true);
  });

  it("fails when running as root", () => {
    const config = buildContainerConfig("caddy");
    config.security.user = "0:0";
    const errors = validateContainerSecurity(config);
    expect(errors.some((e) => e.includes("root"))).toBe(true);
  });

  it("fails with Docker socket mount", () => {
    const config = buildContainerConfig("caddy");
    config.volumes.push({
      source: "/var/run/docker.sock",
      target: "/var/run/docker.sock",
      readOnly: false,
      type: "bind",
    });
    const errors = validateContainerSecurity(config);
    expect(errors.some((e) => e.includes("Docker socket"))).toBe(true);
  });

  it("fails when sandbox lacks seccomp", () => {
    const config = buildContainerConfig("sandbox-exec");
    config.security.seccompProfile = undefined;
    const errors = validateContainerSecurity(config);
    expect(errors.some((e) => e.includes("seccomp"))).toBe(true);
  });
});

// ── Unit: Dangerous env var stripping ───────────────────────────────────────

describe("stripDangerousEnvVars", () => {
  it("removes all blocked env vars", () => {
    const input: Record<string, string> = {};
    for (const v of BLOCKED_ENV_VARS) {
      input[v] = "bad-value";
    }
    input["SAFE_KEY"] = "ok";

    const result = stripDangerousEnvVars(input);
    for (const v of BLOCKED_ENV_VARS) {
      expect(result[v]).toBeUndefined();
    }
    expect(result["SAFE_KEY"]).toBe("ok");
  });
});

// ── Unit: Gateway isolation ─────────────────────────────────────────────────

describe("Gateway isolation", () => {
  it("default gateway config passes isolation check", () => {
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));
    const errors = validateGatewayIsolation(configs);
    expect(errors).toEqual([]);
  });

  it("fails when gateway is on egress network", () => {
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));
    const gateway = configs.find((c) => c.name === "openclaw-gateway")!;
    gateway.networks.push("lobsec-egress");

    const errors = validateGatewayIsolation(configs);
    expect(errors.some((e) => e.includes("egress"))).toBe(true);
  });

  it("fails when gateway exposes ports", () => {
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));
    const gateway = configs.find((c) => c.name === "openclaw-gateway")!;
    gateway.ports.push({ host: 8080, container: 8080, protocol: "tcp" });

    const errors = validateGatewayIsolation(configs);
    expect(errors.some((e) => e.includes("ports"))).toBe(true);
  });
});

// ── Unit: Docker socket isolation ───────────────────────────────────────────

describe("Docker socket isolation", () => {
  it("default configs have no Docker socket", () => {
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));
    const errors = validateDockerSocketIsolation(configs);
    expect(errors).toEqual([]);
  });
});

// ── Unit: Container orchestrator ────────────────────────────────────────────

describe("ContainerOrchestrator", () => {
  it("creates all required networks", () => {
    const orch = new ContainerOrchestrator();
    const events = orch.createNetworks();

    expect(events).toHaveLength(REQUIRED_NETWORKS.length);
    expect(events.every((e) => e.success)).toBe(true);
  });

  it("starts containers in correct order", () => {
    const orch = new ContainerOrchestrator();
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));

    orch.createNetworks();
    const events = orch.startAll(configs);

    const startEvents = events.filter((e) => e.action === "container-start" && e.success);
    const startOrder = startEvents.map((e) => e.target);
    expect(startOrder).toEqual(CONTAINER_STARTUP_ORDER);
  });

  it("all containers become healthy after startup", () => {
    const orch = new ContainerOrchestrator();
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));

    orch.createNetworks();
    orch.startAll(configs);
    expect(orch.allHealthy()).toBe(true);
  });

  it("stops containers in reverse order", () => {
    const orch = new ContainerOrchestrator();
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));

    orch.createNetworks();
    orch.startAll(configs);
    const stopEvents = orch.stopAll();

    const stopOrder = stopEvents.map((e) => e.target);
    expect(stopOrder).toEqual(CONTAINER_SHUTDOWN_ORDER);
  });

  it("all containers stopped after shutdown", () => {
    const orch = new ContainerOrchestrator();
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));

    orch.createNetworks();
    orch.startAll(configs);
    orch.stopAll();

    const states = orch.getStates();
    expect(states.every((s) => s.status === "stopped")).toBe(true);
  });

  it("tracks full event log", () => {
    const orch = new ContainerOrchestrator();
    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));

    orch.createNetworks();
    orch.startAll(configs);
    orch.stopAll();

    const log = orch.getEventLog();
    expect(log.length).toBeGreaterThan(0);
    expect(log.some((e) => e.action === "network-create")).toBe(true);
    expect(log.some((e) => e.action === "container-start")).toBe(true);
    expect(log.some((e) => e.action === "container-stop")).toBe(true);
  });
});

// ── Property 12: Container security context completeness ────────────────────

describe("Property 12: Container security context completeness", () => {
  it("all containers built with defaults pass security validation", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...CONTAINER_STARTUP_ORDER) as fc.Arbitrary<ContainerName>,
        (name) => {
          const config = buildContainerConfig(name);
          const errors = validateContainerSecurity(config);
          expect(errors).toEqual([]);
        },
      ),
      { numRuns: 20 },
    );
  });

  it("adding blocked env vars are always stripped", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...CONTAINER_STARTUP_ORDER) as fc.Arbitrary<ContainerName>,
        fc.constantFrom(...BLOCKED_ENV_VARS),
        fc.string({ minLength: 1, maxLength: 50 }),
        (name, blockedVar, value) => {
          const config = buildContainerConfig(name, {
            envVars: { [blockedVar]: value },
          });
          expect(config.envVars[blockedVar]).toBeUndefined();
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ── Property 13: Gateway network isolation ──────────────────────────────────

describe("Property 13: Gateway network isolation", () => {
  it("gateway is never on egress network in default config", () => {
    fc.assert(
      fc.property(
        fc.constant(null),
        () => {
          const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));
          const errors = validateGatewayIsolation(configs);
          expect(errors).toEqual([]);

          const gateway = configs.find((c) => c.name === "openclaw-gateway")!;
          expect(gateway.networks).not.toContain("lobsec-egress");
        },
      ),
      { numRuns: 5 },
    );
  });
});

// ── Property 14: Docker socket isolation ────────────────────────────────────

describe("Property 14: Docker socket isolation", () => {
  it("no container ever mounts Docker socket", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...CONTAINER_STARTUP_ORDER) as fc.Arbitrary<ContainerName>,
        (name) => {
          const config = buildContainerConfig(name);

          for (const vol of config.volumes) {
            expect(vol.source).not.toContain("docker.sock");
            expect(vol.target).not.toContain("docker.sock");
          }
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Integration: Full orchestration lifecycle ───────────────────────────────

describe("Full orchestration lifecycle", () => {
  it("create networks → start → health check → stop", () => {
    const events: string[] = [];
    const orch = new ContainerOrchestrator((event) => {
      events.push(`${event.action}:${event.target}`);
    });

    const configs = CONTAINER_STARTUP_ORDER.map((n) => buildContainerConfig(n));

    // Create networks
    orch.createNetworks();
    expect(events.some((e) => e.startsWith("network-create:"))).toBe(true);

    // Start all
    orch.startAll(configs);
    expect(orch.allHealthy()).toBe(true);

    // Verify each container's state
    for (const name of CONTAINER_STARTUP_ORDER) {
      const state = orch.getState(name);
      expect(state?.status === "running" || state?.status === "healthy").toBe(true);
    }

    // Stop all
    orch.stopAll();
    for (const name of CONTAINER_STARTUP_ORDER) {
      expect(orch.getState(name)?.status).toBe("stopped");
    }
  });
});
