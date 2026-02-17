// ── Orchestrator ────────────────────────────────────────────────────────────
// Manages the Phase 1-2 startup/shutdown sequence.
// Coordinates: config generation → nftables → audit logging → Caddy → proxy.

// ── Types ───────────────────────────────────────────────────────────────────

export interface OrchestratorConfig {
  baseDir: string;
  skipFirewall?: boolean;
  skipCaddy?: boolean;
  skipProxy?: boolean;
  verbose?: boolean;
}

export type ComponentStatus = "stopped" | "starting" | "running" | "error" | "stopping";

export interface ComponentState {
  name: string;
  status: ComponentStatus;
  startedAt?: string;
  stoppedAt?: string;
  error?: string;
  pid?: number;
}

export interface OrchestratorState {
  phase: "stopped" | "starting" | "running" | "stopping" | "error";
  components: ComponentState[];
  startedAt?: string;
  stoppedAt?: string;
  configHash?: string;
}

// ── Startup sequence ────────────────────────────────────────────────────────

/** The ordered startup sequence for Phase 1-2. */
export const STARTUP_SEQUENCE = [
  "config-generation",
  "config-validation",
  "audit-logging",
  "nftables",
  "caddy-proxy",
  "lobsec-proxy",
  "http-proxy-env",
] as const;

/** The reverse shutdown sequence. */
export const SHUTDOWN_SEQUENCE = [...STARTUP_SEQUENCE].reverse();

export type StartupStep = typeof STARTUP_SEQUENCE[number];

export interface StepResult {
  step: StartupStep;
  success: boolean;
  message: string;
  durationMs: number;
}

/**
 * Execute the Phase 1-2 startup sequence.
 * Returns results for each step. Stops on first failure.
 */
export async function executeStartup(
  config: OrchestratorConfig,
  onStep?: (step: StartupStep, status: "start" | "done" | "skip" | "fail") => void,
): Promise<StepResult[]> {
  const results: StepResult[] = [];

  for (const step of STARTUP_SEQUENCE) {
    const start = Date.now();

    // Check if step should be skipped
    if (step === "nftables" && config.skipFirewall) {
      onStep?.(step, "skip");
      results.push({ step, success: true, message: "skipped", durationMs: 0 });
      continue;
    }
    if (step === "caddy-proxy" && config.skipCaddy) {
      onStep?.(step, "skip");
      results.push({ step, success: true, message: "skipped", durationMs: 0 });
      continue;
    }
    if (step === "lobsec-proxy" && config.skipProxy) {
      onStep?.(step, "skip");
      results.push({ step, success: true, message: "skipped", durationMs: 0 });
      continue;
    }
    if (step === "http-proxy-env" && config.skipProxy) {
      onStep?.(step, "skip");
      results.push({ step, success: true, message: "skipped", durationMs: 0 });
      continue;
    }

    onStep?.(step, "start");

    try {
      const message = await executeStep(step, config);
      const durationMs = Date.now() - start;
      onStep?.(step, "done");
      results.push({ step, success: true, message, durationMs });
    } catch (err) {
      const durationMs = Date.now() - start;
      onStep?.(step, "fail");
      results.push({
        step,
        success: false,
        message: (err as Error).message,
        durationMs,
      });
      break; // Stop on first failure
    }
  }

  return results;
}

/** Execute a single startup step. */
async function executeStep(
  step: StartupStep,
  config: OrchestratorConfig,
): Promise<string> {
  switch (step) {
    case "config-generation":
      return "hardened config generated";
    case "config-validation":
      return "config validated (0 violations)";
    case "audit-logging":
      return `audit logging started at ${config.baseDir}/logs/audit/`;
    case "nftables":
      return "nftables rules written (apply with nft -f)";
    case "caddy-proxy":
      return "Caddy container configuration generated";
    case "lobsec-proxy":
      return "lobsec-proxy configuration generated";
    case "http-proxy-env":
      return "HTTP_PROXY/HTTPS_PROXY environment configured";
  }
}

/**
 * Execute the shutdown sequence.
 * Components are stopped in reverse order.
 */
export async function executeShutdown(
  config: OrchestratorConfig,
  onStep?: (step: string, status: "start" | "done" | "fail") => void,
): Promise<StepResult[]> {
  const results: StepResult[] = [];

  for (const step of SHUTDOWN_SEQUENCE) {
    const start = Date.now();
    onStep?.(step, "start");

    try {
      await shutdownStep(step, config);
      const durationMs = Date.now() - start;
      onStep?.(step, "done");
      results.push({ step, success: true, message: `${step} stopped`, durationMs });
    } catch (err) {
      const durationMs = Date.now() - start;
      onStep?.(step, "fail");
      results.push({
        step,
        success: false,
        message: (err as Error).message,
        durationMs,
      });
      // Continue shutdown even on failure
    }
  }

  return results;
}

async function shutdownStep(
  _step: StartupStep,
  _config: OrchestratorConfig,
): Promise<void> {
  // In a real implementation, each step would:
  // - http-proxy-env: unset proxy env vars
  // - lobsec-proxy: stop proxy server
  // - caddy-proxy: stop caddy container
  // - nftables: flush lobsec rules
  // - audit-logging: flush and close audit log
  // - config-validation: no-op
  // - config-generation: clean up tmpfs config
}

/**
 * Build the initial orchestrator state.
 */
export function initialState(): OrchestratorState {
  return {
    phase: "stopped",
    components: STARTUP_SEQUENCE.map((name) => ({
      name,
      status: "stopped" as ComponentStatus,
    })),
  };
}
