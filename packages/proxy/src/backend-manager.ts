// ── Backend Manager ─────────────────────────────────────────────────────────
// Manages sovereign (local) and cloud LLM backends with health checks,
// failover, budget-aware routing, and per-backend API key injection.
// Integrates with SovereignRouter (from @lobsec/plugin) for session mode.

import type { CredentialStore } from "./credential-store.js";

// ── Types ───────────────────────────────────────────────────────────────────

export type BackendType = "sovereign" | "cloud";

export interface BackendConfig {
  /** Unique backend name (e.g., "jetson-orin", "remote-gpu", "anthropic"). */
  name: string;
  /** Backend type. */
  type: BackendType;
  /** Base URL for API requests. */
  url: string;
  /** Default model for this backend. */
  model: string;
  /** Credential label in CredentialStore for API key. */
  credentialLabel?: string;
  /** Whether this backend requires TLS cert pinning. */
  tlsCertPin?: boolean;
  /** Whether this backend goes through WireGuard tunnel. */
  wireguard?: boolean;
  /** Priority (lower = preferred). */
  priority: number;
  /** Maximum requests per minute (rate limit). */
  maxRpm?: number;
}

export interface BackendHealth {
  name: string;
  healthy: boolean;
  lastCheck: string;
  lastLatencyMs: number;
  consecutiveFailures: number;
  totalRequests: number;
  totalFailures: number;
}

export interface BudgetConfig {
  /** Monthly budget in USD. */
  monthlyBudgetUsd: number;
  /** Current month spend in USD. */
  currentSpendUsd: number;
  /** Warning threshold (0-1, e.g., 0.8 = 80%). */
  warnThreshold: number;
  /** Downgrade threshold (0-1, e.g., 0.9 = 90%). Switch to cheaper models. */
  downgradeThreshold: number;
  /** Hard limit threshold (0-1, e.g., 1.0 = 100%). Block cloud requests. */
  hardLimitThreshold: number;
}

export type BudgetAction = "allow" | "warn" | "downgrade" | "block";

export interface BudgetCheckResult {
  action: BudgetAction;
  spendRatio: number;
  reason: string;
}

export interface RoutingRequest {
  sessionId: string;
  requestedModel: string;
  traceId: string;
  mode: "sovereign" | "public" | "auto";
  estimatedCostUsd?: number;
}

export interface RoutingResult {
  backend: BackendConfig;
  model: string;
  targetUrl: string;
  authorization?: string;
  budgetAction: BudgetAction;
  reason: string;
  traceId: string;
  timestamp: string;
}

export interface BackendManagerConfig {
  backends: BackendConfig[];
  budget?: BudgetConfig;
  healthCheckIntervalMs?: number;
  /** Callback for routing events. */
  onRoute?: (result: RoutingResult) => void;
}

export interface BackendEvent {
  action: "route" | "health-check" | "failover" | "budget-warn" | "budget-block";
  backend: string;
  detail: string;
  timestamp: string;
}

// ── Backend Manager ────────────────────────────────────────────────────────

export class BackendManager {
  private config: BackendManagerConfig;
  private health = new Map<string, BackendHealth>();
  private eventLog: BackendEvent[] = [];

  constructor(config: BackendManagerConfig) {
    this.config = config;

    // Initialize health state for all backends
    for (const backend of config.backends) {
      this.health.set(backend.name, {
        name: backend.name,
        healthy: true,
        lastCheck: new Date().toISOString(),
        lastLatencyMs: 0,
        consecutiveFailures: 0,
        totalRequests: 0,
        totalFailures: 0,
      });
    }
  }

  /** Route a request based on session mode, backend health, and budget. */
  route(
    request: RoutingRequest,
    credentials: CredentialStore,
  ): RoutingResult {
    const { mode, requestedModel, traceId } = request;

    // Check budget for cloud requests
    const budgetCheck = this.checkBudget(request.estimatedCostUsd);

    switch (mode) {
      case "sovereign":
        return this.routeSovereign(requestedModel, traceId, credentials);
      case "public":
        return this.routePublic(requestedModel, traceId, credentials, budgetCheck);
      case "auto":
        return this.routeAuto(requestedModel, traceId, credentials, budgetCheck);
    }
  }

  /** Sovereign mode: route to local backends only. Never cloud. */
  private routeSovereign(
    requestedModel: string,
    traceId: string,
    credentials: CredentialStore,
  ): RoutingResult {
    const sovereignBackends = this.getHealthyBackends("sovereign");

    if (sovereignBackends.length > 0) {
      const backend = sovereignBackends[0]!;
      return this.buildResult(backend, requestedModel, traceId, credentials, "allow",
        "sovereign mode: local inference");
    }

    // No healthy sovereign backends — still refuse cloud
    const allSovereign = this.config.backends.filter((b) => b.type === "sovereign");
    if (allSovereign.length > 0) {
      // Use first sovereign backend even if unhealthy (for the config)
      return {
        backend: allSovereign[0]!,
        model: "unavailable",
        targetUrl: allSovereign[0]!.url,
        budgetAction: "allow",
        reason: "sovereign mode: no healthy sovereign backends, refusing cloud",
        traceId,
        timestamp: new Date().toISOString(),
      };
    }

    // No sovereign backends configured at all
    return {
      backend: { name: "none", type: "sovereign", url: "", model: "unavailable", priority: 999 },
      model: "unavailable",
      targetUrl: "",
      budgetAction: "allow",
      reason: "sovereign mode: no sovereign backends configured, refusing cloud",
      traceId,
      timestamp: new Date().toISOString(),
    };
  }

  /** Public mode: cloud first, sovereign fallback. Budget-aware. */
  private routePublic(
    requestedModel: string,
    traceId: string,
    credentials: CredentialStore,
    budgetCheck: BudgetCheckResult,
  ): RoutingResult {
    // Budget hard limit: block cloud entirely
    if (budgetCheck.action === "block") {
      this.logEvent({
        action: "budget-block",
        backend: "cloud",
        detail: `budget blocked at ${(budgetCheck.spendRatio * 100).toFixed(0)}%`,
        timestamp: new Date().toISOString(),
      });
      // Fall through to sovereign
      return this.fallbackToSovereign(requestedModel, traceId, credentials, budgetCheck,
        "public mode: cloud blocked by budget, sovereign fallback");
    }

    // Budget downgrade: use cheaper cloud model
    if (budgetCheck.action === "downgrade") {
      this.logEvent({
        action: "budget-warn",
        backend: "cloud",
        detail: `budget downgrade at ${(budgetCheck.spendRatio * 100).toFixed(0)}%`,
        timestamp: new Date().toISOString(),
      });
    }

    // Try cloud backends
    const cloudBackends = this.getHealthyBackends("cloud");
    if (cloudBackends.length > 0) {
      const backend = cloudBackends[0]!;
      const result = this.buildResult(backend, requestedModel, traceId, credentials,
        budgetCheck.action, `public mode: cloud inference`);
      this.config.onRoute?.(result);
      this.logEvent({
        action: "route",
        backend: backend.name,
        detail: `public → ${backend.name}:${result.model}`,
        timestamp: result.timestamp,
      });
      return result;
    }

    // Cloud unavailable — fall back to sovereign
    return this.fallbackToSovereign(requestedModel, traceId, credentials, budgetCheck,
      "public mode: cloud unavailable, sovereign fallback");
  }

  /** Auto mode: cloud preferred (if budget allows), sovereign fallback. */
  private routeAuto(
    requestedModel: string,
    traceId: string,
    credentials: CredentialStore,
    budgetCheck: BudgetCheckResult,
  ): RoutingResult {
    // If budget blocks cloud, go straight to sovereign
    if (budgetCheck.action === "block") {
      return this.fallbackToSovereign(requestedModel, traceId, credentials, budgetCheck,
        "auto mode: cloud blocked by budget, sovereign fallback");
    }

    // Try cloud first
    const cloudBackends = this.getHealthyBackends("cloud");
    if (cloudBackends.length > 0) {
      const backend = cloudBackends[0]!;
      const result = this.buildResult(backend, requestedModel, traceId, credentials,
        budgetCheck.action, `auto mode: cloud available`);
      this.config.onRoute?.(result);
      this.logEvent({
        action: "route",
        backend: backend.name,
        detail: `auto → ${backend.name}:${result.model}`,
        timestamp: result.timestamp,
      });
      return result;
    }

    // Fall back to sovereign
    return this.fallbackToSovereign(requestedModel, traceId, credentials, budgetCheck,
      "auto mode: cloud unavailable, sovereign fallback");
  }

  /** Fallback to sovereign backend. */
  private fallbackToSovereign(
    requestedModel: string,
    traceId: string,
    credentials: CredentialStore,
    budgetCheck: BudgetCheckResult,
    reason: string,
  ): RoutingResult {
    const sovereignBackends = this.getHealthyBackends("sovereign");

    if (sovereignBackends.length > 0) {
      const backend = sovereignBackends[0]!;
      const result = this.buildResult(backend, requestedModel, traceId, credentials,
        budgetCheck.action, reason);
      this.logEvent({
        action: "failover",
        backend: backend.name,
        detail: reason,
        timestamp: result.timestamp,
      });
      this.config.onRoute?.(result);
      return result;
    }

    // Nothing available
    return {
      backend: { name: "none", type: "sovereign", url: "", model: "unavailable", priority: 999 },
      model: "unavailable",
      targetUrl: "",
      budgetAction: budgetCheck.action,
      reason: `${reason} — no backends available`,
      traceId,
      timestamp: new Date().toISOString(),
    };
  }

  /** Build a RoutingResult with API key injection. */
  private buildResult(
    backend: BackendConfig,
    requestedModel: string,
    traceId: string,
    credentials: CredentialStore,
    budgetAction: BudgetAction,
    reason: string,
  ): RoutingResult {
    // Inject API key from credential store
    let authorization: string | undefined;
    if (backend.credentialLabel) {
      const apiKey = credentials.get(backend.credentialLabel);
      if (apiKey) {
        authorization = apiKey;
      }
    }

    // Use backend's default model for sovereign, requested model for cloud
    const model = backend.type === "sovereign" ? backend.model : requestedModel;

    return {
      backend,
      model,
      targetUrl: `${backend.url}`,
      authorization,
      budgetAction,
      reason,
      traceId,
      timestamp: new Date().toISOString(),
    };
  }

  /** Check budget constraints and return action. */
  checkBudget(estimatedCostUsd?: number): BudgetCheckResult {
    if (!this.config.budget) {
      return { action: "allow", spendRatio: 0, reason: "no budget configured" };
    }

    const { monthlyBudgetUsd, currentSpendUsd, warnThreshold, downgradeThreshold, hardLimitThreshold } = this.config.budget;

    if (monthlyBudgetUsd <= 0) {
      return { action: "allow", spendRatio: 0, reason: "budget is zero or negative" };
    }

    const projectedSpend = currentSpendUsd + (estimatedCostUsd ?? 0);
    const spendRatio = projectedSpend / monthlyBudgetUsd;

    if (spendRatio >= hardLimitThreshold) {
      return {
        action: "block",
        spendRatio,
        reason: `spend ${(spendRatio * 100).toFixed(0)}% >= hard limit ${(hardLimitThreshold * 100).toFixed(0)}%`,
      };
    }

    if (spendRatio >= downgradeThreshold) {
      return {
        action: "downgrade",
        spendRatio,
        reason: `spend ${(spendRatio * 100).toFixed(0)}% >= downgrade threshold ${(downgradeThreshold * 100).toFixed(0)}%`,
      };
    }

    if (spendRatio >= warnThreshold) {
      return {
        action: "warn",
        spendRatio,
        reason: `spend ${(spendRatio * 100).toFixed(0)}% >= warn threshold ${(warnThreshold * 100).toFixed(0)}%`,
      };
    }

    return {
      action: "allow",
      spendRatio,
      reason: `spend ${(spendRatio * 100).toFixed(0)}% within budget`,
    };
  }

  /** Report a health check result for a backend. */
  reportHealth(name: string, healthy: boolean, latencyMs: number): void {
    const health = this.health.get(name);
    if (!health) return;

    health.healthy = healthy;
    health.lastCheck = new Date().toISOString();
    health.lastLatencyMs = latencyMs;
    health.totalRequests++;

    if (!healthy) {
      health.consecutiveFailures++;
      health.totalFailures++;
    } else {
      health.consecutiveFailures = 0;
    }

    this.logEvent({
      action: "health-check",
      backend: name,
      detail: `${healthy ? "healthy" : "unhealthy"} (${latencyMs}ms, failures: ${health.consecutiveFailures})`,
      timestamp: health.lastCheck,
    });
  }

  /** Report a request result (success/failure). */
  reportRequestResult(name: string, success: boolean, latencyMs: number): void {
    this.reportHealth(name, success, latencyMs);
  }

  /** Get healthy backends of a given type, sorted by priority. */
  getHealthyBackends(type: BackendType): BackendConfig[] {
    return this.config.backends
      .filter((b) => b.type === type && this.isHealthy(b.name))
      .sort((a, b) => a.priority - b.priority);
  }

  /** Check if a backend is healthy (fewer than 3 consecutive failures). */
  isHealthy(name: string): boolean {
    const health = this.health.get(name);
    if (!health) return false;
    return health.consecutiveFailures < 3;
  }

  /** Get health status for a backend. */
  getHealth(name: string): BackendHealth | undefined {
    const h = this.health.get(name);
    return h ? { ...h } : undefined;
  }

  /** Get all backend health statuses. */
  getAllHealth(): BackendHealth[] {
    return [...this.health.values()].map((h) => ({ ...h }));
  }

  /** Get all configured backends. */
  getBackends(): BackendConfig[] {
    return [...this.config.backends];
  }

  /** Update budget spend. */
  updateSpend(additionalUsd: number): void {
    if (this.config.budget) {
      this.config.budget.currentSpendUsd += additionalUsd;
    }
  }

  /** Get event log. */
  getEventLog(): BackendEvent[] {
    return [...this.eventLog];
  }

  private logEvent(event: BackendEvent): void {
    this.eventLog.push(event);
  }
}
