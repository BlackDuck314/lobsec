// ── Sovereign/Public Routing ────────────────────────────────────────────────
// Controls whether LLM requests go to local (sovereign) or cloud (public)
// inference backends. Per-session mode tracking with /sovereign and /public
// commands. Sovereign mode: sensitive data never leaves user infrastructure.

// ── Types ───────────────────────────────────────────────────────────────────

export type RoutingMode = "sovereign" | "public" | "auto";

export interface SovereignBackendConfig {
  name: string;
  url: string;
  model: string;
  available: boolean;
}

export interface RoutingDecision {
  mode: RoutingMode;
  backend: "sovereign" | "cloud";
  model: string;
  reason: string;
  traceId: string;
  timestamp: string;
}

export interface SessionState {
  sessionId: string;
  mode: RoutingMode;
  setAt: string;
  setBy: "user" | "default" | "channel" | "auto";
  requestCount: number;
}

export interface RouterConfig {
  /** Default mode for new sessions. */
  defaultMode: RoutingMode;
  /** Sovereign backends available. */
  sovereignBackends: SovereignBackendConfig[];
  /** Cloud models available. */
  cloudModels: string[];
  /** Per-channel default modes. */
  channelDefaults: Record<string, RoutingMode>;
  /** Callback for routing events. */
  onDecision?: (decision: RoutingDecision) => void;
}

export interface RoutingEvent {
  action: "mode-change" | "route" | "fallback";
  sessionId: string;
  detail: string;
  timestamp: string;
}

// ── Sovereign Router ────────────────────────────────────────────────────────

export class SovereignRouter {
  private config: RouterConfig;
  private sessions = new Map<string, SessionState>();
  private eventLog: RoutingEvent[] = [];

  constructor(config: RouterConfig) {
    this.config = config;
  }

  /** Set session mode via /sovereign or /public command. */
  setMode(sessionId: string, mode: RoutingMode, setBy: SessionState["setBy"] = "user"): void {
    const existing = this.sessions.get(sessionId);
    const state: SessionState = {
      sessionId,
      mode,
      setAt: new Date().toISOString(),
      setBy,
      requestCount: existing?.requestCount ?? 0,
    };
    this.sessions.set(sessionId, state);

    this.logEvent({
      action: "mode-change",
      sessionId,
      detail: `mode set to ${mode} by ${setBy}`,
      timestamp: state.setAt,
    });
  }

  /** Get current session mode. Creates session with default if not exists. */
  getMode(sessionId: string, channel?: string): RoutingMode {
    const existing = this.sessions.get(sessionId);
    if (existing) return existing.mode;

    // Check channel defaults
    if (channel && this.config.channelDefaults[channel]) {
      const mode = this.config.channelDefaults[channel]!;
      this.setMode(sessionId, mode, "channel");
      return mode;
    }

    // Use default
    this.setMode(sessionId, this.config.defaultMode, "default");
    return this.config.defaultMode;
  }

  /** Route a model request based on session mode. */
  route(
    sessionId: string,
    requestedModel: string,
    traceId: string,
    channel?: string,
  ): RoutingDecision {
    const mode = this.getMode(sessionId, channel);
    const state = this.sessions.get(sessionId)!;
    state.requestCount++;

    let decision: RoutingDecision;

    switch (mode) {
      case "sovereign":
        decision = this.routeSovereign(requestedModel, traceId);
        break;
      case "public":
        decision = this.routePublic(requestedModel, traceId);
        break;
      case "auto":
        decision = this.routeAuto(requestedModel, traceId);
        break;
    }

    this.config.onDecision?.(decision);
    this.logEvent({
      action: "route",
      sessionId,
      detail: `${decision.backend}:${decision.model} (${decision.reason})`,
      timestamp: decision.timestamp,
    });

    return decision;
  }

  /** Sovereign mode: always route to local backend. */
  private routeSovereign(requestedModel: string, traceId: string): RoutingDecision {
    const available = this.config.sovereignBackends.filter((b) => b.available);

    if (available.length > 0) {
      return {
        mode: "sovereign",
        backend: "sovereign",
        model: available[0]!.model,
        reason: "sovereign mode: local inference",
        traceId,
        timestamp: new Date().toISOString(),
      };
    }

    // No sovereign backend available — still deny cloud in sovereign mode
    return {
      mode: "sovereign",
      backend: "sovereign",
      model: "unavailable",
      reason: "sovereign mode: no local backend available, refusing cloud",
      traceId,
      timestamp: new Date().toISOString(),
    };
  }

  /** Public mode: route to cloud, fall back to sovereign. */
  private routePublic(requestedModel: string, traceId: string): RoutingDecision {
    if (this.config.cloudModels.includes(requestedModel)) {
      return {
        mode: "public",
        backend: "cloud",
        model: requestedModel,
        reason: "public mode: cloud inference",
        traceId,
        timestamp: new Date().toISOString(),
      };
    }

    // Requested model not available in cloud, check default
    if (this.config.cloudModels.length > 0) {
      return {
        mode: "public",
        backend: "cloud",
        model: this.config.cloudModels[0]!,
        reason: "public mode: default cloud model",
        traceId,
        timestamp: new Date().toISOString(),
      };
    }

    // No cloud models — fall back to sovereign
    const available = this.config.sovereignBackends.filter((b) => b.available);
    if (available.length > 0) {
      this.logEvent({
        action: "fallback",
        sessionId: "",
        detail: "cloud unavailable, falling back to sovereign",
        timestamp: new Date().toISOString(),
      });
      return {
        mode: "public",
        backend: "sovereign",
        model: available[0]!.model,
        reason: "public mode: cloud unavailable, sovereign fallback",
        traceId,
        timestamp: new Date().toISOString(),
      };
    }

    return {
      mode: "public",
      backend: "cloud",
      model: "unavailable",
      reason: "public mode: no backends available",
      traceId,
      timestamp: new Date().toISOString(),
    };
  }

  /** Auto mode: try cloud first, fall back to sovereign. */
  private routeAuto(requestedModel: string, traceId: string): RoutingDecision {
    // Try cloud first
    if (this.config.cloudModels.length > 0) {
      const model = this.config.cloudModels.includes(requestedModel)
        ? requestedModel
        : this.config.cloudModels[0]!;
      return {
        mode: "auto",
        backend: "cloud",
        model,
        reason: "auto mode: cloud available",
        traceId,
        timestamp: new Date().toISOString(),
      };
    }

    // Fall back to sovereign
    const available = this.config.sovereignBackends.filter((b) => b.available);
    if (available.length > 0) {
      return {
        mode: "auto",
        backend: "sovereign",
        model: available[0]!.model,
        reason: "auto mode: sovereign fallback",
        traceId,
        timestamp: new Date().toISOString(),
      };
    }

    return {
      mode: "auto",
      backend: "cloud",
      model: "unavailable",
      reason: "auto mode: no backends available",
      traceId,
      timestamp: new Date().toISOString(),
    };
  }

  /** Get session state. */
  getSession(sessionId: string): SessionState | undefined {
    return this.sessions.get(sessionId);
  }

  /** List all active sessions. */
  listSessions(): SessionState[] {
    return [...this.sessions.values()];
  }

  /** Get event log. */
  getEventLog(): RoutingEvent[] {
    return [...this.eventLog];
  }

  private logEvent(event: RoutingEvent): void {
    this.eventLog.push(event);
  }
}
