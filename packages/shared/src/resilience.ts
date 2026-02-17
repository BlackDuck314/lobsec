// ── Error Handling and Resilience ───────────────────────────────────────────
// Retry with exponential backoff, circuit breaker, and graceful degradation.
// Applied to HSM, network, container, and filesystem operations.

// ── Types ───────────────────────────────────────────────────────────────────

export interface RetryConfig {
  /** Maximum number of retries. */
  maxRetries: number;
  /** Base delay in ms (doubles each retry). */
  baseDelayMs: number;
  /** Maximum delay cap in ms. */
  maxDelayMs: number;
  /** Jitter factor (0-1, applied to delay). */
  jitterFactor: number;
  /** Which errors are retryable. */
  retryableErrors?: string[];
}

export interface RetryResult<T> {
  success: boolean;
  value?: T;
  attempts: number;
  totalDelayMs: number;
  lastError?: string;
}

export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitBreakerConfig {
  /** Number of failures before opening. */
  failureThreshold: number;
  /** Time to wait before trying again (ms). */
  resetTimeoutMs: number;
  /** Number of successes in half-open to close. */
  halfOpenSuccesses: number;
}

export interface CircuitBreakerStatus {
  state: CircuitState;
  failures: number;
  successes: number;
  lastFailure?: string;
  lastStateChange: string;
}

export type DegradationLevel = "normal" | "degraded" | "emergency";

export interface DegradationConfig {
  /** What to do when cloud API fails. */
  cloudFailure: "local-fallback" | "queue" | "reject";
  /** What to do when audit log write fails. */
  auditLogFailure: "buffer" | "stderr" | "reject";
  /** What to do when cert rotation fails. */
  certRotationFailure: "continue-current" | "alert-only" | "reject";
}

export interface ResilienceEvent {
  action: "retry" | "circuit-open" | "circuit-close" | "circuit-half-open" | "degradation";
  detail: string;
  timestamp: string;
}

// ── Default configs ────────────────────────────────────────────────────────

export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 100,
  maxDelayMs: 5000,
  jitterFactor: 0.2,
};

export const DEFAULT_CIRCUIT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  resetTimeoutMs: 30000,
  halfOpenSuccesses: 2,
};

export const DEFAULT_DEGRADATION_CONFIG: DegradationConfig = {
  cloudFailure: "local-fallback",
  auditLogFailure: "buffer",
  certRotationFailure: "continue-current",
};

// ── Retry with Exponential Backoff ─────────────────────────────────────────

/** Calculate delay for a given attempt with exponential backoff + jitter. */
export function calculateDelay(attempt: number, config: RetryConfig): number {
  const exponential = config.baseDelayMs * Math.pow(2, attempt);
  const capped = Math.min(exponential, config.maxDelayMs);
  const jitter = capped * config.jitterFactor * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(capped + jitter));
}

/** Deterministic delay (no jitter) for testing. */
export function calculateDelayDeterministic(attempt: number, config: RetryConfig): number {
  const exponential = config.baseDelayMs * Math.pow(2, attempt);
  return Math.min(exponential, config.maxDelayMs);
}

/** Check if an error is retryable. */
export function isRetryable(error: Error, config: RetryConfig): boolean {
  if (!config.retryableErrors || config.retryableErrors.length === 0) {
    // Default: retry all errors
    return true;
  }
  return config.retryableErrors.some((pattern) =>
    error.message.toLowerCase().includes(pattern.toLowerCase()),
  );
}

/**
 * Retry an async operation with exponential backoff.
 * Returns immediately on non-retryable errors.
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  config: RetryConfig = DEFAULT_RETRY_CONFIG,
): Promise<RetryResult<T>> {
  let lastError: string | undefined;
  let totalDelay = 0;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      const value = await fn();
      return { success: true, value, attempts: attempt + 1, totalDelayMs: totalDelay };
    } catch (err) {
      lastError = (err as Error).message;

      if (!isRetryable(err as Error, config)) {
        return { success: false, attempts: attempt + 1, totalDelayMs: totalDelay, lastError };
      }

      if (attempt < config.maxRetries) {
        const delay = calculateDelay(attempt, config);
        totalDelay += delay;
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  return {
    success: false,
    attempts: config.maxRetries + 1,
    totalDelayMs: totalDelay,
    lastError,
  };
}

// ── Circuit Breaker ────────────────────────────────────────────────────────

export class CircuitBreaker {
  private config: CircuitBreakerConfig;
  private state: CircuitState = "closed";
  private failureCount = 0;
  private halfOpenSuccessCount = 0;
  private lastFailureTime?: number;
  private lastStateChange = new Date().toISOString();
  private eventLog: ResilienceEvent[] = [];

  constructor(config: CircuitBreakerConfig = DEFAULT_CIRCUIT_CONFIG) {
    this.config = config;
  }

  /** Execute an operation through the circuit breaker. */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === "open") {
      // Check if reset timeout has passed
      if (this.lastFailureTime && Date.now() - this.lastFailureTime >= this.config.resetTimeoutMs) {
        this.transition("half-open");
      } else {
        throw new Error("Circuit breaker is open");
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  /** Record a success. */
  private onSuccess(): void {
    if (this.state === "half-open") {
      this.halfOpenSuccessCount++;
      if (this.halfOpenSuccessCount >= this.config.halfOpenSuccesses) {
        this.transition("closed");
      }
    } else {
      this.failureCount = 0;
    }
  }

  /** Record a failure. */
  private onFailure(): void {
    this.lastFailureTime = Date.now();
    this.failureCount++;

    if (this.state === "half-open") {
      this.transition("open");
    } else if (this.failureCount >= this.config.failureThreshold) {
      this.transition("open");
    }
  }

  /** Transition to a new state. */
  private transition(newState: CircuitState): void {
    const oldState = this.state;
    this.state = newState;
    this.lastStateChange = new Date().toISOString();

    if (newState === "closed") {
      this.failureCount = 0;
      this.halfOpenSuccessCount = 0;
    } else if (newState === "half-open") {
      this.halfOpenSuccessCount = 0;
    }

    const actionMap: Record<CircuitState, ResilienceEvent["action"]> = {
      open: "circuit-open",
      closed: "circuit-close",
      "half-open": "circuit-half-open",
    };

    this.eventLog.push({
      action: actionMap[newState],
      detail: `${oldState} → ${newState} (failures: ${this.failureCount})`,
      timestamp: this.lastStateChange,
    });
  }

  /** Get current status. */
  getStatus(): CircuitBreakerStatus {
    return {
      state: this.state,
      failures: this.failureCount,
      successes: this.halfOpenSuccessCount,
      lastFailure: this.lastFailureTime ? new Date(this.lastFailureTime).toISOString() : undefined,
      lastStateChange: this.lastStateChange,
    };
  }

  /** Get event log. */
  getEventLog(): ResilienceEvent[] {
    return [...this.eventLog];
  }

  /** Force reset (for testing). */
  reset(): void {
    this.state = "closed";
    this.failureCount = 0;
    this.halfOpenSuccessCount = 0;
    this.lastFailureTime = undefined;
  }
}

// ── Graceful Degradation ───────────────────────────────────────────────────

export class DegradationManager {
  private config: DegradationConfig;
  private level: DegradationLevel = "normal";
  private eventLog: ResilienceEvent[] = [];
  private auditBuffer: string[] = [];

  constructor(config: DegradationConfig = DEFAULT_DEGRADATION_CONFIG) {
    this.config = config;
  }

  /** Handle cloud API failure. */
  handleCloudFailure(reason: string): { action: string; detail: string } {
    this.setLevel("degraded");
    this.logEvent({
      action: "degradation",
      detail: `cloud failure: ${reason}, action: ${this.config.cloudFailure}`,
      timestamp: new Date().toISOString(),
    });

    return { action: this.config.cloudFailure, detail: reason };
  }

  /** Handle audit log write failure. */
  handleAuditLogFailure(entry: string, reason: string): { action: string; buffered: boolean } {
    this.logEvent({
      action: "degradation",
      detail: `audit log failure: ${reason}, action: ${this.config.auditLogFailure}`,
      timestamp: new Date().toISOString(),
    });

    if (this.config.auditLogFailure === "buffer") {
      this.auditBuffer.push(entry);
      return { action: "buffer", buffered: true };
    }

    if (this.config.auditLogFailure === "stderr") {
      return { action: "stderr", buffered: false };
    }

    return { action: "reject", buffered: false };
  }

  /** Handle cert rotation failure. */
  handleCertRotationFailure(reason: string): { action: string; detail: string } {
    this.logEvent({
      action: "degradation",
      detail: `cert rotation failure: ${reason}, action: ${this.config.certRotationFailure}`,
      timestamp: new Date().toISOString(),
    });

    return { action: this.config.certRotationFailure, detail: reason };
  }

  /** Get buffered audit entries. */
  getAuditBuffer(): string[] {
    return [...this.auditBuffer];
  }

  /** Flush audit buffer (after recovery). */
  flushAuditBuffer(): string[] {
    const entries = [...this.auditBuffer];
    this.auditBuffer = [];
    return entries;
  }

  /** Set degradation level. */
  setLevel(level: DegradationLevel): void {
    this.level = level;
  }

  /** Get current degradation level. */
  getLevel(): DegradationLevel {
    return this.level;
  }

  /** Get event log. */
  getEventLog(): ResilienceEvent[] {
    return [...this.eventLog];
  }

  private logEvent(event: ResilienceEvent): void {
    this.eventLog.push(event);
  }
}
