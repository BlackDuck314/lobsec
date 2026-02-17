// ── System Monitor & Alerting ───────────────────────────────────────────────
// Tracks component health, performance metrics, and security events.
// Generates alerts for: config drift, cert expiry, failed webhooks,
// blocked egress, denied tool calls, HSM errors.

// ── Types ───────────────────────────────────────────────────────────────────

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export type AlertCategory =
  | "config-drift"
  | "cert-expiry"
  | "webhook-failure"
  | "egress-blocked"
  | "tool-denied"
  | "hsm-error"
  | "budget-warning"
  | "health-degraded";

export interface Alert {
  id: string;
  severity: AlertSeverity;
  category: AlertCategory;
  title: string;
  detail: string;
  timestamp: string;
  acknowledged: boolean;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
}

export interface HealthStatus {
  component: string;
  healthy: boolean;
  lastCheck: string;
  detail?: string;
}

export interface MetricPoint {
  name: string;
  value: number;
  unit: string;
  timestamp: string;
}

export interface NotificationConfig {
  /** Webhook URL for alert delivery. */
  webhookUrl?: string;
  /** Minimum severity to notify. */
  minSeverity: AlertSeverity;
  /** Channel type (for formatting). */
  channel: "slack" | "discord" | "email" | "generic";
}

export interface MonitorConfig {
  /** Cert expiry warning thresholds in days. */
  certExpiryWarnDays: number[];
  /** Notification endpoints. */
  notifications: NotificationConfig[];
  /** Alert retention count. */
  maxAlerts: number;
}

export interface MonitorEvent {
  action: "alert-created" | "alert-acknowledged" | "health-check" | "metric-recorded";
  detail: string;
  timestamp: string;
}

// ── Severity ordering ──────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<AlertSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function severityMeetsThreshold(severity: AlertSeverity, threshold: AlertSeverity): boolean {
  return SEVERITY_ORDER[severity] <= SEVERITY_ORDER[threshold];
}

// ── System Monitor ─────────────────────────────────────────────────────────

export class SystemMonitor {
  private config: MonitorConfig;
  private alerts: Alert[] = [];
  private health = new Map<string, HealthStatus>();
  private metrics: MetricPoint[] = [];
  private eventLog: MonitorEvent[] = [];
  private alertCounter = 0;

  constructor(config: MonitorConfig) {
    this.config = config;
  }

  /** Create an alert. */
  createAlert(
    severity: AlertSeverity,
    category: AlertCategory,
    title: string,
    detail: string,
  ): Alert {
    const alert: Alert = {
      id: `alert-${++this.alertCounter}`,
      severity,
      category,
      title,
      detail,
      timestamp: new Date().toISOString(),
      acknowledged: false,
    };

    this.alerts.push(alert);

    // Trim alerts if over limit
    if (this.alerts.length > this.config.maxAlerts) {
      this.alerts = this.alerts.slice(-this.config.maxAlerts);
    }

    this.logEvent({
      action: "alert-created",
      detail: `[${severity}] ${category}: ${title}`,
      timestamp: alert.timestamp,
    });

    return alert;
  }

  /** Acknowledge an alert. */
  acknowledgeAlert(alertId: string, by: string): boolean {
    const alert = this.alerts.find((a) => a.id === alertId);
    if (!alert) return false;

    alert.acknowledged = true;
    alert.acknowledgedAt = new Date().toISOString();
    alert.acknowledgedBy = by;

    this.logEvent({
      action: "alert-acknowledged",
      detail: `${alertId} acknowledged by ${by}`,
      timestamp: alert.acknowledgedAt,
    });

    return true;
  }

  /** Check certificate expiry and create alerts. */
  checkCertExpiry(certName: string, expiresAt: Date): Alert[] {
    const now = new Date();
    const daysUntilExpiry = Math.floor((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    const alerts: Alert[] = [];

    for (const threshold of this.config.certExpiryWarnDays) {
      if (daysUntilExpiry <= threshold) {
        const severity: AlertSeverity =
          daysUntilExpiry <= 1 ? "critical" :
          daysUntilExpiry <= 7 ? "high" :
          daysUntilExpiry <= 14 ? "medium" : "low";

        alerts.push(this.createAlert(
          severity,
          "cert-expiry",
          `Certificate ${certName} expires in ${daysUntilExpiry} days`,
          `Certificate ${certName} expires at ${expiresAt.toISOString()}. ${daysUntilExpiry} days remaining.`,
        ));
        break; // Only one alert per cert check
      }
    }

    return alerts;
  }

  /** Report config drift and create alert. */
  reportConfigDrift(violations: string[]): Alert {
    return this.createAlert(
      "critical",
      "config-drift",
      `Configuration drift detected: ${violations.length} violations`,
      violations.join("; "),
    );
  }

  /** Report webhook verification failure. */
  reportWebhookFailure(channel: string, reason: string): Alert {
    return this.createAlert(
      "high",
      "webhook-failure",
      `Webhook verification failed: ${channel}`,
      reason,
    );
  }

  /** Report blocked egress. */
  reportEgressBlocked(destination: string, reason: string): Alert {
    return this.createAlert(
      "medium",
      "egress-blocked",
      `Egress blocked: ${destination}`,
      reason,
    );
  }

  /** Report denied tool call. */
  reportToolDenied(tool: string, reason: string): Alert {
    return this.createAlert(
      "high",
      "tool-denied",
      `Tool call denied: ${tool}`,
      reason,
    );
  }

  /** Report HSM error. */
  reportHsmError(operation: string, error: string): Alert {
    return this.createAlert(
      "critical",
      "hsm-error",
      `HSM error: ${operation}`,
      error,
    );
  }

  /** Report budget warning. */
  reportBudgetWarning(spendRatio: number, action: string): Alert {
    const severity: AlertSeverity =
      action === "block" ? "critical" :
      action === "downgrade" ? "high" : "medium";

    return this.createAlert(
      severity,
      "budget-warning",
      `Budget ${action}: ${(spendRatio * 100).toFixed(0)}% spent`,
      `Monthly budget usage at ${(spendRatio * 100).toFixed(1)}%. Action: ${action}`,
    );
  }

  /** Update component health. */
  updateHealth(component: string, healthy: boolean, detail?: string): void {
    const status: HealthStatus = {
      component,
      healthy,
      lastCheck: new Date().toISOString(),
      detail,
    };
    this.health.set(component, status);

    if (!healthy) {
      this.createAlert(
        "high",
        "health-degraded",
        `Component unhealthy: ${component}`,
        detail ?? "No detail",
      );
    }

    this.logEvent({
      action: "health-check",
      detail: `${component}: ${healthy ? "healthy" : "unhealthy"}`,
      timestamp: status.lastCheck,
    });
  }

  /** Record a metric. */
  recordMetric(name: string, value: number, unit: string): void {
    this.metrics.push({
      name,
      value,
      unit,
      timestamp: new Date().toISOString(),
    });

    this.logEvent({
      action: "metric-recorded",
      detail: `${name}: ${value} ${unit}`,
      timestamp: new Date().toISOString(),
    });
  }

  /** Get alerts, optionally filtered. */
  getAlerts(options?: {
    severity?: AlertSeverity;
    category?: AlertCategory;
    unacknowledgedOnly?: boolean;
  }): Alert[] {
    let result = [...this.alerts];

    if (options?.severity) {
      result = result.filter((a) => severityMeetsThreshold(a.severity, options.severity!));
    }
    if (options?.category) {
      result = result.filter((a) => a.category === options.category);
    }
    if (options?.unacknowledgedOnly) {
      result = result.filter((a) => !a.acknowledged);
    }

    return result;
  }

  /** Get all component health statuses. */
  getHealth(): HealthStatus[] {
    return [...this.health.values()];
  }

  /** Get recent metrics. */
  getMetrics(name?: string, limit = 100): MetricPoint[] {
    const filtered = name ? this.metrics.filter((m) => m.name === name) : this.metrics;
    return filtered.slice(-limit);
  }

  /** Get notification configs that should receive an alert. */
  getNotificationTargets(severity: AlertSeverity): NotificationConfig[] {
    return this.config.notifications.filter(
      (n) => severityMeetsThreshold(severity, n.minSeverity),
    );
  }

  /** Get event log. */
  getEventLog(): MonitorEvent[] {
    return [...this.eventLog];
  }

  private logEvent(event: MonitorEvent): void {
    this.eventLog.push(event);
  }
}
