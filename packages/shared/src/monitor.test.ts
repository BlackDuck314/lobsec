import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  SystemMonitor,
  severityMeetsThreshold,
} from "./monitor.js";
import type { MonitorConfig } from "./monitor.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<MonitorConfig> = {}): MonitorConfig {
  return {
    certExpiryWarnDays: [30, 14, 7, 1],
    notifications: [
      { minSeverity: "high", channel: "slack", webhookUrl: "https://hooks.slack.com/test" },
      { minSeverity: "critical", channel: "email" },
    ],
    maxAlerts: 100,
    ...overrides,
  };
}

// ── Unit: Alert creation ────────────────────────────────────────────────────

describe("Alert creation", () => {
  it("creates alert with correct fields", () => {
    const monitor = new SystemMonitor(makeConfig());
    const alert = monitor.createAlert("high", "config-drift", "Test alert", "Detail");

    expect(alert.id).toMatch(/^alert-\d+$/);
    expect(alert.severity).toBe("high");
    expect(alert.category).toBe("config-drift");
    expect(alert.title).toBe("Test alert");
    expect(alert.acknowledged).toBe(false);
  });

  it("increments alert IDs", () => {
    const monitor = new SystemMonitor(makeConfig());
    const a1 = monitor.createAlert("info", "config-drift", "First", "");
    const a2 = monitor.createAlert("info", "config-drift", "Second", "");
    expect(a1.id).not.toBe(a2.id);
  });

  it("trims alerts when exceeding max", () => {
    const monitor = new SystemMonitor(makeConfig({ maxAlerts: 3 }));
    monitor.createAlert("info", "config-drift", "1", "");
    monitor.createAlert("info", "config-drift", "2", "");
    monitor.createAlert("info", "config-drift", "3", "");
    monitor.createAlert("info", "config-drift", "4", "");

    expect(monitor.getAlerts()).toHaveLength(3);
  });
});

// ── Unit: Alert acknowledgment ──────────────────────────────────────────────

describe("Alert acknowledgment", () => {
  it("acknowledges an alert", () => {
    const monitor = new SystemMonitor(makeConfig());
    const alert = monitor.createAlert("high", "hsm-error", "HSM down", "Detail");
    const acked = monitor.acknowledgeAlert(alert.id, "admin");

    expect(acked).toBe(true);
    const updated = monitor.getAlerts().find((a) => a.id === alert.id);
    expect(updated?.acknowledged).toBe(true);
    expect(updated?.acknowledgedBy).toBe("admin");
  });

  it("returns false for unknown alert", () => {
    const monitor = new SystemMonitor(makeConfig());
    expect(monitor.acknowledgeAlert("nonexistent", "admin")).toBe(false);
  });

  it("filters unacknowledged alerts", () => {
    const monitor = new SystemMonitor(makeConfig());
    const a1 = monitor.createAlert("high", "config-drift", "Alert 1", "");
    monitor.createAlert("high", "config-drift", "Alert 2", "");
    monitor.acknowledgeAlert(a1.id, "admin");

    const unacked = monitor.getAlerts({ unacknowledgedOnly: true });
    expect(unacked).toHaveLength(1);
    expect(unacked[0]!.title).toBe("Alert 2");
  });
});

// ── Unit: Certificate expiry alerting ───────────────────────────────────────

describe("Certificate expiry alerting", () => {
  it("alerts at 30-day threshold", () => {
    const monitor = new SystemMonitor(makeConfig());
    const expiry = new Date(Date.now() + 25 * 24 * 60 * 60 * 1000);
    const alerts = monitor.checkCertExpiry("proxy-cert", expiry);

    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.category).toBe("cert-expiry");
    expect(alerts[0]!.severity).toBe("low");
  });

  it("alerts critical at 1-day threshold", () => {
    const monitor = new SystemMonitor(makeConfig());
    const expiry = new Date(Date.now() + 12 * 60 * 60 * 1000); // 12 hours
    const alerts = monitor.checkCertExpiry("proxy-cert", expiry);

    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.severity).toBe("critical");
  });

  it("no alert when cert not near expiry", () => {
    const monitor = new SystemMonitor(makeConfig());
    const expiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
    const alerts = monitor.checkCertExpiry("proxy-cert", expiry);

    expect(alerts).toHaveLength(0);
  });

  it("assigns correct severity based on days remaining", () => {
    const monitor = new SystemMonitor(makeConfig());

    // 5 days → high
    const highAlert = monitor.checkCertExpiry("cert-1",
      new Date(Date.now() + 5 * 24 * 60 * 60 * 1000));
    expect(highAlert[0]!.severity).toBe("high");

    // 10 days → medium
    const medAlert = monitor.checkCertExpiry("cert-2",
      new Date(Date.now() + 10 * 24 * 60 * 60 * 1000));
    expect(medAlert[0]!.severity).toBe("medium");
  });
});

// ── Unit: Specific alert types ──────────────────────────────────────────────

describe("Specific alert types", () => {
  it("reports config drift", () => {
    const monitor = new SystemMonitor(makeConfig());
    const alert = monitor.reportConfigDrift(["field changed", "section missing"]);

    expect(alert.category).toBe("config-drift");
    expect(alert.severity).toBe("critical");
    expect(alert.detail).toContain("field changed");
  });

  it("reports webhook failure", () => {
    const monitor = new SystemMonitor(makeConfig());
    const alert = monitor.reportWebhookFailure("telegram", "invalid signature");

    expect(alert.category).toBe("webhook-failure");
    expect(alert.severity).toBe("high");
  });

  it("reports egress blocked", () => {
    const monitor = new SystemMonitor(makeConfig());
    const alert = monitor.reportEgressBlocked("169.254.169.254", "metadata endpoint");

    expect(alert.category).toBe("egress-blocked");
    expect(alert.severity).toBe("medium");
  });

  it("reports tool denied", () => {
    const monitor = new SystemMonitor(makeConfig());
    const alert = monitor.reportToolDenied("WebFetch", "path traversal");

    expect(alert.category).toBe("tool-denied");
    expect(alert.severity).toBe("high");
  });

  it("reports HSM error", () => {
    const monitor = new SystemMonitor(makeConfig());
    const alert = monitor.reportHsmError("sign", "slot not found");

    expect(alert.category).toBe("hsm-error");
    expect(alert.severity).toBe("critical");
  });

  it("reports budget warning with correct severity", () => {
    const monitor = new SystemMonitor(makeConfig());

    const warnAlert = monitor.reportBudgetWarning(0.85, "warn");
    expect(warnAlert.severity).toBe("medium");

    const downgradeAlert = monitor.reportBudgetWarning(0.92, "downgrade");
    expect(downgradeAlert.severity).toBe("high");

    const blockAlert = monitor.reportBudgetWarning(1.0, "block");
    expect(blockAlert.severity).toBe("critical");
  });
});

// ── Unit: Health monitoring ─────────────────────────────────────────────────

describe("Health monitoring", () => {
  it("tracks component health", () => {
    const monitor = new SystemMonitor(makeConfig());
    monitor.updateHealth("proxy", true, "responding normally");
    monitor.updateHealth("hsm", false, "connection timeout");

    const health = monitor.getHealth();
    expect(health).toHaveLength(2);

    const proxy = health.find((h) => h.component === "proxy");
    expect(proxy?.healthy).toBe(true);

    const hsm = health.find((h) => h.component === "hsm");
    expect(hsm?.healthy).toBe(false);
  });

  it("creates alert for unhealthy component", () => {
    const monitor = new SystemMonitor(makeConfig());
    monitor.updateHealth("hsm", false, "connection lost");

    const alerts = monitor.getAlerts({ category: "health-degraded" });
    expect(alerts).toHaveLength(1);
  });
});

// ── Unit: Metrics ───────────────────────────────────────────────────────────

describe("Metric recording", () => {
  it("records and retrieves metrics", () => {
    const monitor = new SystemMonitor(makeConfig());
    monitor.recordMetric("request_latency_ms", 45, "ms");
    monitor.recordMetric("request_latency_ms", 52, "ms");
    monitor.recordMetric("memory_mb", 256, "MB");

    const latency = monitor.getMetrics("request_latency_ms");
    expect(latency).toHaveLength(2);

    const all = monitor.getMetrics();
    expect(all).toHaveLength(3);
  });

  it("limits metric retrieval", () => {
    const monitor = new SystemMonitor(makeConfig());
    for (let i = 0; i < 10; i++) {
      monitor.recordMetric("cpu", i, "%");
    }

    const limited = monitor.getMetrics("cpu", 5);
    expect(limited).toHaveLength(5);
  });
});

// ── Unit: Notification routing ──────────────────────────────────────────────

describe("Notification routing", () => {
  it("routes critical alerts to all channels", () => {
    const monitor = new SystemMonitor(makeConfig());
    const targets = monitor.getNotificationTargets("critical");
    expect(targets).toHaveLength(2);
  });

  it("routes high alerts to high+ channels", () => {
    const monitor = new SystemMonitor(makeConfig());
    const targets = monitor.getNotificationTargets("high");
    expect(targets).toHaveLength(1); // Only slack (minSeverity: high)
  });

  it("routes info alerts to none", () => {
    const monitor = new SystemMonitor(makeConfig());
    const targets = monitor.getNotificationTargets("info");
    expect(targets).toHaveLength(0);
  });
});

// ── Unit: Severity comparison ───────────────────────────────────────────────

describe("Severity comparison", () => {
  it("critical meets all thresholds", () => {
    expect(severityMeetsThreshold("critical", "critical")).toBe(true);
    expect(severityMeetsThreshold("critical", "high")).toBe(true);
    expect(severityMeetsThreshold("critical", "info")).toBe(true);
  });

  it("info only meets info threshold", () => {
    expect(severityMeetsThreshold("info", "info")).toBe(true);
    expect(severityMeetsThreshold("info", "low")).toBe(false);
    expect(severityMeetsThreshold("info", "critical")).toBe(false);
  });
});

// ── Property 48: Certificate expiry alerting ────────────────────────────────

describe("Property 48: Certificate expiry alerting", () => {
  it("certs expiring within threshold always generate alerts", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 29 }),
        (daysRemaining) => {
          const monitor = new SystemMonitor(makeConfig());
          const expiry = new Date(Date.now() + daysRemaining * 24 * 60 * 60 * 1000);
          const alerts = monitor.checkCertExpiry("test-cert", expiry);

          expect(alerts.length).toBeGreaterThan(0);
          expect(alerts[0]!.category).toBe("cert-expiry");
        },
      ),
      { numRuns: 20 },
    );
  });

  it("certs with 31+ days remaining generate no alerts", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 31, max: 365 }),
        (daysRemaining) => {
          const monitor = new SystemMonitor(makeConfig());
          const expiry = new Date(Date.now() + daysRemaining * 24 * 60 * 60 * 1000);
          const alerts = monitor.checkCertExpiry("test-cert", expiry);

          expect(alerts).toHaveLength(0);
        },
      ),
      { numRuns: 15 },
    );
  });
});

// ── Property 49: Configuration drift alerting ───────────────────────────────

describe("Property 49: Configuration drift alerting", () => {
  it("drift reports always create critical alerts", () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1, maxLength: 30 }), { minLength: 1, maxLength: 5 }),
        (violations) => {
          const monitor = new SystemMonitor(makeConfig());
          const alert = monitor.reportConfigDrift(violations);

          expect(alert.severity).toBe("critical");
          expect(alert.category).toBe("config-drift");
        },
      ),
      { numRuns: 15 },
    );
  });
});

// ── Property 50: Failed webhook verification alerting ───────────────────────

describe("Property 50: Failed webhook verification alerting", () => {
  it("webhook failures always create high alerts", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("telegram", "slack", "discord", "twilio", "whatsapp"),
        fc.string({ minLength: 1, maxLength: 50 }),
        (channel, reason) => {
          const monitor = new SystemMonitor(makeConfig());
          const alert = monitor.reportWebhookFailure(channel, reason);

          expect(alert.severity).toBe("high");
          expect(alert.category).toBe("webhook-failure");
          expect(alert.title).toContain(channel);
        },
      ),
      { numRuns: 15 },
    );
  });
});
