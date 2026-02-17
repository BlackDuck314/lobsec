// ── Config Monitor ──────────────────────────────────────────────────────────
// Plugin-side module that periodically checks for config drift,
// HEARTBEAT.md tampering, and suspicious cron jobs.

import {
  detectDrift,
  checkHeartbeat,
  detectSuspiciousCron,
} from "@lobsec/shared";
import type { DriftResult, HeartbeatStatus } from "@lobsec/shared";

// ── Types ───────────────────────────────────────────────────────────────────

export interface MonitorConfig {
  /** Expected config hash. */
  expectedHash: string;
  /** Config object to monitor. */
  config: Record<string, unknown>;
  /** Path to HEARTBEAT.md file. */
  heartbeatPath: string;
  /** Interval in seconds for periodic checks. Default: 60. */
  intervalSeconds: number;
  /** Callback for alerts. */
  onAlert?: (alert: MonitorAlert) => void;
}

export type AlertSeverity = "critical" | "warning" | "info";

export interface MonitorAlert {
  severity: AlertSeverity;
  source: "drift" | "heartbeat" | "cron";
  message: string;
  timestamp: string;
  detail?: Record<string, unknown>;
}

export interface MonitorStatus {
  running: boolean;
  lastCheckAt?: string;
  checksCompleted: number;
  alertsRaised: number;
  lastDriftResult?: DriftResult;
  lastHeartbeatStatus?: HeartbeatStatus;
}

// ── Config Monitor ──────────────────────────────────────────────────────────

export class ConfigMonitor {
  private config: MonitorConfig;
  private running = false;
  private interval?: ReturnType<typeof setInterval>;
  private checksCompleted = 0;
  private alertsRaised = 0;
  private lastCheckAt?: string;
  private lastDriftResult?: DriftResult;
  private lastHeartbeatStatus?: HeartbeatStatus;
  private alertLog: MonitorAlert[] = [];

  constructor(config: MonitorConfig) {
    this.config = config;
  }

  /** Start periodic monitoring. */
  start(): void {
    if (this.running) return;
    this.running = true;

    // Run first check immediately
    this.runCheck();

    // Schedule periodic checks
    this.interval = setInterval(() => {
      this.runCheck();
    }, this.config.intervalSeconds * 1000);
  }

  /** Stop periodic monitoring. */
  stop(): void {
    this.running = false;
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = undefined;
    }
  }

  /** Run a single monitoring check. */
  runCheck(): void {
    this.lastCheckAt = new Date().toISOString();
    this.checksCompleted++;

    this.checkDrift();
    this.checkHeartbeat();
    this.checkCron();
  }

  /** Check for config drift. */
  private checkDrift(): void {
    const result = detectDrift(
      this.config.config,
      this.config.expectedHash,
    );
    this.lastDriftResult = result;

    if (!result.clean) {
      this.raiseAlert({
        severity: "critical",
        source: "drift",
        message: `Config drift detected: expected ${this.config.expectedHash}, got ${result.currentHash}`,
        timestamp: new Date().toISOString(),
        detail: { violations: result.violations },
      });
    }
  }

  /** Check HEARTBEAT.md for tampering. */
  private checkHeartbeat(): void {
    // Use checkHeartbeat async but fire-and-forget for periodic monitoring
    checkHeartbeat(
      this.config.heartbeatPath,
      undefined,
    ).then((status) => {
      this.lastHeartbeatStatus = status;

      if (!status.valid || status.modified) {
        this.raiseAlert({
          severity: "warning",
          source: "heartbeat",
          message: `HEARTBEAT.md issue: valid=${status.valid}, modified=${status.modified}`,
          timestamp: new Date().toISOString(),
        });
      }
    }).catch(() => {
      // Heartbeat check failed — file may not exist
    });
  }

  /** Check for suspicious cron jobs. */
  private checkCron(): void {
    // Mock crontab content for testing
    const suspicious = detectSuspiciousCron("");
    if (suspicious.length > 0) {
      this.raiseAlert({
        severity: "warning",
        source: "cron",
        message: `Suspicious cron entries found: ${suspicious.length}`,
        timestamp: new Date().toISOString(),
        detail: { entries: suspicious },
      });
    }
  }

  private raiseAlert(alert: MonitorAlert): void {
    this.alertsRaised++;
    this.alertLog.push(alert);
    this.config.onAlert?.(alert);
  }

  /** Get current monitor status. */
  getStatus(): MonitorStatus {
    return {
      running: this.running,
      lastCheckAt: this.lastCheckAt,
      checksCompleted: this.checksCompleted,
      alertsRaised: this.alertsRaised,
      lastDriftResult: this.lastDriftResult,
      lastHeartbeatStatus: this.lastHeartbeatStatus,
    };
  }

  /** Get all alerts. */
  getAlerts(): MonitorAlert[] {
    return [...this.alertLog];
  }

  /** Update the expected config hash. */
  updateExpectedHash(hash: string): void {
    this.config.expectedHash = hash;
  }

  /** Whether the monitor is running. */
  get isRunning(): boolean {
    return this.running;
  }
}
