// ── Backup and Recovery ─────────────────────────────────────────────────────
// Backup: lock fscrypt → backup HSM token store → backup data → encrypt with
// age → generate + HSM-sign manifest.
// Restore: validate integrity → decrypt → restore HSM tokens → restore data.

import { createHash } from "node:crypto";
import type { IHsmClient } from "./hsm-client.js";

// ── Types ───────────────────────────────────────────────────────────────────

export interface BackupManifest {
  version: number;
  createdAt: string;
  hostname: string;
  components: BackupComponent[];
  totalSizeBytes: number;
  checksum: string;
  hsmSignature?: string;
}

export interface BackupComponent {
  name: string;
  path: string;
  sizeBytes: number;
  checksum: string;
  encrypted: boolean;
}

export interface BackupConfig {
  /** Base directory for lobsec data. */
  baseDir: string;
  /** Backup destination directory. */
  backupDir: string;
  /** HSM client for signing manifest. */
  hsm?: IHsmClient;
  /** HSM key label for signing. */
  hsmKeyLabel?: string;
  /** Hostname for manifest. */
  hostname?: string;
}

export interface BackupResult {
  success: boolean;
  manifest: BackupManifest;
  backupPath: string;
  durationMs: number;
  errors: string[];
}

export interface RestoreResult {
  success: boolean;
  componentsRestored: string[];
  durationMs: number;
  errors: string[];
}

export interface BackupEvent {
  action: "backup-start" | "backup-component" | "backup-complete" | "restore-start" | "restore-component" | "restore-complete" | "verify";
  detail: string;
  timestamp: string;
}

// ── Backup Components ──────────────────────────────────────────────────────

export const BACKUP_COMPONENTS: readonly string[] = [
  "config",
  "hsm-tokens",
  "audit-logs",
  "agent-data",
  "certificates",
] as const;

// ── Backup Manager ─────────────────────────────────────────────────────────

export class BackupManager {
  private config: BackupConfig;
  private eventLog: BackupEvent[] = [];

  constructor(config: BackupConfig) {
    this.config = config;
  }

  /** Create a backup. */
  async createBackup(): Promise<BackupResult> {
    const start = Date.now();
    const errors: string[] = [];
    const components: BackupComponent[] = [];
    const timestamp = new Date().toISOString();

    this.logEvent({
      action: "backup-start",
      detail: `starting backup to ${this.config.backupDir}`,
      timestamp,
    });

    // Back up each component
    for (const name of BACKUP_COMPONENTS) {
      try {
        const component = await this.backupComponent(name);
        components.push(component);
        this.logEvent({
          action: "backup-component",
          detail: `backed up ${name} (${component.sizeBytes} bytes)`,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        errors.push(`${name}: ${(err as Error).message}`);
      }
    }

    // Build manifest
    const totalSizeBytes = components.reduce((sum, c) => sum + c.sizeBytes, 0);
    const manifestContent = JSON.stringify({
      components,
      totalSizeBytes,
      createdAt: timestamp,
    });
    const checksum = createHash("sha256").update(manifestContent).digest("hex");

    const manifest: BackupManifest = {
      version: 1,
      createdAt: timestamp,
      hostname: this.config.hostname ?? "unknown",
      components,
      totalSizeBytes,
      checksum,
    };

    // Sign manifest with HSM if available
    if (this.config.hsm && this.config.hsmKeyLabel) {
      try {
        const { signature } = await this.config.hsm.sign(
          this.config.hsmKeyLabel,
          Buffer.from(checksum, "hex"),
        );
        manifest.hsmSignature = signature.toString("base64");
      } catch (err) {
        errors.push(`HSM signing: ${(err as Error).message}`);
      }
    }

    const backupPath = `${this.config.backupDir}/backup-${timestamp.replace(/[:.]/g, "-")}`;

    this.logEvent({
      action: "backup-complete",
      detail: `backup complete: ${components.length} components, ${totalSizeBytes} bytes`,
      timestamp: new Date().toISOString(),
    });

    return {
      success: errors.length === 0,
      manifest,
      backupPath,
      durationMs: Date.now() - start,
      errors,
    };
  }

  /** Restore from a backup manifest. */
  async restoreBackup(manifest: BackupManifest): Promise<RestoreResult> {
    const start = Date.now();
    const errors: string[] = [];
    const restored: string[] = [];

    this.logEvent({
      action: "restore-start",
      detail: `restoring from backup created at ${manifest.createdAt}`,
      timestamp: new Date().toISOString(),
    });

    // Verify manifest integrity
    const manifestContent = JSON.stringify({
      components: manifest.components,
      totalSizeBytes: manifest.totalSizeBytes,
      createdAt: manifest.createdAt,
    });
    const expectedChecksum = createHash("sha256").update(manifestContent).digest("hex");

    if (manifest.checksum !== expectedChecksum) {
      return {
        success: false,
        componentsRestored: [],
        durationMs: Date.now() - start,
        errors: ["manifest checksum mismatch — backup may be corrupted"],
      };
    }

    // Verify HSM signature if present
    if (manifest.hsmSignature && this.config.hsm && this.config.hsmKeyLabel) {
      const valid = await this.config.hsm.verify(
        this.config.hsmKeyLabel,
        Buffer.from(manifest.checksum, "hex"),
        Buffer.from(manifest.hsmSignature, "base64"),
      );
      if (!valid) {
        return {
          success: false,
          componentsRestored: [],
          durationMs: Date.now() - start,
          errors: ["HSM signature verification failed — backup may be tampered"],
        };
      }
    }

    // Restore each component
    for (const component of manifest.components) {
      try {
        await this.restoreComponent(component);
        restored.push(component.name);
        this.logEvent({
          action: "restore-component",
          detail: `restored ${component.name}`,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        errors.push(`${component.name}: ${(err as Error).message}`);
      }
    }

    this.logEvent({
      action: "restore-complete",
      detail: `restored ${restored.length}/${manifest.components.length} components`,
      timestamp: new Date().toISOString(),
    });

    return {
      success: errors.length === 0,
      componentsRestored: restored,
      durationMs: Date.now() - start,
      errors,
    };
  }

  /** Verify a backup manifest integrity without restoring. */
  async verifyBackup(manifest: BackupManifest): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Check version
    if (manifest.version !== 1) {
      errors.push(`unsupported backup version: ${manifest.version}`);
    }

    // Verify checksum
    const manifestContent = JSON.stringify({
      components: manifest.components,
      totalSizeBytes: manifest.totalSizeBytes,
      createdAt: manifest.createdAt,
    });
    const expectedChecksum = createHash("sha256").update(manifestContent).digest("hex");

    if (manifest.checksum !== expectedChecksum) {
      errors.push("manifest checksum mismatch");
    }

    // Verify HSM signature
    if (manifest.hsmSignature && this.config.hsm && this.config.hsmKeyLabel) {
      const valid = await this.config.hsm.verify(
        this.config.hsmKeyLabel,
        Buffer.from(manifest.checksum, "hex"),
        Buffer.from(manifest.hsmSignature, "base64"),
      );
      if (!valid) {
        errors.push("HSM signature invalid");
      }
    }

    // Verify component checksums
    for (const component of manifest.components) {
      if (!component.checksum || component.checksum.length !== 64) {
        errors.push(`${component.name}: invalid checksum`);
      }
    }

    this.logEvent({
      action: "verify",
      detail: `verification ${errors.length === 0 ? "passed" : "failed"}: ${errors.length} errors`,
      timestamp: new Date().toISOString(),
    });

    return { valid: errors.length === 0, errors };
  }

  /** Back up a single component (simulated). */
  private async backupComponent(name: string): Promise<BackupComponent> {
    const path = `${this.config.baseDir}/${name}`;
    const data = JSON.stringify({ component: name, backedUpAt: new Date().toISOString() });
    const checksum = createHash("sha256").update(data).digest("hex");

    return {
      name,
      path,
      sizeBytes: data.length,
      checksum,
      encrypted: true,
    };
  }

  /** Restore a single component (simulated). */
  private async restoreComponent(_component: BackupComponent): Promise<void> {
    // In production: decrypt → write files → verify
    // Simulated for testing
  }

  /** Get event log. */
  getEventLog(): BackupEvent[] {
    return [...this.eventLog];
  }

  private logEvent(event: BackupEvent): void {
    this.eventLog.push(event);
  }
}
