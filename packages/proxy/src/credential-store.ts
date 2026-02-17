// ── In-Memory Credential Store ──────────────────────────────────────────────
// Credentials are loaded from environment variables at startup.
// Values are held in memory only, never written to disk.
// All access is logged (without revealing values).

import type { CredentialType } from "@lobsec/shared";

// ── Types ───────────────────────────────────────────────────────────────────

export interface CredentialEntry {
  type: CredentialType;
  label: string;
  loadedAt: string;
  accessCount: number;
  lastAccessedAt?: string;
}

export type CredentialAccessCallback = (
  label: string,
  type: CredentialType,
  operation: "retrieve" | "inject" | "destroy" | "rotate",
) => void;

// ── Store ───────────────────────────────────────────────────────────────────

export class CredentialStore {
  /** Metadata (no values). */
  private meta = new Map<string, CredentialEntry>();
  /** Actual values (never logged, never serialised). */
  private values = new Map<string, string>();
  /** Access callback for audit logging. */
  private onAccess?: CredentialAccessCallback;
  /** Whether the store has been destroyed. */
  private destroyed = false;

  constructor(onAccess?: CredentialAccessCallback) {
    this.onAccess = onAccess;
  }

  /** Load a credential from an environment variable. */
  loadFromEnv(label: string, type: CredentialType, envVar: string): boolean {
    if (this.destroyed) return false;

    const value = process.env[envVar];
    if (value === undefined || value === "") return false;

    this.values.set(label, value);
    this.meta.set(label, {
      type,
      label,
      loadedAt: new Date().toISOString(),
      accessCount: 0,
    });

    return true;
  }

  /** Load a credential from a direct value (for testing). */
  load(label: string, type: CredentialType, value: string): void {
    if (this.destroyed) return;

    this.values.set(label, value);
    this.meta.set(label, {
      type,
      label,
      loadedAt: new Date().toISOString(),
      accessCount: 0,
    });
  }

  /** Retrieve a credential value. Logs access (without value). */
  get(label: string): string | undefined {
    if (this.destroyed) return undefined;

    const entry = this.meta.get(label);
    if (!entry) return undefined;

    entry.accessCount++;
    entry.lastAccessedAt = new Date().toISOString();
    this.onAccess?.(label, entry.type, "retrieve");

    return this.values.get(label);
  }

  /** Check if a credential exists. */
  has(label: string): boolean {
    return !this.destroyed && this.values.has(label);
  }

  /** Get metadata for a credential (never the value). */
  getMeta(label: string): CredentialEntry | undefined {
    return this.meta.get(label);
  }

  /** List all credential labels and their metadata. */
  list(): CredentialEntry[] {
    return [...this.meta.values()];
  }

  /** Destroy a single credential. */
  delete(label: string): boolean {
    const entry = this.meta.get(label);
    if (!entry) return false;

    this.onAccess?.(label, entry.type, "destroy");

    // Overwrite value before deletion (defense in depth)
    const val = this.values.get(label);
    if (val) {
      // Overwrite with zeros of same length
      this.values.set(label, "\0".repeat(val.length));
    }
    this.values.delete(label);
    this.meta.delete(label);

    return true;
  }

  /** Destroy all credentials. Called on shutdown. */
  destroy(): void {
    for (const [label, entry] of this.meta) {
      this.onAccess?.(label, entry.type, "destroy");

      const val = this.values.get(label);
      if (val) {
        this.values.set(label, "\0".repeat(val.length));
      }
    }
    this.values.clear();
    this.meta.clear();
    this.destroyed = true;
  }

  /** Whether the store has been destroyed. */
  get isDestroyed(): boolean {
    return this.destroyed;
  }

  /** Number of credentials loaded. */
  get size(): number {
    return this.values.size;
  }
}
