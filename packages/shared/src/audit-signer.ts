// ── Audit Log HSM Signing ───────────────────────────────────────────────────
// Signs audit log entries with HSM-backed RSA key to ensure tamper-evidence.
// Each entry gets: SHA-256 hash of content → HSM C_Sign → base64 signature.
// Hash chain: each entry's prevHash links to previous entry's hash.

import { createHash } from "node:crypto";
import type { IHsmClient, HsmKeyAttributes } from "./hsm-client.js";
import type { AuditLogEntry } from "./types/log.js";

// ── Types ───────────────────────────────────────────────────────────────────

export interface AuditSignerConfig {
  /** HSM client for signing operations. */
  hsm: IHsmClient;
  /** Key label for the audit signing key. */
  keyLabel: string;
}

export interface SignedAuditEntry extends AuditLogEntry {
  /** SHA-256 hash of this entry (hex). */
  entryHash: string;
  /** HSM signature of entryHash (base64). */
  hsmSignature: string;
  /** Previous entry's hash (hex). Genesis entry uses "0". */
  prevHash: string;
}

export interface VerificationResult {
  valid: boolean;
  entriesVerified: number;
  firstInvalidIndex?: number;
  errors: string[];
}

export interface AuditSignerEvent {
  action: "sign" | "verify" | "key-generate";
  detail: string;
  timestamp: string;
}

// ── Constants ──────────────────────────────────────────────────────────────

export const AUDIT_KEY_LABEL = "audit-signing-key";

export const AUDIT_KEY_ATTRS: HsmKeyAttributes = {
  label: AUDIT_KEY_LABEL,
  extractable: false,
  sensitive: true,
  keyType: "rsa-2048",
  forSigning: true,
  forEncryption: false,
};

/** Genesis hash for the first entry in the chain. */
export const GENESIS_HASH = "0".repeat(64);

// ── Audit Signer ───────────────────────────────────────────────────────────

export class AuditSigner {
  private config: AuditSignerConfig;
  private lastHash: string = GENESIS_HASH;
  private entryCount = 0;
  private eventLog: AuditSignerEvent[] = [];

  constructor(config: AuditSignerConfig) {
    this.config = config;
  }

  /** Generate the audit signing key pair in HSM. */
  async generateSigningKey(): Promise<void> {
    await this.config.hsm.generateKeyPair(AUDIT_KEY_ATTRS);
    this.logEvent({
      action: "key-generate",
      detail: `generated RSA-2048 signing key: ${this.config.keyLabel}`,
      timestamp: new Date().toISOString(),
    });
  }

  /** Check if the signing key exists in HSM. */
  async hasSigningKey(): Promise<boolean> {
    const info = await this.config.hsm.getKeyInfo(this.config.keyLabel);
    return info !== undefined;
  }

  /**
   * Sign an audit log entry.
   * 1. Set prevHash to link to previous entry.
   * 2. Compute SHA-256 hash of entry content (excluding signature fields).
   * 3. Sign the hash with HSM.
   * 4. Return signed entry.
   */
  async sign(entry: AuditLogEntry): Promise<SignedAuditEntry> {
    // Set prevHash to chain
    const prevHash = this.lastHash;

    // Compute hash of entry content (deterministic fields only)
    const hashInput = this.buildHashInput(entry, prevHash);
    const entryHash = createHash("sha256").update(hashInput).digest("hex");

    // Sign hash with HSM
    const { signature } = await this.config.hsm.sign(
      this.config.keyLabel,
      Buffer.from(entryHash, "hex"),
    );

    const signed: SignedAuditEntry = {
      ...entry,
      prevHash,
      entryHash,
      hsmSignature: signature.toString("base64"),
    };

    // Update chain state
    this.lastHash = entryHash;
    this.entryCount++;

    this.logEvent({
      action: "sign",
      detail: `signed entry #${this.entryCount} (trace: ${entry.traceId})`,
      timestamp: new Date().toISOString(),
    });

    return signed;
  }

  /**
   * Verify a chain of signed audit entries.
   * Checks:
   * 1. Hash chain integrity (prevHash linkage).
   * 2. Entry hash matches recomputed hash.
   * 3. HSM signature is valid for the entry hash.
   */
  async verify(entries: SignedAuditEntry[]): Promise<VerificationResult> {
    const errors: string[] = [];
    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;

      // 1. Check prevHash chain
      if (entry.prevHash !== expectedPrevHash) {
        errors.push(
          `entry[${i}]: prevHash mismatch (expected ${expectedPrevHash.slice(0, 16)}..., got ${entry.prevHash.slice(0, 16)}...)`,
        );
        return { valid: false, entriesVerified: i, firstInvalidIndex: i, errors };
      }

      // 2. Recompute hash
      const hashInput = this.buildHashInput(entry, entry.prevHash);
      const expectedHash = createHash("sha256").update(hashInput).digest("hex");

      if (entry.entryHash !== expectedHash) {
        errors.push(
          `entry[${i}]: entryHash mismatch (content tampered)`,
        );
        return { valid: false, entriesVerified: i, firstInvalidIndex: i, errors };
      }

      // 3. Verify HSM signature
      const signatureValid = await this.config.hsm.verify(
        this.config.keyLabel,
        Buffer.from(entry.entryHash, "hex"),
        Buffer.from(entry.hsmSignature, "base64"),
      );

      if (!signatureValid) {
        errors.push(
          `entry[${i}]: HSM signature invalid`,
        );
        return { valid: false, entriesVerified: i, firstInvalidIndex: i, errors };
      }

      expectedPrevHash = entry.entryHash;
    }

    this.logEvent({
      action: "verify",
      detail: `verified ${entries.length} entries — chain intact`,
      timestamp: new Date().toISOString(),
    });

    return { valid: true, entriesVerified: entries.length, errors: [] };
  }

  /**
   * Build deterministic hash input from entry fields.
   * Excludes entryHash and hsmSignature (they depend on this hash).
   */
  private buildHashInput(entry: AuditLogEntry, prevHash: string): string {
    // Use a stable subset of fields for hashing
    return JSON.stringify({
      ts: entry.ts,
      level: entry.level,
      component: entry.component,
      module: entry.module,
      fn: entry.fn,
      msg: entry.msg,
      traceId: entry.traceId,
      layer: entry.layer,
      event: entry.event,
      attackClass: entry.attackClass,
      prevHash,
    });
  }

  /** Get the current chain head hash. */
  getLastHash(): string {
    return this.lastHash;
  }

  /** Get entry count. */
  getEntryCount(): number {
    return this.entryCount;
  }

  /** Get event log. */
  getEventLog(): AuditSignerEvent[] {
    return [...this.eventLog];
  }

  /** Reset chain state (for testing). */
  reset(): void {
    this.lastHash = GENESIS_HASH;
    this.entryCount = 0;
  }

  private logEvent(event: AuditSignerEvent): void {
    this.eventLog.push(event);
  }
}
