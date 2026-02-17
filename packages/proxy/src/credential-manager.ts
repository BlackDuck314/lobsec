// ── Credential Manager ──────────────────────────────────────────────────────
// Orchestrates credential lifecycle: HSM storage → injection → rotation → cleanup.
// Bridges IHsmClient (secure storage) with CredentialStore (runtime access).

import type {
  IHsmClient,
  HsmKeyAttributes,
  CredentialType,
  InjectionMethod,
  CredentialMeta,
} from "@lobsec/shared";
import { ROTATION_SCHEDULES } from "@lobsec/shared";
import { CredentialStore } from "./credential-store.js";
import type { CredentialAccessCallback } from "./credential-store.js";
import { writeFileSync, unlinkSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

// ── Types ───────────────────────────────────────────────────────────────────

export interface CredentialSpec {
  label: string;
  type: CredentialType;
  extractable: boolean;
  injectionMethod: InjectionMethod;
  /** Env var name for env/tmpfs injection. */
  envVar?: string;
  /** File path for tmpfs-file injection. */
  tmpfsPath?: string;
}

export interface CredentialManagerConfig {
  /** Path to tmpfs mount for credential files (e.g., /run/lobsec/creds). */
  tmpfsDir: string;
  /** HSM client for key storage. */
  hsm: IHsmClient;
  /** Callback for credential access logging. */
  onAccess?: CredentialAccessCallback;
  /** Callback for lifecycle events. */
  onEvent?: (event: CredentialLifecycleEvent) => void;
}

export interface CredentialLifecycleEvent {
  action: "load" | "inject" | "rotate" | "revoke" | "cleanup";
  label: string;
  type: CredentialType;
  injectionMethod: InjectionMethod;
  success: boolean;
  detail?: string;
}

// ── Default credential specifications ───────────────────────────────────────

export const DEFAULT_CREDENTIAL_SPECS: CredentialSpec[] = [
  {
    label: "llm-api-key-anthropic",
    type: "llm-api-key",
    extractable: true,
    injectionMethod: "env",
    envVar: "ANTHROPIC_API_KEY",
  },
  {
    label: "llm-api-key-openai",
    type: "llm-api-key",
    extractable: true,
    injectionMethod: "env",
    envVar: "OPENAI_API_KEY",
  },
  {
    label: "channel-token-telegram",
    type: "channel-token",
    extractable: true,
    injectionMethod: "tmpfs-file",
    tmpfsPath: "telegram-token",
  },
  {
    label: "channel-token-discord",
    type: "channel-token",
    extractable: true,
    injectionMethod: "env",
    envVar: "DISCORD_BOT_TOKEN",
  },
  {
    label: "channel-token-slack",
    type: "channel-token",
    extractable: true,
    injectionMethod: "env",
    envVar: "SLACK_BOT_TOKEN",
  },
  {
    label: "webhook-secret-telegram",
    type: "webhook-secret",
    extractable: false,
    injectionMethod: "hsm-only",
  },
  {
    label: "webhook-secret-slack",
    type: "webhook-secret",
    extractable: false,
    injectionMethod: "hsm-only",
  },
  {
    label: "gateway-auth-token",
    type: "gateway-auth-token",
    extractable: true,
    injectionMethod: "env",
    envVar: "GATEWAY_AUTH_TOKEN",
  },
  {
    label: "proxy-internal-token",
    type: "proxy-internal-token",
    extractable: true,
    injectionMethod: "env",
    envVar: "LOBSEC_PROXY_TOKEN",
  },
  {
    label: "fscrypt-master-key",
    type: "fscrypt-master-key",
    extractable: true,
    injectionMethod: "kernel",
  },
];

// ── Credential Manager ──────────────────────────────────────────────────────

export class CredentialManager {
  private config: CredentialManagerConfig;
  private store: CredentialStore;
  private specs = new Map<string, CredentialSpec>();
  private injectedEnvVars = new Set<string>();
  private injectedTmpfsFiles = new Set<string>();
  private destroyed = false;

  constructor(config: CredentialManagerConfig) {
    this.config = config;
    this.store = new CredentialStore(config.onAccess);
  }

  /** Register credential specifications. */
  registerSpecs(specs: CredentialSpec[]): void {
    for (const spec of specs) {
      this.specs.set(spec.label, spec);
    }
  }

  /** Load a credential from HSM into the runtime store. */
  async loadFromHsm(label: string): Promise<boolean> {
    const spec = this.specs.get(label);
    if (!spec) {
      this.emitEvent("load", label, "llm-api-key", "env", false, "spec not found");
      return false;
    }

    if (!spec.extractable) {
      // Non-extractable credentials stay in HSM (e.g., webhook secrets)
      this.emitEvent("load", label, spec.type, spec.injectionMethod, true, "hsm-only (non-extractable)");
      return true;
    }

    try {
      const keyData = await this.config.hsm.exportKey(label);
      this.store.load(label, spec.type, keyData.toString("utf-8"));
      this.emitEvent("load", label, spec.type, spec.injectionMethod, true);
      return true;
    } catch {
      this.emitEvent("load", label, spec.type, spec.injectionMethod, false, "HSM export failed");
      return false;
    }
  }

  /** Import a credential value into HSM and runtime store. */
  async importCredential(label: string, value: string): Promise<boolean> {
    const spec = this.specs.get(label);
    if (!spec) return false;

    const attrs: HsmKeyAttributes = {
      label,
      extractable: spec.extractable,
      sensitive: true,
      keyType: "generic-secret",
      forSigning: spec.type === "webhook-secret" || spec.type === "audit-signing-key",
      forEncryption: false,
    };

    try {
      await this.config.hsm.importKey(attrs, Buffer.from(value, "utf-8"));

      if (spec.extractable) {
        this.store.load(label, spec.type, value);
      }

      this.emitEvent("load", label, spec.type, spec.injectionMethod, true);
      return true;
    } catch {
      this.emitEvent("load", label, spec.type, spec.injectionMethod, false, "HSM import failed");
      return false;
    }
  }

  /** Inject a credential into its target (env var, tmpfs file, etc.). */
  inject(label: string): boolean {
    const spec = this.specs.get(label);
    if (!spec) return false;

    switch (spec.injectionMethod) {
      case "env": {
        if (!spec.envVar) return false;
        const value = this.store.get(label);
        if (!value) return false;
        process.env[spec.envVar] = value;
        this.injectedEnvVars.add(spec.envVar);
        this.emitEvent("inject", label, spec.type, spec.injectionMethod, true, `env:${spec.envVar}`);
        return true;
      }

      case "tmpfs-file": {
        if (!spec.tmpfsPath) return false;
        const value = this.store.get(label);
        if (!value) return false;
        const fullPath = join(this.config.tmpfsDir, spec.tmpfsPath);
        try {
          mkdirSync(this.config.tmpfsDir, { recursive: true });
          writeFileSync(fullPath, value, { mode: 0o600 });
          this.injectedTmpfsFiles.add(fullPath);
          this.emitEvent("inject", label, spec.type, spec.injectionMethod, true, `tmpfs:${spec.tmpfsPath}`);
          return true;
        } catch {
          this.emitEvent("inject", label, spec.type, spec.injectionMethod, false, "tmpfs write failed");
          return false;
        }
      }

      case "hsm-only":
        // No injection needed — credential stays in HSM for C_Sign operations
        this.emitEvent("inject", label, spec.type, spec.injectionMethod, true, "hsm-only");
        return true;

      case "kernel":
        // Kernel keyring injection would happen here (requires privileged ops)
        this.emitEvent("inject", label, spec.type, spec.injectionMethod, true, "kernel (placeholder)");
        return true;

      case "fscrypt-dir":
        // fscrypt directory setup would happen here
        this.emitEvent("inject", label, spec.type, spec.injectionMethod, true, "fscrypt-dir (placeholder)");
        return true;
    }
  }

  /** Rotate a credential: generate new value, update HSM, re-inject. */
  async rotate(label: string, newValue: string): Promise<boolean> {
    const spec = this.specs.get(label);
    if (!spec) return false;

    try {
      // Destroy old key in HSM
      await this.config.hsm.destroyKey(label);

      // Import new value
      const imported = await this.importCredential(label, newValue);
      if (!imported) return false;

      // Re-inject
      if (spec.injectionMethod !== "hsm-only") {
        this.inject(label);
      }

      this.emitEvent("rotate", label, spec.type, spec.injectionMethod, true);
      return true;
    } catch {
      this.emitEvent("rotate", label, spec.type, spec.injectionMethod, false, "rotation failed");
      return false;
    }
  }

  /** Revoke (destroy) a single credential from all locations. */
  async revoke(label: string): Promise<boolean> {
    const spec = this.specs.get(label);
    if (!spec) return false;

    // Clear from env
    if (spec.envVar && this.injectedEnvVars.has(spec.envVar)) {
      delete process.env[spec.envVar];
      this.injectedEnvVars.delete(spec.envVar);
    }

    // Clear from tmpfs
    if (spec.tmpfsPath) {
      const fullPath = join(this.config.tmpfsDir, spec.tmpfsPath);
      if (this.injectedTmpfsFiles.has(fullPath)) {
        try {
          unlinkSync(fullPath);
        } catch {
          // File may already be gone
        }
        this.injectedTmpfsFiles.delete(fullPath);
      }
    }

    // Clear from runtime store
    this.store.delete(label);

    // Destroy in HSM
    try {
      await this.config.hsm.destroyKey(label);
    } catch {
      // Key may not exist in HSM
    }

    this.emitEvent("revoke", label, spec.type, spec.injectionMethod, true);
    return true;
  }

  /** Clean up all credentials on shutdown. */
  async cleanup(): Promise<void> {
    if (this.destroyed) return;

    // Clear all injected env vars
    for (const envVar of this.injectedEnvVars) {
      delete process.env[envVar];
    }
    this.injectedEnvVars.clear();

    // Delete all tmpfs files
    for (const filePath of this.injectedTmpfsFiles) {
      try {
        unlinkSync(filePath);
      } catch {
        // File may already be gone
      }
    }
    this.injectedTmpfsFiles.clear();

    // Destroy all credentials in HSM
    for (const [label, spec] of this.specs) {
      try {
        await this.config.hsm.destroyKey(label);
      } catch {
        // Key may not exist
      }
      this.emitEvent("cleanup", label, spec.type, spec.injectionMethod, true);
    }

    // Destroy runtime store
    this.store.destroy();
    this.destroyed = true;
  }

  /** Check which required credentials are missing for startup. */
  validateStartupCredentials(requiredLabels: string[]): string[] {
    const missing: string[] = [];
    for (const label of requiredLabels) {
      const spec = this.specs.get(label);
      if (!spec) {
        missing.push(label);
        continue;
      }

      // Non-extractable credentials don't need to be in the store
      if (!spec.extractable) continue;

      if (!this.store.has(label)) {
        missing.push(label);
      }
    }
    return missing;
  }

  /** Get metadata for all loaded credentials. */
  listCredentials(): CredentialMeta[] {
    const result: CredentialMeta[] = [];
    for (const [label, spec] of this.specs) {
      const entry = this.store.getMeta(label);
      result.push({
        label,
        type: spec.type,
        extractable: spec.extractable,
        sensitive: true,
        injectionMethod: spec.injectionMethod,
        rotationDays: ROTATION_SCHEDULES[spec.type],
        createdAt: entry?.loadedAt ?? "",
      });
    }
    return result;
  }

  /** Check if a credential needs rotation. */
  needsRotation(label: string): boolean {
    const spec = this.specs.get(label);
    if (!spec) return false;

    const entry = this.store.getMeta(label);
    if (!entry) return false;

    const rotationDays = ROTATION_SCHEDULES[spec.type];
    const loadedAt = new Date(entry.loadedAt).getTime();
    const now = Date.now();
    const daysSinceLoad = (now - loadedAt) / (1000 * 60 * 60 * 24);

    return daysSinceLoad >= rotationDays;
  }

  /** Get the underlying credential store (for direct access in proxy). */
  getStore(): CredentialStore {
    return this.store;
  }

  /** Whether the manager has been destroyed. */
  get isDestroyed(): boolean {
    return this.destroyed;
  }

  /** Clean tmpfs directory of all credential files. */
  cleanTmpfsDir(): void {
    if (!existsSync(this.config.tmpfsDir)) return;
    try {
      const files = readdirSync(this.config.tmpfsDir);
      for (const file of files) {
        try {
          unlinkSync(join(this.config.tmpfsDir, file));
        } catch {
          // Ignore individual file errors
        }
      }
    } catch {
      // Directory may not exist or be inaccessible
    }
  }

  private emitEvent(
    action: CredentialLifecycleEvent["action"],
    label: string,
    type: CredentialType,
    injectionMethod: InjectionMethod,
    success: boolean,
    detail?: string,
  ): void {
    this.config.onEvent?.({ action, label, type, injectionMethod, success, detail });
  }
}
