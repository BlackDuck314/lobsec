// ── Encryption at Rest ──────────────────────────────────────────────────────
// Manages LUKS2 full-disk encryption and fscrypt directory encryption.
// Abstracts behind interfaces for testing without real block devices.

import type { IHsmClient } from "./hsm-client.js";

// ── LUKS Types ──────────────────────────────────────────────────────────────

export type LuksUnlockMethod = "passphrase" | "tpm2" | "ssh-dropbear" | "tang-clevis";

export interface LuksConfig {
  /** LUKS device path (e.g., /dev/sda2). */
  device: string;
  /** Mapped device name (e.g., lobsec-data). */
  mapperName: string;
  /** Cipher suite. Always aes-xts-plain64. */
  cipher: "aes-xts-plain64";
  /** Key size in bits. Always 512 for AES-256-XTS. */
  keySize: 512;
  /** KDF algorithm. Always argon2id. */
  kdf: "argon2id";
  /** Argon2id memory in KiB. Default: 1048576 (1 GiB). */
  argon2idMemoryKiB: number;
  /** Unlock method. */
  unlockMethod: LuksUnlockMethod;
}

export interface LuksStatus {
  device: string;
  mapperName: string;
  isUnlocked: boolean;
  cipher?: string;
  keySize?: number;
  kdf?: string;
}

/** Commands that would be executed for LUKS operations. */
export interface LuksCommand {
  operation: "format" | "open" | "close" | "status" | "validate";
  command: string;
  args: string[];
}

// ── LUKS defaults ───────────────────────────────────────────────────────────

export const LUKS_DEFAULTS: Readonly<Omit<LuksConfig, "device" | "mapperName" | "unlockMethod">> = {
  cipher: "aes-xts-plain64",
  keySize: 512,
  kdf: "argon2id",
  argon2idMemoryKiB: 1048576, // 1 GiB
};

// ── fscrypt Types ───────────────────────────────────────────────────────────

export interface FscryptConfig {
  /** Base path for encrypted directories. */
  basePath: string;
  /** Directories to encrypt. */
  directories: string[];
  /** Content encryption algorithm. */
  contentAlgo: "AES-256-XTS";
  /** Filename encryption algorithm. */
  filenameAlgo: "AES-256-CTS";
  /** HSM label for the master key. */
  masterKeyLabel: string;
}

export interface FscryptDirectoryStatus {
  path: string;
  encrypted: boolean;
  locked: boolean;
  policy?: string;
}

export interface FscryptCommand {
  operation: "setup" | "encrypt" | "unlock" | "lock" | "status";
  command: string;
  args: string[];
}

// ── fscrypt defaults ────────────────────────────────────────────────────────

export const FSCRYPT_DIRECTORIES = [
  "workspace",
  "agents",
  "logs",
  "canvas",
] as const;

export const FSCRYPT_DEFAULTS: Readonly<Omit<FscryptConfig, "basePath" | "masterKeyLabel">> = {
  directories: [...FSCRYPT_DIRECTORIES],
  contentAlgo: "AES-256-XTS",
  filenameAlgo: "AES-256-CTS",
};

// ── LUKS Manager ────────────────────────────────────────────────────────────
// Generates cryptsetup commands but does not execute them directly.
// Real execution requires root and actual block devices.

export class LuksManager {
  private config: LuksConfig;
  private unlocked = false;
  private commandLog: LuksCommand[] = [];

  constructor(config: LuksConfig) {
    this.config = config;
  }

  /** Generate the cryptsetup format command. */
  formatCommand(): LuksCommand {
    const args = [
      "luksFormat",
      "--type", "luks2",
      "--cipher", this.config.cipher,
      "--key-size", String(this.config.keySize),
      "--pbkdf", this.config.kdf,
      "--pbkdf-memory", String(this.config.argon2idMemoryKiB),
      "--batch-mode",
      this.config.device,
    ];

    const cmd: LuksCommand = {
      operation: "format",
      command: "cryptsetup",
      args,
    };
    this.commandLog.push(cmd);
    return cmd;
  }

  /** Generate the open (unlock) command. */
  openCommand(): LuksCommand {
    let cmd: LuksCommand;

    switch (this.config.unlockMethod) {
      case "passphrase":
        cmd = {
          operation: "open",
          command: "cryptsetup",
          args: ["open", "--type", "luks2", this.config.device, this.config.mapperName],
        };
        break;

      case "tpm2":
        cmd = {
          operation: "open",
          command: "systemd-cryptenroll",
          args: ["--tpm2-device=auto", this.config.device],
        };
        break;

      case "ssh-dropbear":
        cmd = {
          operation: "open",
          command: "cryptsetup",
          args: ["open", "--type", "luks2", this.config.device, this.config.mapperName],
        };
        break;

      case "tang-clevis":
        cmd = {
          operation: "open",
          command: "clevis",
          args: ["luks", "unlock", "-d", this.config.device, "-n", this.config.mapperName],
        };
        break;
    }

    this.commandLog.push(cmd);
    return cmd;
  }

  /** Generate the close (lock) command. */
  closeCommand(): LuksCommand {
    const cmd: LuksCommand = {
      operation: "close",
      command: "cryptsetup",
      args: ["close", this.config.mapperName],
    };
    this.commandLog.push(cmd);
    return cmd;
  }

  /** Generate the status check command. */
  statusCommand(): LuksCommand {
    const cmd: LuksCommand = {
      operation: "status",
      command: "cryptsetup",
      args: ["status", this.config.mapperName],
    };
    this.commandLog.push(cmd);
    return cmd;
  }

  /** Validate LUKS configuration against security requirements. */
  validate(): string[] {
    const errors: string[] = [];

    if (this.config.cipher !== "aes-xts-plain64") {
      errors.push(`Invalid cipher: ${this.config.cipher}. Required: aes-xts-plain64`);
    }
    if (this.config.keySize !== 512) {
      errors.push(`Invalid key size: ${this.config.keySize}. Required: 512 (AES-256-XTS)`);
    }
    if (this.config.kdf !== "argon2id") {
      errors.push(`Invalid KDF: ${this.config.kdf}. Required: argon2id`);
    }
    if (this.config.argon2idMemoryKiB < 1048576) {
      errors.push(`Argon2id memory too low: ${this.config.argon2idMemoryKiB} KiB. Minimum: 1048576 (1 GiB)`);
    }

    const cmd: LuksCommand = {
      operation: "validate",
      command: "validation",
      args: errors.length > 0 ? errors : ["PASS"],
    };
    this.commandLog.push(cmd);

    return errors;
  }

  /** Simulate unlock for testing. */
  simulateUnlock(): void {
    this.unlocked = true;
  }

  /** Simulate lock for testing. */
  simulateLock(): void {
    this.unlocked = false;
  }

  get isUnlocked(): boolean {
    return this.unlocked;
  }

  get status(): LuksStatus {
    return {
      device: this.config.device,
      mapperName: this.config.mapperName,
      isUnlocked: this.unlocked,
      cipher: this.config.cipher,
      keySize: this.config.keySize,
      kdf: this.config.kdf,
    };
  }

  getCommandLog(): LuksCommand[] {
    return [...this.commandLog];
  }
}

// ── fscrypt Manager ─────────────────────────────────────────────────────────
// Generates fscrypt commands and integrates with HSM for master key.

export class FscryptManager {
  private config: FscryptConfig;
  private hsm: IHsmClient;
  private lockedDirs = new Set<string>();
  private encryptedDirs = new Set<string>();
  private commandLog: FscryptCommand[] = [];

  constructor(config: FscryptConfig, hsm: IHsmClient) {
    this.config = config;
    this.hsm = hsm;
    // All directories start locked
    for (const dir of config.directories) {
      this.lockedDirs.add(dir);
    }
  }

  /** Generate fscrypt setup command for the filesystem. */
  setupCommand(): FscryptCommand {
    const cmd: FscryptCommand = {
      operation: "setup",
      command: "fscrypt",
      args: ["setup", this.config.basePath],
    };
    this.commandLog.push(cmd);
    return cmd;
  }

  /** Generate fscrypt encrypt command for a directory. */
  encryptCommand(directory: string): FscryptCommand {
    const cmd: FscryptCommand = {
      operation: "encrypt",
      command: "fscrypt",
      args: [
        "encrypt",
        `${this.config.basePath}/${directory}`,
        "--source=raw_key",
        `--name=${directory}`,
      ],
    };
    this.commandLog.push(cmd);
    return cmd;
  }

  /** Generate unlock command for a directory. */
  unlockCommand(directory: string): FscryptCommand {
    const cmd: FscryptCommand = {
      operation: "unlock",
      command: "fscrypt",
      args: [
        "unlock",
        `${this.config.basePath}/${directory}`,
      ],
    };
    this.commandLog.push(cmd);
    return cmd;
  }

  /** Generate lock command for a directory. */
  lockCommand(directory: string): FscryptCommand {
    const cmd: FscryptCommand = {
      operation: "lock",
      command: "fscrypt",
      args: [
        "lock",
        `${this.config.basePath}/${directory}`,
      ],
    };
    this.commandLog.push(cmd);
    return cmd;
  }

  /** Ensure the master key exists in HSM. */
  async ensureMasterKey(): Promise<boolean> {
    const info = await this.hsm.getKeyInfo(this.config.masterKeyLabel);
    if (info) return true;

    try {
      await this.hsm.generateKey({
        label: this.config.masterKeyLabel,
        extractable: true,
        sensitive: true,
        keyType: "aes-256",
        forSigning: false,
        forEncryption: true,
      });
      return true;
    } catch {
      return false;
    }
  }

  /** Export master key from HSM for fscrypt (extractable=true). */
  async exportMasterKey(): Promise<Buffer> {
    return this.hsm.exportKey(this.config.masterKeyLabel);
  }

  /** Simulate encrypting a directory. */
  simulateEncrypt(directory: string): void {
    this.encryptedDirs.add(directory);
  }

  /** Simulate unlocking a directory. */
  simulateUnlock(directory: string): void {
    this.lockedDirs.delete(directory);
  }

  /** Simulate locking a directory. */
  simulateLock(directory: string): void {
    this.lockedDirs.add(directory);
  }

  /** Simulate unlocking all directories (startup). */
  simulateUnlockAll(): void {
    this.lockedDirs.clear();
  }

  /** Simulate locking all directories (shutdown). */
  simulateLockAll(): void {
    for (const dir of this.config.directories) {
      this.lockedDirs.add(dir);
    }
  }

  /** Get directory statuses. */
  getDirectoryStatuses(): FscryptDirectoryStatus[] {
    return this.config.directories.map((dir) => ({
      path: `${this.config.basePath}/${dir}`,
      encrypted: this.encryptedDirs.has(dir),
      locked: this.lockedDirs.has(dir),
    }));
  }

  /** Validate fscrypt config. */
  validate(): string[] {
    const errors: string[] = [];

    if (this.config.contentAlgo !== "AES-256-XTS") {
      errors.push(`Invalid content algo: ${this.config.contentAlgo}. Required: AES-256-XTS`);
    }
    if (this.config.filenameAlgo !== "AES-256-CTS") {
      errors.push(`Invalid filename algo: ${this.config.filenameAlgo}. Required: AES-256-CTS`);
    }

    const required = new Set(FSCRYPT_DIRECTORIES);
    for (const dir of required) {
      if (!this.config.directories.includes(dir)) {
        errors.push(`Missing required directory: ${dir}`);
      }
    }

    return errors;
  }

  getCommandLog(): FscryptCommand[] {
    return [...this.commandLog];
  }
}

// ── Encryption Lifecycle ────────────────────────────────────────────────────

export interface EncryptionStartupResult {
  luksUnlocked: boolean;
  fscryptUnlocked: boolean;
  masterKeyReady: boolean;
  errors: string[];
}

/** Orchestrate encryption startup: LUKS unlock → fscrypt unlock. */
export async function encryptionStartup(
  luks: LuksManager,
  fscrypt: FscryptManager,
): Promise<EncryptionStartupResult> {
  const errors: string[] = [];

  // Step 1: Validate LUKS config
  const luksErrors = luks.validate();
  if (luksErrors.length > 0) {
    return { luksUnlocked: false, fscryptUnlocked: false, masterKeyReady: false, errors: luksErrors };
  }

  // Step 2: Generate LUKS open command
  luks.openCommand();
  luks.simulateUnlock();

  // Step 3: Validate fscrypt config
  const fscryptErrors = fscrypt.validate();
  if (fscryptErrors.length > 0) {
    errors.push(...fscryptErrors);
    return { luksUnlocked: true, fscryptUnlocked: false, masterKeyReady: false, errors };
  }

  // Step 4: Ensure master key in HSM
  const masterKeyReady = await fscrypt.ensureMasterKey();
  if (!masterKeyReady) {
    errors.push("Failed to ensure fscrypt master key in HSM");
    return { luksUnlocked: true, fscryptUnlocked: false, masterKeyReady: false, errors };
  }

  // Step 5: Unlock all fscrypt directories
  fscrypt.simulateUnlockAll();

  return { luksUnlocked: true, fscryptUnlocked: true, masterKeyReady: true, errors };
}

/** Orchestrate encryption shutdown: fscrypt lock → LUKS close. */
export function encryptionShutdown(
  luks: LuksManager,
  fscrypt: FscryptManager,
): void {
  // Step 1: Lock all fscrypt directories
  fscrypt.simulateLockAll();

  // Step 2: Close LUKS
  luks.closeCommand();
  luks.simulateLock();
}
