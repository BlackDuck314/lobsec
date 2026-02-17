import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import { MockHsmClient } from "./hsm-client.js";
import {
  LuksManager,
  FscryptManager,
  LUKS_DEFAULTS,
  FSCRYPT_DEFAULTS,
  FSCRYPT_DIRECTORIES,
  encryptionStartup,
  encryptionShutdown,
} from "./encryption.js";
import type { LuksConfig, FscryptConfig } from "./encryption.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeLuksConfig(overrides: Partial<LuksConfig> = {}): LuksConfig {
  return {
    device: "/dev/sda2",
    mapperName: "lobsec-data",
    unlockMethod: "passphrase",
    ...LUKS_DEFAULTS,
    ...overrides,
  };
}

function makeFscryptConfig(overrides: Partial<FscryptConfig> = {}): FscryptConfig {
  return {
    basePath: "/mnt/lobsec",
    masterKeyLabel: "fscrypt-master-key",
    ...FSCRYPT_DEFAULTS,
    ...overrides,
  };
}

// ── Unit: LUKS Manager ──────────────────────────────────────────────────────

describe("LuksManager", () => {
  it("generates correct format command", () => {
    const luks = new LuksManager(makeLuksConfig());
    const cmd = luks.formatCommand();

    expect(cmd.command).toBe("cryptsetup");
    expect(cmd.args).toContain("luksFormat");
    expect(cmd.args).toContain("--type");
    expect(cmd.args).toContain("luks2");
    expect(cmd.args).toContain("--cipher");
    expect(cmd.args).toContain("aes-xts-plain64");
    expect(cmd.args).toContain("--key-size");
    expect(cmd.args).toContain("512");
    expect(cmd.args).toContain("--pbkdf");
    expect(cmd.args).toContain("argon2id");
  });

  it("generates passphrase open command", () => {
    const luks = new LuksManager(makeLuksConfig({ unlockMethod: "passphrase" }));
    const cmd = luks.openCommand();

    expect(cmd.command).toBe("cryptsetup");
    expect(cmd.args).toContain("open");
    expect(cmd.args).toContain("lobsec-data");
  });

  it("generates TPM2 open command", () => {
    const luks = new LuksManager(makeLuksConfig({ unlockMethod: "tpm2" }));
    const cmd = luks.openCommand();

    expect(cmd.command).toBe("systemd-cryptenroll");
    expect(cmd.args).toContain("--tpm2-device=auto");
  });

  it("generates tang-clevis open command", () => {
    const luks = new LuksManager(makeLuksConfig({ unlockMethod: "tang-clevis" }));
    const cmd = luks.openCommand();

    expect(cmd.command).toBe("clevis");
    expect(cmd.args).toContain("luks");
    expect(cmd.args).toContain("unlock");
  });

  it("generates close command", () => {
    const luks = new LuksManager(makeLuksConfig());
    const cmd = luks.closeCommand();

    expect(cmd.command).toBe("cryptsetup");
    expect(cmd.args).toContain("close");
    expect(cmd.args).toContain("lobsec-data");
  });

  it("generates status command", () => {
    const luks = new LuksManager(makeLuksConfig());
    const cmd = luks.statusCommand();

    expect(cmd.args).toContain("status");
    expect(cmd.args).toContain("lobsec-data");
  });

  it("tracks unlock state", () => {
    const luks = new LuksManager(makeLuksConfig());
    expect(luks.isUnlocked).toBe(false);

    luks.simulateUnlock();
    expect(luks.isUnlocked).toBe(true);

    luks.simulateLock();
    expect(luks.isUnlocked).toBe(false);
  });

  it("returns full status", () => {
    const luks = new LuksManager(makeLuksConfig());
    const status = luks.status;

    expect(status.device).toBe("/dev/sda2");
    expect(status.mapperName).toBe("lobsec-data");
    expect(status.cipher).toBe("aes-xts-plain64");
    expect(status.keySize).toBe(512);
    expect(status.kdf).toBe("argon2id");
  });

  it("logs all commands", () => {
    const luks = new LuksManager(makeLuksConfig());
    luks.formatCommand();
    luks.openCommand();
    luks.closeCommand();

    const log = luks.getCommandLog();
    expect(log).toHaveLength(3);
    expect(log.map((c) => c.operation)).toEqual(["format", "open", "close"]);
  });
});

// ── Unit: LUKS Validation ───────────────────────────────────────────────────

describe("LUKS validation", () => {
  it("passes with correct defaults", () => {
    const luks = new LuksManager(makeLuksConfig());
    const errors = luks.validate();
    expect(errors).toEqual([]);
  });

  it("fails with wrong cipher", () => {
    const luks = new LuksManager(makeLuksConfig({ cipher: "aes-cbc-essiv:sha256" as "aes-xts-plain64" }));
    const errors = luks.validate();
    expect(errors.some((e) => e.includes("cipher"))).toBe(true);
  });

  it("fails with wrong key size", () => {
    const luks = new LuksManager(makeLuksConfig({ keySize: 256 as 512 }));
    const errors = luks.validate();
    expect(errors.some((e) => e.includes("key size"))).toBe(true);
  });

  it("fails with wrong KDF", () => {
    const luks = new LuksManager(makeLuksConfig({ kdf: "pbkdf2" as "argon2id" }));
    const errors = luks.validate();
    expect(errors.some((e) => e.includes("KDF"))).toBe(true);
  });

  it("fails with low argon2id memory", () => {
    const luks = new LuksManager(makeLuksConfig({ argon2idMemoryKiB: 524288 }));
    const errors = luks.validate();
    expect(errors.some((e) => e.includes("memory"))).toBe(true);
  });
});

// ── Unit: fscrypt Manager ───────────────────────────────────────────────────

describe("FscryptManager", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("generates setup command", () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);
    const cmd = fscrypt.setupCommand();

    expect(cmd.command).toBe("fscrypt");
    expect(cmd.args).toContain("setup");
    expect(cmd.args).toContain("/mnt/lobsec");
  });

  it("generates encrypt command", () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);
    const cmd = fscrypt.encryptCommand("workspace");

    expect(cmd.command).toBe("fscrypt");
    expect(cmd.args).toContain("encrypt");
    expect(cmd.args.some((a) => a.includes("workspace"))).toBe(true);
  });

  it("generates unlock/lock commands", () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);
    const unlock = fscrypt.unlockCommand("workspace");
    const lock = fscrypt.lockCommand("workspace");

    expect(unlock.operation).toBe("unlock");
    expect(lock.operation).toBe("lock");
  });

  it("ensures master key in HSM", async () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

    const result = await fscrypt.ensureMasterKey();
    expect(result).toBe(true);

    const keyInfo = await hsm.getKeyInfo("fscrypt-master-key");
    expect(keyInfo).toBeDefined();
    expect(keyInfo?.extractable).toBe(true);
    expect(keyInfo?.sensitive).toBe(true);
  });

  it("does not re-create existing master key", async () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

    await fscrypt.ensureMasterKey();
    const firstKey = await hsm.getKeyInfo("fscrypt-master-key");

    await fscrypt.ensureMasterKey();
    const secondKey = await hsm.getKeyInfo("fscrypt-master-key");

    expect(firstKey?.createdAt).toBe(secondKey?.createdAt);
  });

  it("exports master key", async () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);
    await fscrypt.ensureMasterKey();

    const key = await fscrypt.exportMasterKey();
    expect(key.length).toBeGreaterThan(0);
  });

  it("tracks directory lock state", () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

    // All start locked
    const statuses = fscrypt.getDirectoryStatuses();
    expect(statuses.every((s) => s.locked)).toBe(true);

    fscrypt.simulateUnlock("workspace");
    const after = fscrypt.getDirectoryStatuses();
    expect(after.find((s) => s.path.includes("workspace"))?.locked).toBe(false);
    expect(after.find((s) => s.path.includes("agents"))?.locked).toBe(true);
  });

  it("unlock/lock all", () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

    fscrypt.simulateUnlockAll();
    expect(fscrypt.getDirectoryStatuses().every((s) => !s.locked)).toBe(true);

    fscrypt.simulateLockAll();
    expect(fscrypt.getDirectoryStatuses().every((s) => s.locked)).toBe(true);
  });
});

// ── Unit: fscrypt Validation ────────────────────────────────────────────────

describe("fscrypt validation", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("passes with correct defaults", () => {
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);
    const errors = fscrypt.validate();
    expect(errors).toEqual([]);
  });

  it("fails with missing directory", () => {
    const fscrypt = new FscryptManager(makeFscryptConfig({
      directories: ["workspace", "agents"],
    }), hsm);
    const errors = fscrypt.validate();
    expect(errors.some((e) => e.includes("logs"))).toBe(true);
    expect(errors.some((e) => e.includes("canvas"))).toBe(true);
  });
});

// ── Unit: Encryption Lifecycle ──────────────────────────────────────────────

describe("Encryption startup/shutdown lifecycle", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("startup unlocks LUKS then fscrypt", async () => {
    const luks = new LuksManager(makeLuksConfig());
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

    const result = await encryptionStartup(luks, fscrypt);

    expect(result.luksUnlocked).toBe(true);
    expect(result.fscryptUnlocked).toBe(true);
    expect(result.masterKeyReady).toBe(true);
    expect(result.errors).toEqual([]);

    expect(luks.isUnlocked).toBe(true);
    expect(fscrypt.getDirectoryStatuses().every((s) => !s.locked)).toBe(true);
  });

  it("shutdown locks fscrypt then LUKS", async () => {
    const luks = new LuksManager(makeLuksConfig());
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

    await encryptionStartup(luks, fscrypt);
    encryptionShutdown(luks, fscrypt);

    expect(luks.isUnlocked).toBe(false);
    expect(fscrypt.getDirectoryStatuses().every((s) => s.locked)).toBe(true);
  });

  it("startup fails with invalid LUKS config", async () => {
    const luks = new LuksManager(makeLuksConfig({ kdf: "pbkdf2" as "argon2id" }));
    const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

    const result = await encryptionStartup(luks, fscrypt);

    expect(result.luksUnlocked).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });
});

// ── Property: All LUKS parameters are security-compliant ────────────────────

describe("Property: LUKS security compliance", () => {
  it("valid configs always pass validation", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("passphrase", "tpm2", "ssh-dropbear", "tang-clevis") as fc.Arbitrary<"passphrase" | "tpm2" | "ssh-dropbear" | "tang-clevis">,
        fc.string({ minLength: 1, maxLength: 20 }),
        (unlockMethod, device) => {
          const luks = new LuksManager(makeLuksConfig({
            device: `/dev/${device}`,
            unlockMethod,
          }));
          const errors = luks.validate();
          expect(errors).toEqual([]);
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Property: fscrypt always encrypts required directories ──────────────────

describe("Property: fscrypt required directories", () => {
  it("all 4 required directories are present in status", async () => {
    const hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");

    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 30 }),
        (basePath) => {
          const fscrypt = new FscryptManager(makeFscryptConfig({
            basePath: `/mnt/${basePath}`,
          }), hsm);

          const statuses = fscrypt.getDirectoryStatuses();
          const paths = statuses.map((s) => s.path);

          for (const dir of FSCRYPT_DIRECTORIES) {
            expect(paths.some((p) => p.includes(dir))).toBe(true);
          }
        },
      ),
      { numRuns: 20 },
    );
  });
});

// ── Property: Encryption lifecycle always ends locked ───────────────────────

describe("Property: Encryption lifecycle always ends locked", () => {
  it("shutdown always leaves everything locked", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("passphrase", "tpm2") as fc.Arbitrary<"passphrase" | "tpm2">,
        async (unlockMethod) => {
          const hsm = new MockHsmClient();
          await hsm.initialize("/path", 0, "pin");

          const luks = new LuksManager(makeLuksConfig({ unlockMethod }));
          const fscrypt = new FscryptManager(makeFscryptConfig(), hsm);

          // Start up
          const result = await encryptionStartup(luks, fscrypt);
          expect(result.luksUnlocked).toBe(true);
          expect(result.fscryptUnlocked).toBe(true);

          // Shut down
          encryptionShutdown(luks, fscrypt);

          // Everything must be locked
          expect(luks.isUnlocked).toBe(false);
          expect(fscrypt.getDirectoryStatuses().every((s) => s.locked)).toBe(true);

          await hsm.finalize();
        },
      ),
      { numRuns: 10 },
    );
  });
});
