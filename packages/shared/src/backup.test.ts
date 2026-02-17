import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import { BackupManager, BACKUP_COMPONENTS } from "./backup.js";
import type { BackupConfig } from "./backup.js";
import { MockHsmClient } from "./hsm-client.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

let hsm: MockHsmClient;

async function setup(): Promise<void> {
  hsm = new MockHsmClient();
  await hsm.initialize("/mock", 0, "1234");
  await hsm.generateKeyPair({
    label: "backup-signing-key",
    extractable: false,
    sensitive: true,
    keyType: "rsa-2048",
    forSigning: true,
    forEncryption: false,
  });
}

function makeConfig(overrides: Partial<BackupConfig> = {}): BackupConfig {
  return {
    baseDir: "/etc/lobsec",
    backupDir: "/var/backups/lobsec",
    hsm,
    hsmKeyLabel: "backup-signing-key",
    hostname: "test-host",
    ...overrides,
  };
}

beforeEach(setup);

// ── Unit: Backup creation ───────────────────────────────────────────────────

describe("Backup creation", () => {
  it("creates backup with all components", async () => {
    const mgr = new BackupManager(makeConfig());
    const result = await mgr.createBackup();

    expect(result.success).toBe(true);
    expect(result.manifest.components).toHaveLength(BACKUP_COMPONENTS.length);
    expect(result.manifest.version).toBe(1);
    expect(result.errors).toHaveLength(0);
  });

  it("generates valid checksum", async () => {
    const mgr = new BackupManager(makeConfig());
    const result = await mgr.createBackup();

    expect(result.manifest.checksum).toMatch(/^[0-9a-f]{64}$/);
  });

  it("signs manifest with HSM", async () => {
    const mgr = new BackupManager(makeConfig());
    const result = await mgr.createBackup();

    expect(result.manifest.hsmSignature).toBeDefined();
    expect(result.manifest.hsmSignature!.length).toBeGreaterThan(0);
  });

  it("works without HSM", async () => {
    const mgr = new BackupManager(makeConfig({ hsm: undefined, hsmKeyLabel: undefined }));
    const result = await mgr.createBackup();

    expect(result.success).toBe(true);
    expect(result.manifest.hsmSignature).toBeUndefined();
  });

  it("records hostname in manifest", async () => {
    const mgr = new BackupManager(makeConfig({ hostname: "jetson-orin" }));
    const result = await mgr.createBackup();

    expect(result.manifest.hostname).toBe("jetson-orin");
  });

  it("tracks backup duration", async () => {
    const mgr = new BackupManager(makeConfig());
    const result = await mgr.createBackup();

    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// ── Unit: Backup verification ───────────────────────────────────────────────

describe("Backup verification", () => {
  it("verifies valid backup", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();

    const verification = await mgr.verifyBackup(manifest);
    expect(verification.valid).toBe(true);
    expect(verification.errors).toHaveLength(0);
  });

  it("detects corrupted checksum", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();

    // Corrupt checksum
    manifest.checksum = "0".repeat(64);

    const verification = await mgr.verifyBackup(manifest);
    expect(verification.valid).toBe(false);
    expect(verification.errors).toContain("manifest checksum mismatch");
  });

  it("detects tampered component list", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();

    // Add a component (changes what the checksum should be)
    manifest.components.push({
      name: "malicious",
      path: "/tmp/evil",
      sizeBytes: 999,
      checksum: "a".repeat(64),
      encrypted: false,
    });

    const verification = await mgr.verifyBackup(manifest);
    expect(verification.valid).toBe(false);
  });

  it("detects invalid HSM signature", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();

    // Corrupt signature
    manifest.hsmSignature = "AAAA" + manifest.hsmSignature!.slice(4);

    const verification = await mgr.verifyBackup(manifest);
    expect(verification.valid).toBe(false);
    expect(verification.errors.some((e) => e.includes("signature"))).toBe(true);
  });
});

// ── Unit: Backup restoration ────────────────────────────────────────────────

describe("Backup restoration", () => {
  it("restores from valid backup", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();

    const result = await mgr.restoreBackup(manifest);
    expect(result.success).toBe(true);
    expect(result.componentsRestored).toHaveLength(BACKUP_COMPONENTS.length);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects restore from corrupted backup", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();

    manifest.checksum = "0".repeat(64);

    const result = await mgr.restoreBackup(manifest);
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain("checksum mismatch");
  });

  it("rejects restore with bad HSM signature", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();

    manifest.hsmSignature = "AAAA" + manifest.hsmSignature!.slice(4);

    const result = await mgr.restoreBackup(manifest);
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain("signature");
  });
});

// ── Unit: Event logging ─────────────────────────────────────────────────────

describe("Backup event logging", () => {
  it("logs backup events", async () => {
    const mgr = new BackupManager(makeConfig());
    await mgr.createBackup();

    const events = mgr.getEventLog();
    expect(events.some((e) => e.action === "backup-start")).toBe(true);
    expect(events.some((e) => e.action === "backup-complete")).toBe(true);
    expect(events.some((e) => e.action === "backup-component")).toBe(true);
  });

  it("logs restore events", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();
    await mgr.restoreBackup(manifest);

    const events = mgr.getEventLog();
    expect(events.some((e) => e.action === "restore-start")).toBe(true);
    expect(events.some((e) => e.action === "restore-complete")).toBe(true);
  });

  it("logs verification events", async () => {
    const mgr = new BackupManager(makeConfig());
    const { manifest } = await mgr.createBackup();
    await mgr.verifyBackup(manifest);

    const events = mgr.getEventLog();
    expect(events.some((e) => e.action === "verify")).toBe(true);
  });
});

// ── Property 43: Backup and restore round-trip ──────────────────────────────

describe("Property 43: Backup and restore round-trip", () => {
  it("backup → verify → restore always succeeds for valid backups", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 20 }),
        async (hostname) => {
          const mgr = new BackupManager(makeConfig({ hostname }));
          const backup = await mgr.createBackup();

          expect(backup.success).toBe(true);
          expect(backup.manifest.hostname).toBe(hostname);

          const verification = await mgr.verifyBackup(backup.manifest);
          expect(verification.valid).toBe(true);

          const restore = await mgr.restoreBackup(backup.manifest);
          expect(restore.success).toBe(true);
          expect(restore.componentsRestored).toHaveLength(BACKUP_COMPONENTS.length);
        },
      ),
      { numRuns: 10 },
    );
  });

  it("tampered backup always fails restore", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 63 }),
        async (corruptIndex) => {
          const mgr = new BackupManager(makeConfig());
          const { manifest } = await mgr.createBackup();

          // Corrupt one character of checksum
          const chars = manifest.checksum.split("");
          chars[corruptIndex] = chars[corruptIndex] === "0" ? "1" : "0";
          manifest.checksum = chars.join("");

          const result = await mgr.restoreBackup(manifest);
          expect(result.success).toBe(false);
        },
      ),
      { numRuns: 10 },
    );
  });
});
