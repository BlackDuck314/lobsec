import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import { MockHsmClient } from "./hsm-client.js";
import {
  CertManager,
  DEFAULT_CERT_VALIDITY_HOURS,
  DEFAULT_ROTATION_INTERVAL_HOURS,
} from "./cert-manager.js";
import type { CertManagerConfig, CertLifecycleEvent } from "./cert-manager.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(
  hsm: MockHsmClient,
  overrides: Partial<CertManagerConfig> = {},
  events: CertLifecycleEvent[] = [],
): CertManagerConfig {
  return {
    hsm,
    tmpfsDir: "/tmp/lobsec-cert-test",
    caLabel: "internal-ca",
    certValidityHours: DEFAULT_CERT_VALIDITY_HOURS,
    rotationIntervalHours: DEFAULT_ROTATION_INTERVAL_HOURS,
    externalTlsMode: "self-signed",
    onEvent: (e) => events.push(e),
    ...overrides,
  };
}

// ── Unit: Internal CA creation ──────────────────────────────────────────────

describe("Internal CA creation", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("creates internal CA with non-extractable key", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    const caInfo = await mgr.createInternalCA();

    expect(caInfo.subject).toBe("CN=lobsec-internal-ca");
    expect(caInfo.issuer).toBe("CN=lobsec-internal-ca");
    expect(mgr.isCaCreated).toBe(true);

    // CA key must be non-extractable
    const keyInfo = await hsm.getKeyInfo("internal-ca");
    expect(keyInfo).toBeDefined();
    expect(keyInfo?.extractable).toBe(false);
  });

  it("CA is valid for 10 years", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    const caInfo = await mgr.createInternalCA();

    const notBefore = new Date(caInfo.notBefore);
    const notAfter = new Date(caInfo.notAfter);
    const years = (notAfter.getTime() - notBefore.getTime()) / (365.25 * 24 * 60 * 60 * 1000);
    expect(years).toBeCloseTo(10, 0);
  });

  it("emits ca-create event", async () => {
    const events: CertLifecycleEvent[] = [];
    const mgr = new CertManager(makeConfig(hsm, {}, events));
    await mgr.createInternalCA();

    const caEvent = events.find((e) => e.action === "ca-create");
    expect(caEvent).toBeDefined();
    expect(caEvent?.success).toBe(true);
  });
});

// ── Unit: Certificate issuance ──────────────────────────────────────────────

describe("Certificate issuance", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("issues a certificate with correct CN", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await mgr.createInternalCA();

    const cert = await mgr.issueCert("caddy-proxy", ["caddy.lobsec.internal"]);
    expect(cert.info.subject).toBe("CN=caddy-proxy");
    expect(cert.info.issuer).toBe("CN=lobsec-internal-ca");
    expect(cert.info.sans).toContain("caddy.lobsec.internal");
  });

  it("certificate has PEM format", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await mgr.createInternalCA();

    const cert = await mgr.issueCert("test-service");
    expect(cert.certPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(cert.certPem).toContain("-----END CERTIFICATE-----");
  });

  it("throws without CA", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await expect(mgr.issueCert("test")).rejects.toThrow("Internal CA not created");
  });

  it("tracks active cert count", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await mgr.createInternalCA();

    expect(mgr.activeCertCount).toBe(0);
    await mgr.issueCert("svc-a");
    expect(mgr.activeCertCount).toBe(1);
    await mgr.issueCert("svc-b");
    expect(mgr.activeCertCount).toBe(2);
  });

  it("emits cert-issue event", async () => {
    const events: CertLifecycleEvent[] = [];
    const mgr = new CertManager(makeConfig(hsm, {}, events));
    await mgr.createInternalCA();
    await mgr.issueCert("test-svc");

    const issueEvent = events.find((e) => e.action === "cert-issue");
    expect(issueEvent).toBeDefined();
    expect(issueEvent?.subject).toBe("CN=test-svc");
  });
});

// ── Unit: Certificate validity and expiry ───────────────────────────────────

describe("Certificate validity and expiry", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("certificate validity matches config", async () => {
    const mgr = new CertManager(makeConfig(hsm, { certValidityHours: 24 }));
    await mgr.createInternalCA();

    const cert = await mgr.issueCert("validity-test");
    const notBefore = new Date(cert.info.notBefore).getTime();
    const notAfter = new Date(cert.info.notAfter).getTime();
    const hours = (notAfter - notBefore) / (60 * 60 * 1000);
    expect(hours).toBe(24);
  });

  it("fresh certificate is not expired", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await mgr.createInternalCA();
    await mgr.issueCert("fresh-cert");

    expect(mgr.isExpired("fresh-cert")).toBe(false);
  });

  it("non-existent cert is treated as expired", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    expect(mgr.isExpired("nonexistent")).toBe(true);
  });

  it("fresh cert does not need rotation (with long interval)", async () => {
    const mgr = new CertManager(makeConfig(hsm, { rotationIntervalHours: 12 }));
    await mgr.createInternalCA();
    await mgr.issueCert("fresh-cert");

    // Just issued — shouldn't need rotation yet
    expect(mgr.needsRotation("fresh-cert")).toBe(false);
  });

  it("missing cert needs rotation", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    expect(mgr.needsRotation("missing")).toBe(true);
  });
});

// ── Unit: Certificate rotation ──────────────────────────────────────────────

describe("Certificate rotation", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("rotates a certificate and destroys old key", async () => {
    const events: CertLifecycleEvent[] = [];
    const mgr = new CertManager(makeConfig(hsm, {}, events));
    await mgr.createInternalCA();

    const oldCert = await mgr.issueCert("rotate-svc");
    const oldKeyLabel = oldCert.keyLabel;

    const newCert = await mgr.rotateCert("rotate-svc");
    expect(newCert.keyLabel).not.toBe(oldKeyLabel);

    // Old key should be destroyed
    const oldKeyInfo = await hsm.getKeyInfo(oldKeyLabel);
    expect(oldKeyInfo).toBeUndefined();

    const rotateEvent = events.find((e) => e.action === "cert-rotate");
    expect(rotateEvent).toBeDefined();
  });

  it("rotation issues new cert before revoking old", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await mgr.createInternalCA();

    await mgr.issueCert("zero-downtime");
    const newCert = await mgr.rotateCert("zero-downtime");

    // New cert should be valid
    expect(newCert.info.subject).toBe("CN=zero-downtime");
    expect(mgr.activeCertCount).toBe(1); // Old replaced by new
  });
});

// ── Unit: Certificate revocation ────────────────────────────────────────────

describe("Certificate revocation", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("revokes a certificate and destroys key", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await mgr.createInternalCA();

    const cert = await mgr.issueCert("revoke-svc");
    const keyLabel = cert.keyLabel;

    const revoked = await mgr.revokeCert("revoke-svc");
    expect(revoked).toBe(true);
    expect(mgr.activeCertCount).toBe(0);

    const keyInfo = await hsm.getKeyInfo(keyLabel);
    expect(keyInfo).toBeUndefined();
  });

  it("returns false for unknown certificate", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    const revoked = await mgr.revokeCert("nonexistent");
    expect(revoked).toBe(false);
  });
});

// ── Unit: List certificates ─────────────────────────────────────────────────

describe("List certificates", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("lists all issued certificates with status", async () => {
    const mgr = new CertManager(makeConfig(hsm));
    await mgr.createInternalCA();

    await mgr.issueCert("svc-a");
    await mgr.issueCert("svc-b");

    const certs = mgr.listCerts();
    expect(certs).toHaveLength(2);
    expect(certs.map((c) => c.commonName).sort()).toEqual(["svc-a", "svc-b"]);
  });
});

// ── Unit: External TLS modes ────────────────────────────────────────────────

describe("External TLS modes", () => {
  let hsm: MockHsmClient;

  beforeEach(async () => {
    hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");
  });

  it("self-signed mode", () => {
    const mgr = new CertManager(makeConfig(hsm, { externalTlsMode: "self-signed" }));
    const config = mgr.getExternalTlsConfig();
    expect(config.mode).toBe("self-signed");
  });

  it("ACME mode with config", () => {
    const mgr = new CertManager(makeConfig(hsm, {
      externalTlsMode: "acme",
      acme: {
        email: "admin@example.com",
        caUrl: "https://acme-v02.api.letsencrypt.org/directory",
        dnsProvider: "cloudflare",
        domains: ["lobsec.example.com"],
      },
    }));
    const config = mgr.getExternalTlsConfig();
    expect(config.mode).toBe("acme");
    expect(config.detail).toContain("letsencrypt");
  });

  it("custom mode with config", () => {
    const mgr = new CertManager(makeConfig(hsm, {
      externalTlsMode: "custom",
      custom: {
        certPath: "/etc/ssl/certs/lobsec.pem",
        keyPath: "/etc/ssl/private/lobsec.key",
      },
    }));
    const config = mgr.getExternalTlsConfig();
    expect(config.mode).toBe("custom");
    expect(config.detail).toContain("lobsec.pem");
  });
});

// ── Property 3 (modified): Container certificate validity = 24h ─────────────

describe("Property 3: Container certificate validity = 24h", () => {
  it("all issued certificates have exactly configured validity", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 168 }), // validity 1-168 hours
        fc.array(
          fc.string({ minLength: 1, maxLength: 10 }).filter((s) => /^[a-z][a-z0-9-]*$/.test(s)),
          { minLength: 1, maxLength: 3 },
        ),
        async (validityHours, serviceNames) => {
          const hsm = new MockHsmClient();
          await hsm.initialize("/path", 0, "pin");

          const mgr = new CertManager(makeConfig(hsm, {
            certValidityHours: validityHours,
          }));
          await mgr.createInternalCA();

          const uniqueNames = [...new Set(serviceNames)];
          for (const name of uniqueNames) {
            const cert = await mgr.issueCert(name);

            const notBefore = new Date(cert.info.notBefore).getTime();
            const notAfter = new Date(cert.info.notAfter).getTime();
            const hours = (notAfter - notBefore) / (60 * 60 * 1000);

            expect(hours).toBe(validityHours);
            expect(cert.info.issuer).toBe("CN=lobsec-internal-ca");
          }

          await hsm.finalize();
        },
      ),
      { numRuns: 10 },
    );
  }, 15000);
});

// ── Property: CA key is never extractable ───────────────────────────────────

describe("Property: CA key is never extractable", () => {
  it("internal CA key cannot be exported", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 20 }),
        async (caLabel) => {
          const hsm = new MockHsmClient();
          await hsm.initialize("/path", 0, "pin");

          const mgr = new CertManager(makeConfig(hsm, { caLabel }));
          await mgr.createInternalCA();

          // CA key must not be extractable
          const keyInfo = await hsm.getKeyInfo(caLabel);
          expect(keyInfo?.extractable).toBe(false);

          await hsm.finalize();
        },
      ),
      { numRuns: 10 },
    );
  });
});

// ── Property: Certificate rotation maintains zero downtime ──────────────────

describe("Property: Certificate rotation zero downtime", () => {
  it("rotation always leaves a valid certificate", async () => {
    const hsm = new MockHsmClient();
    await hsm.initialize("/path", 0, "pin");

    const mgr = new CertManager(makeConfig(hsm, { certValidityHours: 24 }));
    await mgr.createInternalCA();

    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 5 }),
        async (rotations) => {
          const cn = "rotation-test";
          await mgr.issueCert(cn);

          for (let i = 0; i < rotations; i++) {
            const newCert = await mgr.rotateCert(cn);

            // After rotation, there is always a valid cert
            expect(newCert.info.subject).toBe(`CN=${cn}`);
            expect(mgr.isExpired(cn)).toBe(false);
            expect(mgr.activeCertCount).toBeGreaterThanOrEqual(1);
          }

          await mgr.revokeCert(cn);
        },
      ),
      { numRuns: 10 },
    );

    await hsm.finalize();
  });
});
