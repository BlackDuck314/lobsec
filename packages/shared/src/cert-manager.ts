// ── Certificate Manager ─────────────────────────────────────────────────────
// Manages internal CA, per-container certificates, and external TLS modes.
// Internal mTLS: always on, always HSM-backed, 24h lifetime.

import type { IHsmClient, HsmKeyAttributes } from "./hsm-client.js";

// ── Types ───────────────────────────────────────────────────────────────────

export type ExternalTlsMode = "self-signed" | "acme" | "custom";

export interface CertInfo {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  serialNumber: string;
  sans: string[];
  fingerprint: string;
}

export interface CertManagerConfig {
  /** HSM client for key operations. */
  hsm: IHsmClient;
  /** Directory for tmpfs certificate storage. */
  tmpfsDir: string;
  /** Internal CA label in HSM. */
  caLabel: string;
  /** Certificate validity in hours. Default: 24. */
  certValidityHours: number;
  /** Rotation interval in hours. Default: 12. */
  rotationIntervalHours: number;
  /** External TLS mode. */
  externalTlsMode: ExternalTlsMode;
  /** ACME config (for acme mode). */
  acme?: AcmeCertConfig;
  /** Custom cert paths (for custom mode). */
  custom?: CustomCertConfig;
  /** Lifecycle event callback. */
  onEvent?: (event: CertLifecycleEvent) => void;
}

export interface AcmeCertConfig {
  email: string;
  caUrl: string;
  dnsProvider: string;
  domains: string[];
}

export interface CustomCertConfig {
  certPath: string;
  keyPath: string;
  chainPath?: string;
}

export interface CertLifecycleEvent {
  action: "ca-create" | "cert-issue" | "cert-rotate" | "cert-revoke" | "cert-check";
  subject: string;
  success: boolean;
  detail?: string;
}

export interface IssuedCert {
  certPem: string;
  keyLabel: string;
  info: CertInfo;
  issuedAt: number;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Default certificate validity: 24 hours. */
export const DEFAULT_CERT_VALIDITY_HOURS = 24;

/** Default rotation interval: 12 hours. */
export const DEFAULT_ROTATION_INTERVAL_HOURS = 12;

/** Internal CA key type. */
const CA_KEY_TYPE = "ec-p256" as const;

// ── Mock Certificate Manager ────────────────────────────────────────────────
// Uses HSM for key operations but generates mock certificates.
// Real implementation would use node-forge or openssl for X.509.

export class CertManager {
  private config: CertManagerConfig;
  private caCreated = false;
  private issuedCerts = new Map<string, IssuedCert>();

  constructor(config: CertManagerConfig) {
    this.config = config;
  }

  /** Create the internal CA key pair in HSM. */
  async createInternalCA(): Promise<CertInfo> {
    const attrs: HsmKeyAttributes = {
      label: this.config.caLabel,
      extractable: false, // CA key NEVER leaves HSM
      sensitive: true,
      keyType: CA_KEY_TYPE,
      forSigning: true,
      forEncryption: false,
    };

    try {
      await this.config.hsm.generateKeyPair(attrs);
      this.caCreated = true;

      const now = new Date();
      const notAfter = new Date(now);
      notAfter.setFullYear(notAfter.getFullYear() + 10); // CA valid 10 years

      const info: CertInfo = {
        subject: "CN=lobsec-internal-ca",
        issuer: "CN=lobsec-internal-ca",
        notBefore: now.toISOString(),
        notAfter: notAfter.toISOString(),
        serialNumber: generateSerial(),
        sans: [],
        fingerprint: generateFingerprint(),
      };

      this.emitEvent("ca-create", info.subject, true, "EC-P256, non-extractable");
      return info;
    } catch (err) {
      this.emitEvent("ca-create", "CN=lobsec-internal-ca", false, (err as Error).message);
      throw err;
    }
  }

  /** Issue a certificate for a container/service. */
  async issueCert(
    commonName: string,
    sans: string[] = [],
  ): Promise<IssuedCert> {
    if (!this.caCreated) {
      throw new Error("Internal CA not created. Call createInternalCA() first.");
    }

    const validityMs = this.config.certValidityHours * 60 * 60 * 1000;
    const now = Date.now();
    const notBefore = new Date(now);
    const notAfter = new Date(now + validityMs);

    // Generate key for this cert in HSM
    const keyLabel = `cert-${commonName}-${now}`;
    const keyAttrs: HsmKeyAttributes = {
      label: keyLabel,
      extractable: true, // Need to extract for container use
      sensitive: true,
      keyType: CA_KEY_TYPE,
      forSigning: true,
      forEncryption: false,
    };

    await this.config.hsm.generateKeyPair(keyAttrs);

    // Sign with CA key (mock: just sign the subject data)
    const certData = Buffer.from(JSON.stringify({ cn: commonName, sans, notBefore, notAfter }));
    const { signature } = await this.config.hsm.sign(this.config.caLabel, certData);

    const info: CertInfo = {
      subject: `CN=${commonName}`,
      issuer: "CN=lobsec-internal-ca",
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      serialNumber: generateSerial(),
      sans,
      fingerprint: generateFingerprint(),
    };

    // Mock PEM (real impl would use ASN.1/DER encoding)
    const certPem = [
      "-----BEGIN CERTIFICATE-----",
      signature.toString("base64"),
      "-----END CERTIFICATE-----",
    ].join("\n");

    const issued: IssuedCert = {
      certPem,
      keyLabel,
      info,
      issuedAt: now,
    };

    this.issuedCerts.set(commonName, issued);
    this.emitEvent("cert-issue", info.subject, true, `validity: ${this.config.certValidityHours}h`);

    return issued;
  }

  /** Check if a certificate needs rotation. */
  needsRotation(commonName: string): boolean {
    const cert = this.issuedCerts.get(commonName);
    if (!cert) return true; // No cert = needs issuance

    const ageMs = Date.now() - cert.issuedAt;
    const rotationMs = this.config.rotationIntervalHours * 60 * 60 * 1000;
    return ageMs >= rotationMs;
  }

  /** Check if a certificate is expired. */
  isExpired(commonName: string): boolean {
    const cert = this.issuedCerts.get(commonName);
    if (!cert) return true;

    const expiryTime = new Date(cert.info.notAfter).getTime();
    return Date.now() >= expiryTime;
  }

  /** Rotate a certificate: issue new, revoke old. */
  async rotateCert(
    commonName: string,
    sans: string[] = [],
  ): Promise<IssuedCert> {
    const oldCert = this.issuedCerts.get(commonName);

    // Issue new cert first (zero-downtime)
    const newCert = await this.issueCert(commonName, sans);

    // Revoke old cert's key
    if (oldCert) {
      try {
        await this.config.hsm.destroyKey(oldCert.keyLabel);
      } catch {
        // Old key may already be gone
      }
      this.emitEvent("cert-rotate", `CN=${commonName}`, true, "old key destroyed");
    }

    return newCert;
  }

  /** Revoke a certificate and destroy its key. */
  async revokeCert(commonName: string): Promise<boolean> {
    const cert = this.issuedCerts.get(commonName);
    if (!cert) return false;

    try {
      await this.config.hsm.destroyKey(cert.keyLabel);
    } catch {
      // Key may already be gone
    }

    this.issuedCerts.delete(commonName);
    this.emitEvent("cert-revoke", `CN=${commonName}`, true);
    return true;
  }

  /** Get all issued certificates and their status. */
  listCerts(): Array<{ commonName: string; info: CertInfo; needsRotation: boolean; isExpired: boolean }> {
    const result: Array<{ commonName: string; info: CertInfo; needsRotation: boolean; isExpired: boolean }> = [];
    for (const [cn, cert] of this.issuedCerts) {
      result.push({
        commonName: cn,
        info: cert.info,
        needsRotation: this.needsRotation(cn),
        isExpired: this.isExpired(cn),
      });
    }
    return result;
  }

  /** Check all certificates and rotate those that need it. */
  async checkAndRotate(): Promise<string[]> {
    const rotated: string[] = [];
    for (const [cn] of this.issuedCerts) {
      if (this.needsRotation(cn)) {
        await this.rotateCert(cn);
        rotated.push(cn);
      }
    }
    return rotated;
  }

  /** Get the external TLS configuration for Caddy. */
  getExternalTlsConfig(): { mode: ExternalTlsMode; detail: string } {
    switch (this.config.externalTlsMode) {
      case "self-signed":
        return { mode: "self-signed", detail: "Using internal CA for external TLS" };
      case "acme":
        return {
          mode: "acme",
          detail: this.config.acme
            ? `ACME: ${this.config.acme.caUrl} (${this.config.acme.domains.join(", ")})`
            : "ACME: not configured",
        };
      case "custom":
        return {
          mode: "custom",
          detail: this.config.custom
            ? `Custom: ${this.config.custom.certPath}`
            : "Custom: not configured",
        };
    }
  }

  /** Whether the internal CA has been created. */
  get isCaCreated(): boolean {
    return this.caCreated;
  }

  /** Number of active certificates. */
  get activeCertCount(): number {
    return this.issuedCerts.size;
  }

  private emitEvent(
    action: CertLifecycleEvent["action"],
    subject: string,
    success: boolean,
    detail?: string,
  ): void {
    this.config.onEvent?.({ action, subject, success, detail });
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function generateSerial(): string {
  const bytes = new Uint8Array(16);
  // Use Math.random for mock (real impl would use crypto.randomBytes)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateFingerprint(): string {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return "SHA-256:" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(":");
}
