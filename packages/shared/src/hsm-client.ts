// ── PKCS#11 HSM Client (L6) ─────────────────────────────────────────────────
// Abstracts HSM operations behind a portable interface.
// SoftHSM2 for dev, YubiHSM2 for prod — only LOBSEC_PKCS11_MODULE changes.

// ── Types ───────────────────────────────────────────────────────────────────

export interface HsmKeyAttributes {
  /** Key label in HSM. */
  label: string;
  /** Whether the key can be extracted from HSM. */
  extractable: boolean;
  /** Whether the key is marked as sensitive. */
  sensitive: boolean;
  /** Key type identifier. */
  keyType: "aes-256" | "rsa-2048" | "ec-p256" | "generic-secret";
  /** Whether this is a signing key. */
  forSigning: boolean;
  /** Whether this is an encryption key. */
  forEncryption: boolean;
}

export interface HsmKeyInfo {
  handle: string;
  label: string;
  keyType: string;
  extractable: boolean;
  sensitive: boolean;
  createdAt: string;
}

export interface HsmSignResult {
  signature: Buffer;
  mechanism: string;
}

export interface HsmOperationLog {
  operation: string;
  keyLabel: string;
  success: boolean;
  durationMs: number;
  /** Never contains key material. */
  detail?: string;
}

// ── HSM Client Interface ────────────────────────────────────────────────────

/**
 * Abstract HSM client interface.
 * Implementations: RealHsmClient (graphene-pk11), MockHsmClient (testing).
 */
export interface IHsmClient {
  /** Initialize the HSM module and open a session. */
  initialize(modulePath: string, slotIndex: number, pin: string): Promise<void>;

  /** Close the session and finalize the module. */
  finalize(): Promise<void>;

  /** Whether the client is initialized with an active session. */
  readonly isInitialized: boolean;

  /** Generate a symmetric key (AES-256 or generic secret). */
  generateKey(attrs: HsmKeyAttributes): Promise<HsmKeyInfo>;

  /** Generate an asymmetric key pair (RSA-2048 or EC-P256). */
  generateKeyPair(attrs: HsmKeyAttributes): Promise<{ publicKey: HsmKeyInfo; privateKey: HsmKeyInfo }>;

  /** Import a key into the HSM. */
  importKey(attrs: HsmKeyAttributes, keyData: Buffer): Promise<HsmKeyInfo>;

  /** Export a key from the HSM (only if extractable=true). */
  exportKey(label: string): Promise<Buffer>;

  /** Delete a key from the HSM. */
  destroyKey(label: string): Promise<boolean>;

  /** Sign data using a key in the HSM. */
  sign(keyLabel: string, data: Buffer): Promise<HsmSignResult>;

  /** Verify a signature using a key in the HSM. */
  verify(keyLabel: string, data: Buffer, signature: Buffer): Promise<boolean>;

  /** List all keys in the HSM. */
  listKeys(): Promise<HsmKeyInfo[]>;

  /** Get a key's info by label. */
  getKeyInfo(label: string): Promise<HsmKeyInfo | undefined>;

  /** Get the operation log (for audit). */
  getOperationLog(): HsmOperationLog[];
}

// ── Mock HSM Client (for testing without SoftHSM2) ─────────────────────────

import { createHmac, randomBytes, generateKeyPairSync, sign, verify } from "node:crypto";

export class MockHsmClient implements IHsmClient {
  private initialized = false;
  private keys = new Map<string, { attrs: HsmKeyAttributes; data: Buffer; createdAt: string }>();
  private keyPairs = new Map<string, { publicKey: Buffer; privateKey: Buffer; attrs: HsmKeyAttributes; createdAt: string }>();
  private operationLog: HsmOperationLog[] = [];

  get isInitialized(): boolean {
    return this.initialized;
  }

  async initialize(_modulePath: string, _slotIndex: number, _pin: string): Promise<void> {
    this.initialized = true;
    this.log("initialize", "session", true, "HSM session opened");
  }

  async finalize(): Promise<void> {
    this.initialized = false;
    this.log("finalize", "session", true, "HSM session closed");
  }

  async generateKey(attrs: HsmKeyAttributes): Promise<HsmKeyInfo> {
    this.ensureInitialized();
    const start = Date.now();

    const keyData = randomBytes(32); // AES-256 = 32 bytes
    const info: HsmKeyInfo = {
      handle: randomBytes(4).toString("hex"),
      label: attrs.label,
      keyType: attrs.keyType,
      extractable: attrs.extractable,
      sensitive: attrs.sensitive,
      createdAt: new Date().toISOString(),
    };

    this.keys.set(attrs.label, { attrs, data: keyData, createdAt: info.createdAt });
    this.log("generateKey", attrs.label, true, `key type: ${attrs.keyType}`, Date.now() - start);

    return info;
  }

  async generateKeyPair(attrs: HsmKeyAttributes): Promise<{ publicKey: HsmKeyInfo; privateKey: HsmKeyInfo }> {
    this.ensureInitialized();
    const start = Date.now();

    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" },
    });

    const createdAt = new Date().toISOString();

    this.keyPairs.set(attrs.label, {
      publicKey: publicKey as Buffer,
      privateKey: privateKey as Buffer,
      attrs,
      createdAt,
    });

    const pubInfo: HsmKeyInfo = {
      handle: randomBytes(4).toString("hex"),
      label: attrs.label + "-pub",
      keyType: attrs.keyType,
      extractable: true,
      sensitive: false,
      createdAt,
    };

    const privInfo: HsmKeyInfo = {
      handle: randomBytes(4).toString("hex"),
      label: attrs.label,
      keyType: attrs.keyType,
      extractable: attrs.extractable,
      sensitive: attrs.sensitive,
      createdAt,
    };

    this.log("generateKeyPair", attrs.label, true, `key type: ${attrs.keyType}`, Date.now() - start);
    return { publicKey: pubInfo, privateKey: privInfo };
  }

  async importKey(attrs: HsmKeyAttributes, keyData: Buffer): Promise<HsmKeyInfo> {
    this.ensureInitialized();
    const start = Date.now();

    const info: HsmKeyInfo = {
      handle: randomBytes(4).toString("hex"),
      label: attrs.label,
      keyType: attrs.keyType,
      extractable: attrs.extractable,
      sensitive: attrs.sensitive,
      createdAt: new Date().toISOString(),
    };

    this.keys.set(attrs.label, { attrs, data: Buffer.from(keyData), createdAt: info.createdAt });
    this.log("importKey", attrs.label, true, `imported ${keyData.length} bytes`, Date.now() - start);

    return info;
  }

  async exportKey(label: string): Promise<Buffer> {
    this.ensureInitialized();
    const start = Date.now();

    const key = this.keys.get(label);
    if (!key) {
      this.log("exportKey", label, false, "key not found", Date.now() - start);
      throw new Error(`Key not found: ${label}`);
    }

    if (!key.attrs.extractable) {
      this.log("exportKey", label, false, "key is not extractable", Date.now() - start);
      throw new Error(`Key ${label} is not extractable`);
    }

    this.log("exportKey", label, true, undefined, Date.now() - start);
    return Buffer.from(key.data);
  }

  async destroyKey(label: string): Promise<boolean> {
    this.ensureInitialized();
    const start = Date.now();

    const hadKey = this.keys.delete(label) || this.keyPairs.delete(label);
    this.log("destroyKey", label, hadKey, hadKey ? "key destroyed" : "key not found", Date.now() - start);
    return hadKey;
  }

  async sign(keyLabel: string, data: Buffer): Promise<HsmSignResult> {
    this.ensureInitialized();
    const start = Date.now();

    // Check key pairs first (RSA signing)
    const pair = this.keyPairs.get(keyLabel);
    if (pair) {
      const { createPrivateKey } = await import("node:crypto");
      const privKey = createPrivateKey({ key: pair.privateKey, format: "der", type: "pkcs8" });
      const signature = sign("sha256", data, privKey);
      this.log("sign", keyLabel, true, "RSA-SHA256", Date.now() - start);
      return { signature, mechanism: "RSA-SHA256" };
    }

    // Fall back to HMAC for symmetric keys
    const key = this.keys.get(keyLabel);
    if (!key) {
      this.log("sign", keyLabel, false, "key not found", Date.now() - start);
      throw new Error(`Signing key not found: ${keyLabel}`);
    }

    const signature = createHmac("sha256", key.data).update(data).digest();
    this.log("sign", keyLabel, true, "HMAC-SHA256", Date.now() - start);
    return { signature: Buffer.from(signature), mechanism: "HMAC-SHA256" };
  }

  async verify(keyLabel: string, data: Buffer, signature: Buffer): Promise<boolean> {
    this.ensureInitialized();
    const start = Date.now();

    const pair = this.keyPairs.get(keyLabel);
    if (pair) {
      const { createPublicKey } = await import("node:crypto");
      const pubKey = createPublicKey({ key: pair.publicKey, format: "der", type: "spki" });
      const valid = verify("sha256", data, pubKey, signature);
      this.log("verify", keyLabel, true, `RSA-SHA256: ${valid}`, Date.now() - start);
      return valid;
    }

    const key = this.keys.get(keyLabel);
    if (!key) {
      this.log("verify", keyLabel, false, "key not found", Date.now() - start);
      throw new Error(`Verification key not found: ${keyLabel}`);
    }

    const expected = createHmac("sha256", key.data).update(data).digest();
    const valid = signature.length === expected.length &&
      Buffer.compare(signature, expected) === 0;
    this.log("verify", keyLabel, true, `HMAC-SHA256: ${valid}`, Date.now() - start);
    return valid;
  }

  async listKeys(): Promise<HsmKeyInfo[]> {
    this.ensureInitialized();
    const infos: HsmKeyInfo[] = [];

    for (const [label, { attrs, createdAt }] of this.keys) {
      infos.push({
        handle: "",
        label,
        keyType: attrs.keyType,
        extractable: attrs.extractable,
        sensitive: attrs.sensitive,
        createdAt,
      });
    }

    for (const [label, { attrs, createdAt }] of this.keyPairs) {
      infos.push({
        handle: "",
        label,
        keyType: attrs.keyType,
        extractable: attrs.extractable,
        sensitive: attrs.sensitive,
        createdAt,
      });
    }

    return infos;
  }

  async getKeyInfo(label: string): Promise<HsmKeyInfo | undefined> {
    this.ensureInitialized();
    const key = this.keys.get(label);
    if (key) {
      return {
        handle: "",
        label,
        keyType: key.attrs.keyType,
        extractable: key.attrs.extractable,
        sensitive: key.attrs.sensitive,
        createdAt: key.createdAt,
      };
    }
    const pair = this.keyPairs.get(label);
    if (pair) {
      return {
        handle: "",
        label,
        keyType: pair.attrs.keyType,
        extractable: pair.attrs.extractable,
        sensitive: pair.attrs.sensitive,
        createdAt: pair.createdAt,
      };
    }
    return undefined;
  }

  getOperationLog(): HsmOperationLog[] {
    return [...this.operationLog];
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error("HSM client not initialized");
    }
  }

  private log(operation: string, keyLabel: string, success: boolean, detail?: string, durationMs = 0): void {
    this.operationLog.push({ operation, keyLabel, success, durationMs, detail });
  }
}
