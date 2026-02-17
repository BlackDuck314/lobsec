// ── PKCS#11 Tool Client ─────────────────────────────────────────────────────
// IHsmClient implementation that shells out to pkcs11-tool for HSM operations.
// Pragmatic approach for SoftHSM2 deployments — no native bindings required.
// Can be replaced with graphene-pk11 for higher throughput.

import { execFile } from "node:child_process";
import { writeFile, unlink, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type {
  IHsmClient,
  HsmKeyAttributes,
  HsmKeyInfo,
  HsmSignResult,
  HsmOperationLog,
} from "./hsm-client.js";

// ── Helpers ────────────────────────────────────────────────────────────────

function exec(cmd: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) reject(Object.assign(err, { stderr }));
      else resolve({ stdout, stderr });
    });
  });
}

async function tmpFile(prefix: string, data: Buffer): Promise<string> {
  const path = join(tmpdir(), `lobsec-${prefix}-${randomBytes(4).toString("hex")}`);
  await writeFile(path, data, { mode: 0o600 });
  return path;
}

// ── Client ─────────────────────────────────────────────────────────────────

export class Pkcs11ToolClient implements IHsmClient {
  private modulePath = "";
  private tokenLabel = "";
  private pin = "";
  private _initialized = false;
  private operationLog: HsmOperationLog[] = [];

  get isInitialized(): boolean {
    return this._initialized;
  }

  async initialize(modulePath: string, _slotIndex: number, pin: string): Promise<void> {
    this.modulePath = modulePath;
    this.pin = pin;
    // Derive token label from environment (default to "lobsec")
    this.tokenLabel = process.env["LOBSEC_HSM_TOKEN_LABEL"] ?? "lobsec";
    this._initialized = true;
    this.log("initialize", "session", true, "pkcs11-tool client ready");
  }

  async finalize(): Promise<void> {
    this._initialized = false;
    this.log("finalize", "session", true);
  }

  async sign(keyLabel: string, data: Buffer): Promise<HsmSignResult> {
    this.ensureInit();
    const start = Date.now();
    const inputPath = await tmpFile("sign-in", data);
    const outputPath = inputPath + ".sig";

    try {
      await exec("pkcs11-tool", [
        "--module", this.modulePath,
        "--token-label", this.tokenLabel,
        "--login", "--pin", this.pin,
        "--sign",
        "--mechanism", "RSA-PKCS",
        "--label", keyLabel,
        "--input-file", inputPath,
        "--output-file", outputPath,
      ]);

      const signature = await readFile(outputPath);
      this.log("sign", keyLabel, true, "RSA-PKCS", Date.now() - start);
      return { signature, mechanism: "RSA-PKCS" };
    } catch (err) {
      this.log("sign", keyLabel, false, String(err), Date.now() - start);
      throw err;
    } finally {
      await unlink(inputPath).catch(() => {});
      await unlink(outputPath).catch(() => {});
    }
  }

  async verify(keyLabel: string, data: Buffer, signature: Buffer): Promise<boolean> {
    this.ensureInit();
    const start = Date.now();
    const inputPath = await tmpFile("verify-in", data);
    const sigPath = await tmpFile("verify-sig", signature);

    try {
      await exec("pkcs11-tool", [
        "--module", this.modulePath,
        "--token-label", this.tokenLabel,
        "--login", "--pin", this.pin,
        "--verify",
        "--mechanism", "RSA-PKCS",
        "--label", keyLabel,
        "--input-file", inputPath,
        "--signature-file", sigPath,
      ]);

      this.log("verify", keyLabel, true, "RSA-PKCS: valid", Date.now() - start);
      return true;
    } catch {
      this.log("verify", keyLabel, true, "RSA-PKCS: invalid", Date.now() - start);
      return false;
    } finally {
      await unlink(inputPath).catch(() => {});
      await unlink(sigPath).catch(() => {});
    }
  }

  async getKeyInfo(label: string): Promise<HsmKeyInfo | undefined> {
    this.ensureInit();
    try {
      const { stdout } = await exec("pkcs11-tool", [
        "--module", this.modulePath,
        "--token-label", this.tokenLabel,
        "--login", "--pin", this.pin,
        "--list-objects",
        "--type", "privkey",
      ]);

      if (stdout.includes(`label:      ${label}`)) {
        return {
          handle: "pkcs11",
          label,
          keyType: "rsa-2048",
          extractable: false,
          sensitive: true,
          createdAt: "unknown",
        };
      }
      return undefined;
    } catch {
      return undefined;
    }
  }

  async listKeys(): Promise<HsmKeyInfo[]> {
    this.ensureInit();
    try {
      const { stdout } = await exec("pkcs11-tool", [
        "--module", this.modulePath,
        "--token-label", this.tokenLabel,
        "--login", "--pin", this.pin,
        "--list-objects",
      ]);

      const keys: HsmKeyInfo[] = [];
      const blocks = stdout.split(/\n(?=\w)/);
      for (const block of blocks) {
        const labelMatch = block.match(/label:\s+'?([^'\n]+)/);
        if (labelMatch) {
          keys.push({
            handle: "pkcs11",
            label: labelMatch[1]!.trim(),
            keyType: block.includes("RSA") ? "rsa-2048" : "generic-secret",
            extractable: !block.includes("never extractable"),
            sensitive: block.includes("sensitive"),
            createdAt: "unknown",
          });
        }
      }
      return keys;
    } catch {
      return [];
    }
  }

  // ── Not implemented (not needed for audit signing) ─────────────────────

  async generateKey(_attrs: HsmKeyAttributes): Promise<HsmKeyInfo> {
    throw new Error("Use pkcs11-tool CLI directly for key generation");
  }

  async generateKeyPair(_attrs: HsmKeyAttributes): Promise<{ publicKey: HsmKeyInfo; privateKey: HsmKeyInfo }> {
    throw new Error("Use pkcs11-tool CLI directly for key generation");
  }

  async importKey(_attrs: HsmKeyAttributes, _keyData: Buffer): Promise<HsmKeyInfo> {
    throw new Error("Use pkcs11-tool CLI directly for key import");
  }

  async exportKey(_label: string): Promise<Buffer> {
    throw new Error("Audit signing keys are non-extractable");
  }

  async destroyKey(_label: string): Promise<boolean> {
    throw new Error("Use pkcs11-tool CLI directly for key destruction");
  }

  getOperationLog(): HsmOperationLog[] {
    return [...this.operationLog];
  }

  private ensureInit(): void {
    if (!this._initialized) throw new Error("Pkcs11ToolClient not initialized");
  }

  private log(op: string, label: string, success: boolean, detail?: string, durationMs = 0): void {
    this.operationLog.push({ operation: op, keyLabel: label, success, durationMs, detail });
  }
}
