/** Credential types stored in HSM */
export type CredentialType =
  | "llm-api-key"
  | "channel-token"
  | "webhook-secret"
  | "gateway-auth-token"
  | "proxy-internal-token"
  | "tls-private-key"
  | "audit-signing-key"
  | "fscrypt-master-key"
  | "internal-ca-key"
  | "external-ca-key";

/** Injection method for a credential */
export type InjectionMethod = "env" | "tmpfs-file" | "hsm-only" | "kernel" | "fscrypt-dir";

/** Credential metadata (never contains the actual value) */
export interface CredentialMeta {
  label: string;
  type: CredentialType;
  extractable: boolean;
  sensitive: boolean;
  injectionMethod: InjectionMethod;
  rotationDays: number;
  createdAt: string;
  expiresAt?: string;
}

/** Default rotation schedules in days */
export const ROTATION_SCHEDULES: Record<CredentialType, number> = {
  "llm-api-key": 90,
  "channel-token": 90,
  "webhook-secret": 180,
  "gateway-auth-token": 30,
  "proxy-internal-token": 30,
  "tls-private-key": 365,
  "audit-signing-key": 365,
  "fscrypt-master-key": 365,
  "internal-ca-key": 365,
  "external-ca-key": 365,
};
