/** lobsec's own configuration */
export interface LobsecConfig {
  version: string;

  hsm: {
    module: string;
    slot: number;
    pinFile?: string;
  };

  tls: {
    mode: "self-signed" | "acme" | "custom";
    domain?: string;
    acme?: AcmeConfig;
    custom?: CustomTlsConfig;
  };

  encryption: {
    luks: { enabled: boolean; device: string; unlockMethod: LuksUnlockMethod };
    fscrypt: { enabled: boolean; directories: string[] };
  };

  sovereign: {
    backends: SovereignBackend[];
    channelDefaults: Record<string, "sovereign" | "public">;
    budgetThresholds: { warning: number; critical: number; fallback: number };
  };

  egress: {
    allowlist: EgressRule[];
    denylist: string[];
  };

  audit: {
    logPath: string;
    hashChain: boolean;
    hsmSigning: boolean;
    attackClassTagging: boolean;
    retentionDays: number;
  };

  monitoring: {
    driftCheckIntervalMinutes: number;
    certExpiryAlertDays: number[];
    alertWebhooks: AlertWebhook[];
  };
}

export type LuksUnlockMethod = "passphrase" | "tpm2" | "tang" | "ssh";

export interface AcmeConfig {
  provider: "letsencrypt" | "zerossl" | "buypass" | "custom";
  email: string;
  challenge: "http-01" | "dns-01" | "tls-alpn-01";
  dnsProvider?: string;
  caUrl?: string;
}

export interface CustomTlsConfig {
  certPath: string;
  keyPath: string;
  chainPath: string;
  keyInHsm: boolean;
}

export interface SovereignBackend {
  name: string;
  type: "ollama" | "llama-cpp" | "vllm";
  url: string;
  tls?: { enabled: boolean; ca?: string; pinSha256?: string };
  wireguard?: { enabled: boolean; iface: string };
  models: string[];
}

export interface EgressRule {
  host: string;
  ports: number[];
  protocol: "http" | "https" | "tcp";
}

export interface AlertWebhook {
  type: "slack" | "discord" | "email" | "custom";
  url: string;
  severity: "critical" | "high" | "medium" | "low";
}
