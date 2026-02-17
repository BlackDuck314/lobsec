// @lobsec/proxy -- proxy server entry point
export { CredentialStore } from "./credential-store.js";
export type { CredentialEntry, CredentialAccessCallback } from "./credential-store.js";

export {
  validateTelegram,
  validateSlack,
  validateDiscord,
  validateTwilio,
  validateWhatsApp,
  isTimestampFresh,
  validateStartupGate,
  MAX_WEBHOOK_AGE_MS,
} from "./webhook-validator.js";

export type {
  ChannelType,
  WebhookValidationResult,
  WebhookRequest,
  ChannelConfig,
} from "./webhook-validator.js";

export {
  isPrivateIp,
  isMetadataIp,
  isIPv4MappedIPv6,
  checkEgress,
  DEFAULT_ALLOWLIST,
  METADATA_IPS,
} from "./egress-firewall.js";

export type {
  EgressRule,
  EgressCheckResult,
} from "./egress-firewall.js";

export {
  detectProvider,
  estimateTokens,
  extractModel,
  validateProxyToken,
  routeRequest,
} from "./llm-router.js";

export type {
  LlmRequest,
  LlmRouteResult,
  LlmAuditEntry,
} from "./llm-router.js";

export { CredentialManager, DEFAULT_CREDENTIAL_SPECS } from "./credential-manager.js";

export type {
  CredentialSpec,
  CredentialManagerConfig,
  CredentialLifecycleEvent,
} from "./credential-manager.js";

export { BackendManager } from "./backend-manager.js";

export { createProxyServer, startProxyFromEnv } from "./server.js";
export type { ProxyServerConfig } from "./server.js";

export type {
  BackendType,
  BackendConfig,
  BackendHealth,
  BudgetConfig,
  BudgetAction,
  BudgetCheckResult,
  RoutingRequest,
  RoutingResult,
  BackendManagerConfig,
  BackendEvent,
} from "./backend-manager.js";
