// @lobsec/plugin -- plugin entry point
export {
  HookRegistry,
  createDefaultRegistry,
  LOBSEC_HOOKS,
} from "./hook-registry.js";

export type {
  HookName,
  HookPriority,
  HookHandler,
  HookContext,
  HookAction,
  HookResult,
  HookRegistration,
  HookEvent,
} from "./hook-registry.js";

export { ConfigMonitor } from "./config-monitor.js";

export type {
  MonitorConfig,
  AlertSeverity,
  MonitorAlert,
  MonitorStatus,
} from "./config-monitor.js";

export {
  ToolValidator,
  validatePath,
  validateSymlink,
  isToolDenied,
  validateCommandConsistency,
  checkDangerousCommand,
  DEFAULT_DANGEROUS_PATTERNS,
} from "./tool-validator.js";

export type {
  ToolCallRequest,
  ValidationAction,
  ValidationResult,
  ToolValidatorConfig,
} from "./tool-validator.js";

export {
  CredentialRedactor,
  CREDENTIAL_PATTERNS,
  PII_PATTERNS,
  ALL_PATTERNS,
} from "./credential-redactor.js";

export type {
  RedactionPattern,
  RedactionResult,
  RedactionEvent,
} from "./credential-redactor.js";

export { SovereignRouter } from "./sovereign-router.js";

export type {
  RoutingMode,
  SovereignBackendConfig,
  RoutingDecision,
  SessionState,
  RouterConfig,
  RoutingEvent,
} from "./sovereign-router.js";
