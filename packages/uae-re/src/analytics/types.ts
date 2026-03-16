/**
 * Python Bridge Types
 *
 * Type definitions for the TypeScript-to-Python subprocess bridge.
 */

/**
 * Result of a Python subprocess execution.
 */
export interface PythonResult<T> {
  /** Whether the execution succeeded. */
  success: boolean;
  /** Parsed JSON output from stdout (if successful). */
  data?: T;
  /** Error message (if failed). */
  error?: string;
  /** Python stderr output (logs, warnings). */
  stderr?: string;
  /** Process exit code (if available). */
  exitCode?: number;
  /** Execution duration in milliseconds. */
  durationMs: number;
}

/**
 * Python script names mapped to modules in python/uae_re/.
 */
export type PythonScriptName =
  | "normalize"
  | "stationarity"
  | "granger"
  | "correlation"
  | "normalize_dld"
  | "normalize_ejari"
  | "normalize_permits"
  | "normalize_adrec"
  | "normalize_bayut"
  | "normalize_propertyfinder"
  | "normalize_dewa"
  | "normalize_mohre"
  | "normalize_dxb"
  | "normalize_gdrfa"
  | "normalize_khda"
  | "normalize_rta"
  | "normalize_remittances"
  | "normalize_jobs"
  | "normalize_salary"
  | "collect_trends"
  | "collect_sentiment";

/**
 * Configuration for the Python subprocess bridge.
 */
export interface BridgeConfig {
  /** Path to Python virtual environment. */
  venvPath: string;
  /** Path to the Python package directory (parent of uae_re package). */
  pythonPkgDir: string;
  /** Default timeout in milliseconds. */
  defaultTimeoutMs: number;
}
