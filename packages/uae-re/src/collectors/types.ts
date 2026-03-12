/**
 * Collector Framework Types
 *
 * Type definitions for the collector framework, including metadata,
 * execution results, status tracking, and registry outcomes.
 */

/**
 * Collection frequency for scheduling.
 */
export type CollectionFrequency = "daily" | "weekly" | "monthly" | "quarterly";

/**
 * Metadata describing a collector's execution characteristics.
 */
export interface CollectorMetadata {
  /** Unique source identifier. */
  source: string;
  /** Collection frequency for scheduling. */
  frequency: CollectionFrequency;
  /** Priority (1=highest). Lower numbers run first. */
  priority: number;
  /** Timeout in milliseconds. */
  timeout: number;
}

/**
 * Result of a single collection execution.
 */
export interface CollectionResult {
  /** Whether collection succeeded. */
  success: boolean;
  /** Number of rows collected (if successful). */
  rowCount?: number;
  /** File path where data was saved (if successful). */
  filePath?: string;
  /** Error message (if failed). */
  error?: string;
  /** Duration in milliseconds. */
  duration: number;
}

/**
 * Current operational status of a collector.
 */
export type CollectorStatus = "idle" | "running" | "stale" | "failed";

/**
 * Information about a collector's current state.
 */
export interface CollectorInfo {
  /** Collector metadata. */
  metadata: CollectorMetadata;
  /** Current status. */
  status: CollectorStatus;
  /** Last successful run timestamp (ISO 8601). */
  lastRun?: string;
  /** Number of consecutive failures. */
  consecutiveFailures: number;
}

/**
 * Result of running multiple collectors via the registry.
 */
export interface RegistryRunResult {
  /** Individual collector results by source name. */
  results: Map<string, CollectionResult>;
  /** Total duration in milliseconds. */
  totalDuration: number;
  /** Number of successful collections. */
  successCount: number;
  /** Number of failed collections. */
  failureCount: number;
}

/**
 * Configuration for connecting to the Ninja Scraper HTTP API.
 */
export interface ScraperApiConfig {
  /** Ninja Scraper API base URL. */
  baseUrl: string;
  /** Bearer token for authentication. */
  authToken: string;
  /** Polling interval for background jobs (ms). */
  pollIntervalMs: number;
  /** Maximum wait time for job completion (ms). */
  maxWaitMs: number;
}
