/**
 * Normalization Pipeline Types
 *
 * Type definitions for the normalization orchestrator, gap detection,
 * and volume validation.
 */

import type { CollectionFrequency } from "../collectors/types.js";

/**
 * Input to normalization process.
 */
export interface NormalizationInput {
  /** Path to collected raw data file. */
  filePath: string;
  /** Data source identifier. */
  source: string;
  /** Collection timestamp (ISO 8601). */
  collectedAt: string;
}

/**
 * Result of normalization process.
 */
export interface NormalizationResult {
  /** Data source identifier. */
  source: string;
  /** Number of records normalized and inserted. */
  recordCount: number;
  /** Date range of measurement_date values in normalized data. */
  measurementDateRange: { start: string; end: string };
  /** Gap warnings (empty if no gaps detected). */
  gapWarnings: GapWarning[];
  /** Volume warning (undefined if validation passed or skipped). */
  volumeWarning?: VolumeWarning;
}

/**
 * Warning about data collection gap.
 */
export interface GapWarning {
  /** Data source identifier. */
  source: string;
  /** Last successful collection date. */
  lastDate: string;
  /** Expected collection frequency. */
  expectedFrequency: CollectionFrequency;
  /** Number of days since last collection. */
  gapDays: number;
  /** True if gap exceeds 2x expected frequency (marked STALE). */
  isStale: boolean;
}

/**
 * Warning about abnormal data volume.
 */
export interface VolumeWarning {
  /** Data source identifier. */
  source: string;
  /** Current collection row count. */
  currentCount: number;
  /** Rolling average from last N collections. */
  rollingAverage: number;
  /** Ratio: currentCount / rollingAverage. */
  ratio: number;
}

/**
 * Normalized record returned from Python normalization module.
 */
export interface NormalizedRecord {
  /** Data source identifier. */
  source: string;
  /** Measurement date (YYYY-MM-DD, typically month start). */
  measurement_date: string;
  /** Metric name (e.g., "median_price_aed", "transaction_count"). */
  metric_name: string;
  /** Metric value. */
  value: number;
  /** Date when this data became available (YYYY-MM-DD). */
  available_date: string;
}

/**
 * Map source name to Python normalization module.
 * Used by orchestrator to call correct per-source normalization script.
 */
export const SOURCE_MODULE_MAP: Record<string, string> = {
  "dld-sales": "normalize_dld",
  "ejari-rentals": "normalize_ejari",
  "building-permits": "normalize_permits",
  "adrec-abu-dhabi": "normalize_adrec",
  "bayut-listings": "normalize_bayut",
  "propertyfinder-listings": "normalize_propertyfinder",
  "dewa-connections": "normalize_dewa",
};
