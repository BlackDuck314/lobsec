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
  // Phase 7 Tier A
  "dld-sales": "normalize_dld",
  "ejari-rentals": "normalize_ejari",
  "building-permits": "normalize_permits",
  "adrec-abu-dhabi": "normalize_adrec",
  "bayut-listings": "normalize_bayut",
  "propertyfinder-listings": "normalize_propertyfinder",
  "dewa-connections": "normalize_dewa",

  // Phase 8 Tier B — Government/Institutional
  "mohre-permits": "normalize_mohre",
  "dxb-passengers": "normalize_dxb",
  "gdrfa-visas": "normalize_gdrfa",
  "khda-enrollment": "normalize_khda",
  "rta-vehicles": "normalize_rta",
  "cbuae-remittances": "normalize_remittances",

  // Phase 8 Tier B — Job platforms (all use normalize_jobs with platform detection)
  "linkedin-jobs": "normalize_jobs",
  "bayt-jobs": "normalize_jobs",
  "indeed-jobs": "normalize_jobs",
  "gulftalent-jobs": "normalize_jobs",

  // Phase 8 Tier B — Salary surveys (all use normalize_salary with firm detection)
  "cooper-fitch-salary": "normalize_salary",
  "hays-salary": "normalize_salary",
  "roberthalf-salary": "normalize_salary",

  // Phase 9 Tier C
  "google-trends": "normalize_trends",          // COLL-14 + COLL-27 (moving keywords)
  "reddit-sentiment": "normalize_sentiment",    // COLL-24
  "rta-metro": "normalize_metro",               // COLL-16
  "cbuae-mortgages": "normalize_mortgages",     // COLL-17
  "dtcm-tourism": "normalize_tourism",          // COLL-18
  "insideairbnb": "normalize_airbnb",           // COLL-19
  "jebel-ali-port": "normalize_port",           // COLL-20
  "fb-closures": "normalize_fb_closures",       // COLL-21
  "customs-imports": "normalize_customs",       // COLL-22
  "ded-licenses": "normalize_licenses",         // COLL-23
  "fcsa-demographics": "normalize_demographics", // COLL-25
  "google-maps-traffic": "normalize_foot_traffic", // COLL-26
  "commercial-office-reports": "normalize_office", // COLL-28
};
