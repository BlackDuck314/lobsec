import type Database from "better-sqlite3";

/**
 * Initialize database schema with all tables and indices.
 *
 * Creates 11 tables:
 * - raw_sources: Metadata for collected raw data files
 * - normalized_monthly: Monthly-normalized time-series data
 * - intelligence_cache: TTL-based cache for intelligence products
 * - collection_log: Audit log for collection runs
 * - area_names: Canonical area name mapping for normalization
 * - stationarity_results: ADF+KPSS stationarity test results per source/metric
 * - granger_results: Granger causality test results with Bonferroni correction
 * - composite_scores: Composite index values per area
 * - anomaly_flags: EWMA anomaly detections
 * - analysis_log: Audit trail for pipeline runs (metadata only, no PII)
 * - validation_results: Out-of-sample Granger validation outcomes (QUAL-01)
 *
 * @param db - Database instance
 */
export function initSchema(db: Database.Database): void {
  // Table 1: Area name mapping
  db.exec(`
    CREATE TABLE IF NOT EXISTS area_names (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      canonical_name TEXT NOT NULL UNIQUE,
      emirate TEXT NOT NULL CHECK(emirate IN ('dubai', 'abu_dhabi')),
      aliases TEXT,
      source_variants TEXT
    )
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_area_canonical
      ON area_names(canonical_name)
  `);

  // Table 2: Raw source metadata
  db.exec(`
    CREATE TABLE IF NOT EXISTS raw_sources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      file_path TEXT NOT NULL,
      collected_at TEXT NOT NULL,
      row_count INTEGER,
      file_size_bytes INTEGER,
      checksum TEXT
    )
  `);

  // Table 3: Normalized monthly data
  db.exec(`
    CREATE TABLE IF NOT EXISTS normalized_monthly (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      measurement_date TEXT NOT NULL,
      metric_name TEXT NOT NULL,
      value REAL,
      available_date TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Table 4: Intelligence cache
  db.exec(`
    CREATE TABLE IF NOT EXISTS intelligence_cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cache_key TEXT UNIQUE NOT NULL,
      product TEXT NOT NULL,
      params_hash TEXT NOT NULL,
      result_json TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL
    )
  `);

  // Table 5: Collection log
  db.exec(`
    CREATE TABLE IF NOT EXISTS collection_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      status TEXT NOT NULL,
      row_count INTEGER,
      duration_ms INTEGER,
      error TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Indices for query performance
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_normalized_source_date
      ON normalized_monthly(source, measurement_date)
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_cache_key_expiry
      ON intelligence_cache(cache_key, expires_at)
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_collection_source_timestamp
      ON collection_log(source, timestamp)
  `);

  // Table 6: Stationarity test results
  db.exec(`
    CREATE TABLE IF NOT EXISTS stationarity_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      metric_name TEXT NOT NULL,
      adf_statistic REAL,
      adf_pvalue REAL,
      kpss_statistic REAL,
      kpss_pvalue REAL,
      verdict TEXT NOT NULL CHECK(verdict IN ('stationary', 'non-stationary', 'inconclusive')),
      differenced INTEGER NOT NULL DEFAULT 0,
      obs_count INTEGER,
      tested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_stationarity_source
      ON stationarity_results(source, metric_name, tested_at)
  `);

  // Table 7: Granger causality results
  db.exec(`
    CREATE TABLE IF NOT EXISTS granger_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      signal_source TEXT NOT NULL,
      signal_metric TEXT NOT NULL,
      target TEXT NOT NULL CHECK(target IN ('dld_price', 'dld_volume')),
      best_lag INTEGER,
      f_statistic REAL,
      pvalue REAL,
      bonferroni_alpha REAL,
      significant INTEGER NOT NULL DEFAULT 0,
      weight REAL,
      tested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_granger_signal_target
      ON granger_results(signal_source, target, tested_at)
  `);

  // Table 8: Composite index scores
  db.exec(`
    CREATE TABLE IF NOT EXISTS composite_scores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      area TEXT NOT NULL,
      score REAL NOT NULL,
      zone TEXT NOT NULL CHECK(zone IN ('strong_sell', 'neutral', 'strong_buy')),
      component_count INTEGER NOT NULL,
      total_components INTEGER NOT NULL,
      components_json TEXT,
      computed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_composite_area_date
      ON composite_scores(area, computed_at)
  `);

  // Table 9: Anomaly flags
  db.exec(`
    CREATE TABLE IF NOT EXISTS anomaly_flags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      metric_name TEXT NOT NULL,
      measurement_date TEXT NOT NULL,
      value REAL,
      z_score REAL,
      flagged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Table 10: Analysis pipeline audit log (metadata only — no PII per SEC-07)
  // 'in_progress' is used as intermediate state during step execution;
  // updated to 'success' or 'failed' on completion (or 'skipped' for dependency-gated steps).
  db.exec(`
    CREATE TABLE IF NOT EXISTS analysis_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_step TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('in_progress', 'success', 'failed', 'skipped')),
      signals_processed INTEGER,
      signals_skipped INTEGER,
      duration_ms INTEGER,
      error TEXT,
      run_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Table 11: Out-of-sample validation results (QUAL-01)
  // Chronological 70/30 split of Granger-significant signals.
  // downweight_factor = 0.5 for signals that fail out-of-sample validation;
  // downweight_factor = 1.0 for validated signals (or signals with < 12 obs, skipped).
  db.exec(`
    CREATE TABLE IF NOT EXISTS validation_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      signal_source TEXT NOT NULL,
      signal_metric TEXT NOT NULL,
      target TEXT NOT NULL,
      train_obs INTEGER NOT NULL,
      test_obs INTEGER NOT NULL,
      train_significant INTEGER NOT NULL,
      test_significant INTEGER NOT NULL,
      validated INTEGER NOT NULL,
      downweight_factor REAL NOT NULL DEFAULT 1.0,
      tested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_validation_signal
      ON validation_results(signal_source, signal_metric, target, tested_at)
  `);
}
