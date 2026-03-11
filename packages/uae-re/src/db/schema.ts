import type Database from "better-sqlite3";

/**
 * Initialize database schema with all tables and indices.
 *
 * Creates 5 tables:
 * - raw_sources: Metadata for collected raw data files
 * - normalized_monthly: Monthly-normalized time-series data
 * - intelligence_cache: TTL-based cache for intelligence products
 * - collection_log: Audit log for collection runs
 * - area_names: Canonical area name mapping for normalization
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
}
