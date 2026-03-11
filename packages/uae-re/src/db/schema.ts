import type Database from "better-sqlite3";

/**
 * Initialize database schema with all tables and indices.
 *
 * Creates 4 tables:
 * - raw_sources: Metadata for collected raw data files
 * - normalized_monthly: Monthly-normalized time-series data
 * - intelligence_cache: TTL-based cache for intelligence products
 * - collection_log: Audit log for collection runs
 *
 * @param db - Database instance
 */
export function initSchema(db: Database.Database): void {
  // Table 1: Raw source metadata
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

  // Table 2: Normalized monthly data
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

  // Table 3: Intelligence cache
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

  // Table 4: Collection log
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
