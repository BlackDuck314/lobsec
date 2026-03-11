import type Database from "better-sqlite3";

/**
 * Monthly data point in normalized_monthly table.
 */
export interface MonthlyDataPoint {
  source: string;
  measurementDate: string;
  metricName: string;
  value: number;
  availableDate: string;
}

/**
 * Raw source entry in raw_sources table.
 */
export interface RawSourceEntry {
  source: string;
  filePath: string;
  collectedAt: string;
  rowCount?: number;
  fileSizeBytes?: number;
  checksum?: string;
}

/**
 * Collection log entry.
 */
export interface CollectionLogEntry {
  id?: number;
  source: string;
  status: string;
  rowCount?: number;
  durationMs?: number;
  error?: string;
  timestamp?: string;
}

/**
 * Insert raw source metadata.
 */
export function insertRawSource(
  db: Database.Database,
  entry: RawSourceEntry
): void {
  const stmt = db.prepare(`
    INSERT INTO raw_sources (source, file_path, collected_at, row_count, file_size_bytes, checksum)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    entry.source,
    entry.filePath,
    entry.collectedAt,
    entry.rowCount ?? null,
    entry.fileSizeBytes ?? null,
    entry.checksum ?? null
  );
}

/**
 * Bulk insert normalized monthly data (transaction).
 */
export function insertNormalized(
  db: Database.Database,
  rows: MonthlyDataPoint[]
): void {
  const stmt = db.prepare(`
    INSERT INTO normalized_monthly (source, measurement_date, metric_name, value, available_date)
    VALUES (?, ?, ?, ?, ?)
  `);

  const insertMany = db.transaction((data: MonthlyDataPoint[]) => {
    for (const row of data) {
      stmt.run(
        row.source,
        row.measurementDate,
        row.metricName,
        row.value,
        row.availableDate
      );
    }
  });

  insertMany(rows);
}

/**
 * Query normalized data by source and date range.
 */
export function queryNormalized(
  db: Database.Database,
  source: string,
  startDate: string,
  endDate: string
): MonthlyDataPoint[] {
  const stmt = db.prepare(`
    SELECT source, measurement_date, metric_name, value, available_date
    FROM normalized_monthly
    WHERE source = ? AND measurement_date >= ? AND measurement_date <= ?
    ORDER BY measurement_date ASC
  `);

  const rows = stmt.all(source, startDate, endDate) as Array<{
    source: string;
    measurement_date: string;
    metric_name: string;
    value: number;
    available_date: string;
  }>;

  return rows.map((row) => ({
    source: row.source,
    measurementDate: row.measurement_date,
    metricName: row.metric_name,
    value: row.value,
    availableDate: row.available_date,
  }));
}

/**
 * Insert collection log entry.
 */
export function insertCollectionLog(
  db: Database.Database,
  entry: Omit<CollectionLogEntry, "id" | "timestamp">
): void {
  const stmt = db.prepare(`
    INSERT INTO collection_log (source, status, row_count, duration_ms, error)
    VALUES (?, ?, ?, ?, ?)
  `);

  stmt.run(
    entry.source,
    entry.status,
    entry.rowCount ?? null,
    entry.durationMs ?? null,
    entry.error ?? null
  );
}

/**
 * Get latest collection log entry for a source.
 */
export function getLatestCollection(
  db: Database.Database,
  source: string
): CollectionLogEntry | undefined {
  const stmt = db.prepare(`
    SELECT id, source, status, row_count, duration_ms, error, timestamp
    FROM collection_log
    WHERE source = ?
    ORDER BY timestamp DESC
    LIMIT 1
  `);

  const row = stmt.get(source) as
    | {
        id: number;
        source: string;
        status: string;
        row_count: number | null;
        duration_ms: number | null;
        error: string | null;
        timestamp: string;
      }
    | undefined;

  if (!row) {
    return undefined;
  }

  return {
    id: row.id,
    source: row.source,
    status: row.status,
    rowCount: row.row_count ?? undefined,
    durationMs: row.duration_ms ?? undefined,
    error: row.error ?? undefined,
    timestamp: row.timestamp,
  };
}
