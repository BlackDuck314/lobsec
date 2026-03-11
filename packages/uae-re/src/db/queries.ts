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

/**
 * Area name entry.
 */
export interface AreaEntry {
  canonicalName: string;
  emirate: "dubai" | "abu_dhabi";
  aliases?: string[];
  sourceVariants?: string[];
}

/**
 * Insert area name mapping entry.
 */
export function insertArea(
  db: Database.Database,
  entry: AreaEntry
): void {
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO area_names (canonical_name, emirate, aliases, source_variants)
    VALUES (?, ?, ?, ?)
  `);

  stmt.run(
    entry.canonicalName,
    entry.emirate,
    entry.aliases ? JSON.stringify(entry.aliases) : null,
    entry.sourceVariants ? JSON.stringify(entry.sourceVariants) : null
  );
}

/**
 * Get canonical area name by searching canonical names, aliases, and source variants.
 */
export function getCanonicalName(
  db: Database.Database,
  rawName: string
): string | null {
  const normalized = rawName.trim().toUpperCase();

  // Check canonical name
  const directStmt = db.prepare(`
    SELECT canonical_name
    FROM area_names
    WHERE UPPER(canonical_name) = ?
  `);

  const directMatch = directStmt.get(normalized) as
    | { canonical_name: string }
    | undefined;

  if (directMatch) {
    return directMatch.canonical_name;
  }

  // Check aliases
  const aliasStmt = db.prepare(`
    SELECT canonical_name, aliases
    FROM area_names
    WHERE aliases IS NOT NULL
  `);

  const aliasRows = aliasStmt.all() as Array<{
    canonical_name: string;
    aliases: string;
  }>;

  for (const row of aliasRows) {
    const aliases: string[] = JSON.parse(row.aliases);
    if (aliases.some((alias) => alias.toUpperCase() === normalized)) {
      return row.canonical_name;
    }
  }

  // Check source variants
  const variantStmt = db.prepare(`
    SELECT canonical_name, source_variants
    FROM area_names
    WHERE source_variants IS NOT NULL
  `);

  const variantRows = variantStmt.all() as Array<{
    canonical_name: string;
    source_variants: string;
  }>;

  for (const row of variantRows) {
    const variants: string[] = JSON.parse(row.source_variants);
    if (variants.some((variant) => variant.toUpperCase() === normalized)) {
      return row.canonical_name;
    }
  }

  return null;
}

/**
 * Get all areas, optionally filtered by emirate.
 */
export function getAllAreas(
  db: Database.Database,
  emirate?: "dubai" | "abu_dhabi"
): Array<{ canonicalName: string; emirate: string }> {
  let stmt: Database.Statement;

  if (emirate) {
    stmt = db.prepare(`
      SELECT canonical_name, emirate
      FROM area_names
      WHERE emirate = ?
      ORDER BY canonical_name ASC
    `);
  } else {
    stmt = db.prepare(`
      SELECT canonical_name, emirate
      FROM area_names
      ORDER BY canonical_name ASC
    `);
  }

  const rows = (
    emirate ? stmt.all(emirate) : stmt.all()
  ) as Array<{ canonical_name: string; emirate: string }>;

  return rows.map((row) => ({
    canonicalName: row.canonical_name,
    emirate: row.emirate,
  }));
}

/**
 * Add alias to existing area.
 */
export function addAreaAlias(
  db: Database.Database,
  canonicalName: string,
  alias: string
): void {
  const stmt = db.prepare(`
    SELECT aliases
    FROM area_names
    WHERE canonical_name = ?
  `);

  const row = stmt.get(canonicalName) as { aliases: string | null } | undefined;

  if (!row) {
    throw new Error(`Area not found: ${canonicalName}`);
  }

  const aliases: string[] = row.aliases ? JSON.parse(row.aliases) : [];
  if (!aliases.includes(alias)) {
    aliases.push(alias);
  }

  const updateStmt = db.prepare(`
    UPDATE area_names
    SET aliases = ?
    WHERE canonical_name = ?
  `);

  updateStmt.run(JSON.stringify(aliases), canonicalName);
}

/**
 * Delete normalized data within a date range (for upsert).
 */
export function deleteNormalizedRange(
  db: Database.Database,
  source: string,
  startDate: string,
  endDate: string
): void {
  const stmt = db.prepare(`
    DELETE FROM normalized_monthly
    WHERE source = ? AND measurement_date >= ? AND measurement_date <= ?
  `);

  stmt.run(source, startDate, endDate);
}
