import Database from "better-sqlite3";
import { initSchema } from "./schema.js";

/**
 * Initialize SQLite database with WAL mode and performance pragmas.
 *
 * @param dataDir - Directory to store the database file
 * @returns Database instance ready for use
 */
export function initDatabase(dataDir: string): Database.Database {
  const dbPath = `${dataDir}/uae-re.db`;
  console.error(`[uae-re] opening database at: ${dbPath}`);

  // Try opening with explicit options
  const db = new Database(dbPath, {
    readonly: false,
    fileMustExist: false,
    timeout: 5000,
    verbose: (...args: unknown[]) => console.error(`[sqlite]`, ...args)
  });
  console.error(`[uae-re] database opened successfully`);

  // Set performance pragmas
  console.error(`[uae-re] setting WAL mode`);
  try {
    const result = db.pragma("journal_mode = WAL", { simple: true });
    console.error(`[uae-re] WAL mode result: ${result}`);
  } catch (err) {
    console.error(`[uae-re] WAL pragma failed:`, err);
    throw err;
  }
  console.error(`[uae-re] WAL mode set`);
  db.pragma("synchronous = NORMAL");
  db.pragma("cache_size = -64000"); // 64MB cache
  db.pragma("temp_store = MEMORY");
  console.error(`[uae-re] all pragmas set`);

  // Initialize schema
  initSchema(db);
  console.error(`[uae-re] schema initialized`);

  return db;
}

/**
 * Close database connection cleanly.
 *
 * @param db - Database instance to close
 */
export function closeDatabase(db: Database.Database): void {
  db.close();
}
