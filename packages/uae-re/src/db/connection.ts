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
  const db = new Database(dbPath);

  // Set performance pragmas
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("cache_size = -64000"); // 64MB cache
  db.pragma("temp_store = MEMORY");

  // Initialize schema
  initSchema(db);

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
