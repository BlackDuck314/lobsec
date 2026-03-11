/**
 * @lobsec/uae-re - UAE Real Estate Intelligence System
 *
 * Provides data collection, normalization, statistical analysis, and
 * intelligence products for UAE real estate market monitoring.
 *
 * This is the foundation package. Full plugin registration happens in Plan 03.
 */

// Database layer
export { initDatabase, closeDatabase } from "./db/connection.js";
export { initSchema } from "./db/schema.js";
export {
  insertRawSource,
  insertNormalized,
  queryNormalized,
  insertCollectionLog,
  getLatestCollection,
} from "./db/queries.js";
export type {
  MonthlyDataPoint,
  RawSourceEntry,
  CollectionLogEntry,
} from "./db/queries.js";

// Cache layer
export { IntelligenceCache } from "./cache/manager.js";
export { DEFAULT_CACHE_CONFIG } from "./cache/types.js";
export type { CacheEntry, CacheConfig } from "./cache/types.js";
