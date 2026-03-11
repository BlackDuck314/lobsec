/**
 * Cache entry in intelligence_cache table.
 */
export interface CacheEntry {
  cacheKey: string;
  product: string;
  paramsHash: string;
  resultJson: string;
  createdAt: string;
  expiresAt: string;
}

/**
 * Cache configuration.
 */
export interface CacheConfig {
  /** Default TTL in milliseconds (default: 1 hour) */
  defaultTtlMs: number;
}

/**
 * Default cache configuration.
 */
export const DEFAULT_CACHE_CONFIG: CacheConfig = {
  defaultTtlMs: 3600000, // 1 hour
};
