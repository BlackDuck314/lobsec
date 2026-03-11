import type Database from "better-sqlite3";
import { sha256 } from "@lobsec/shared";
import { DEFAULT_CACHE_CONFIG, type CacheConfig } from "./types.js";

/**
 * Intelligence cache with TTL-based expiry.
 *
 * Stores intelligence product results keyed by product name and SHA-256 hash
 * of serialized parameters. Supports TTL expiry and cleanup of stale entries.
 */
export class IntelligenceCache {
  private readonly db: Database.Database;
  private readonly config: CacheConfig;

  constructor(db: Database.Database, config: Partial<CacheConfig> = {}) {
    this.db = db;
    this.config = { ...DEFAULT_CACHE_CONFIG, ...config };
  }

  /**
   * Get cached result for a product and parameters.
   *
   * @param product - Intelligence product name
   * @param params - Product parameters
   * @returns Cached result or null if not found/expired
   */
  get<T>(product: string, params: Record<string, unknown>): T | null {
    const paramsHash = this.hashParams(params);
    const cacheKey = `${product}:${paramsHash}`;

    const stmt = this.db.prepare(`
      SELECT result_json, expires_at
      FROM intelligence_cache
      WHERE cache_key = ?
    `);

    const row = stmt.get(cacheKey) as
      | { result_json: string; expires_at: string }
      | undefined;

    if (!row) {
      return null;
    }

    // Check expiry
    const now = new Date().toISOString();
    if (row.expires_at <= now) {
      // Expired - delete and return null
      this.db
        .prepare("DELETE FROM intelligence_cache WHERE cache_key = ?")
        .run(cacheKey);
      return null;
    }

    // Parse and return result
    return JSON.parse(row.result_json) as T;
  }

  /**
   * Set cache entry for a product and parameters.
   *
   * @param product - Intelligence product name
   * @param params - Product parameters
   * @param result - Result to cache
   * @param ttlMs - Optional TTL override (default: config.defaultTtlMs)
   */
  set(
    product: string,
    params: Record<string, unknown>,
    result: unknown,
    ttlMs?: number
  ): void {
    const paramsHash = this.hashParams(params);
    const cacheKey = `${product}:${paramsHash}`;
    const resultJson = JSON.stringify(result);

    const ttl = ttlMs ?? this.config.defaultTtlMs;
    const expiresAt = new Date(Date.now() + ttl).toISOString();

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO intelligence_cache (cache_key, product, params_hash, result_json, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(cacheKey, product, paramsHash, resultJson, expiresAt);
  }

  /**
   * Invalidate all cache entries for a product.
   *
   * @param product - Intelligence product name
   */
  invalidate(product: string): void {
    const stmt = this.db.prepare(`
      DELETE FROM intelligence_cache WHERE product = ?
    `);

    stmt.run(product);
  }

  /**
   * Clean up expired cache entries.
   *
   * @returns Number of entries deleted
   */
  cleanup(): number {
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      DELETE FROM intelligence_cache WHERE expires_at <= ?
    `);

    const result = stmt.run(now);
    return result.changes;
  }

  /**
   * Hash parameters for cache key.
   */
  private hashParams(params: Record<string, unknown>): string {
    // Serialize parameters deterministically (sorted keys)
    const serialized = JSON.stringify(params, Object.keys(params).sort());
    return sha256(serialized);
  }
}
