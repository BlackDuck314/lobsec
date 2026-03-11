/**
 * SourceCollector Abstract Base Class
 *
 * Provides retry logic, circuit breaker, schema validation, and audit logging
 * for all data collection operations. Collectors inherit from this and implement
 * the collect() method.
 */

import type Database from "better-sqlite3";
import {
  retryWithBackoff,
  CircuitBreaker,
  DEFAULT_RETRY_CONFIG,
} from "@lobsec/shared";
import { insertCollectionLog } from "../db/queries.js";
import type {
  CollectorMetadata,
  CollectionResult,
  CollectorStatus,
  CollectorInfo,
} from "./types.js";

/**
 * Abstract base class for all source collectors.
 *
 * Provides:
 * - Retry with exponential backoff
 * - Circuit breaker pattern
 * - Schema validation
 * - Audit logging via collection_log table
 */
export abstract class SourceCollector {
  readonly metadata: CollectorMetadata;
  protected db: Database.Database;
  protected circuitBreaker: CircuitBreaker;

  status: CollectorStatus = "idle";
  consecutiveFailures: number = 0;
  lastRun?: string;

  constructor(metadata: CollectorMetadata, db: Database.Database) {
    this.metadata = metadata;
    this.db = db;
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 30_000,
      halfOpenSuccesses: 1,
    });
  }

  /**
   * Implement this method in subclasses to perform the actual collection.
   *
   * @returns Object with filePath and rowCount on success
   * @throws Error on collection failure
   */
  abstract collect(): Promise<{ filePath: string; rowCount: number }>;

  /**
   * Validate collection result schema.
   *
   * @throws Error if result is malformed or invalid
   */
  protected validateResult(result: {
    filePath: string;
    rowCount: number;
  }): void {
    if (!result.filePath || result.filePath.trim() === "") {
      throw new Error("Collection result missing filePath");
    }

    if (result.rowCount < 0) {
      throw new Error(
        `Invalid rowCount: ${result.rowCount} (must be non-negative)`
      );
    }

    if (result.rowCount === 0) {
      // Warning: Empty collection is technically valid but unusual
      throw new Error("Empty collection: rowCount is 0");
    }
  }

  /**
   * Execute collection with retry and circuit breaker.
   *
   * Wraps collect() in resilience layers and logs results to collection_log.
   */
  async run(): Promise<CollectionResult> {
    this.status = "running";
    const startTime = Date.now();

    try {
      // Wrap collect() in circuit breaker, then retry with backoff
      const retryResult = await retryWithBackoff(
        () => this.circuitBreaker.execute(() => this.collect()),
        { ...DEFAULT_RETRY_CONFIG, maxRetries: 3 }
      );

      if (!retryResult.success || !retryResult.value) {
        throw new Error(
          retryResult.lastError || "Collection failed after retries"
        );
      }

      const result = retryResult.value;
      this.validateResult(result);

      const duration = Date.now() - startTime;

      // Log success
      insertCollectionLog(this.db, {
        source: this.metadata.source,
        status: "success",
        rowCount: result.rowCount,
        durationMs: duration,
      });

      // Reset failure tracking
      this.consecutiveFailures = 0;
      this.status = "idle";
      this.lastRun = new Date().toISOString();

      return {
        success: true,
        rowCount: result.rowCount,
        filePath: result.filePath,
        duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMsg = error instanceof Error ? error.message : String(error);

      // Log failure
      insertCollectionLog(this.db, {
        source: this.metadata.source,
        status: "failure",
        durationMs: duration,
        error: errorMsg,
      });

      // Track consecutive failures
      this.consecutiveFailures++;
      this.status = this.consecutiveFailures >= 2 ? "stale" : "failed";

      return {
        success: false,
        error: errorMsg,
        duration,
      };
    }
  }

  /**
   * Get current collector state snapshot.
   */
  getInfo(): CollectorInfo {
    return {
      metadata: this.metadata,
      status: this.status,
      lastRun: this.lastRun,
      consecutiveFailures: this.consecutiveFailures,
    };
  }
}
