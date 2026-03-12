/**
 * SourceCollector — Thin HTTP Client for Ninja Scraper API
 *
 * Delegates all scraping to the Ninja Scraper service via HTTP.
 * Provides retry logic, circuit breaker, schema validation, and audit logging
 * for all data collection operations.
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
  ScraperApiConfig,
} from "./types.js";

/**
 * Concrete collector class that delegates scraping to Ninja Scraper API.
 *
 * Each instance is differentiated by its missionName, which maps to a
 * YAML mission spec loaded by the Ninja Scraper service.
 *
 * Provides:
 * - HTTP client calling Ninja Scraper /crawl endpoint
 * - Polling for job completion
 * - Retry with exponential backoff
 * - Circuit breaker pattern
 * - Schema validation
 * - Audit logging via collection_log table
 */
export class SourceCollector {
  readonly metadata: CollectorMetadata;
  readonly missionName: string;
  protected db: Database.Database;
  protected circuitBreaker: CircuitBreaker;
  protected scraperConfig: ScraperApiConfig;

  status: CollectorStatus = "idle";
  consecutiveFailures: number = 0;
  lastRun?: string;

  constructor(
    metadata: CollectorMetadata,
    db: Database.Database,
    scraperConfig: ScraperApiConfig,
    missionName: string
  ) {
    this.metadata = metadata;
    this.db = db;
    this.scraperConfig = scraperConfig;
    this.missionName = missionName;
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 30_000,
      halfOpenSuccesses: 1,
    });
  }

  /**
   * Trigger a scrape via Ninja Scraper API and poll for completion.
   *
   * 1. POST /crawl to start the job
   * 2. Poll GET /crawl/{job_id} until completed or failed
   * 3. Return file path and row count from result
   *
   * @returns Object with filePath and rowCount on success
   * @throws Error on collection failure or timeout
   */
  async collect(): Promise<{ filePath: string; rowCount: number }> {
    const { baseUrl, authToken, pollIntervalMs, maxWaitMs } =
      this.scraperConfig;

    // Step 1: Trigger the crawl job
    const crawlResponse = await fetch(`${baseUrl}/crawl`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        mission_name: this.missionName,
        params: {},
      }),
    });

    if (!crawlResponse.ok) {
      const body = await crawlResponse.text().catch(() => "");
      throw new Error(
        `Scraper API POST /crawl failed: HTTP ${crawlResponse.status} ${crawlResponse.statusText}${body ? ` — ${body}` : ""}`
      );
    }

    const crawlData = (await crawlResponse.json()) as {
      job_id: string;
      status: string;
    };
    const { job_id } = crawlData;

    if (!job_id) {
      throw new Error("Scraper API returned no job_id");
    }

    // Step 2: Poll for job completion
    const deadline = Date.now() + maxWaitMs;

    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));

      const statusResponse = await fetch(`${baseUrl}/crawl/${job_id}`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      if (!statusResponse.ok) {
        throw new Error(
          `Scraper API GET /crawl/${job_id} failed: HTTP ${statusResponse.status}`
        );
      }

      const statusData = (await statusResponse.json()) as {
        job_id: string;
        status: string;
        result?: {
          file_path: string;
          row_count: number;
          duration_ms: number;
          error?: string;
        };
      };

      if (statusData.status === "completed") {
        if (!statusData.result) {
          throw new Error("Scraper API returned completed but no result");
        }
        return {
          filePath: statusData.result.file_path,
          rowCount: statusData.result.row_count,
        };
      }

      if (statusData.status === "failed") {
        const errorMsg =
          statusData.result?.error || "Mission failed (no error details)";
        throw new Error(`Scraper mission '${this.missionName}' failed: ${errorMsg}`);
      }

      // Status is "queued" or "running" — continue polling
    }

    throw new Error(
      `Scraper mission '${this.missionName}' timed out after ${maxWaitMs}ms`
    );
  }

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
