/**
 * CollectorRegistry
 *
 * Manages collector registration and execution with concurrency control.
 * Supports running all collectors, filtering by frequency, or running individual collectors.
 */

import { SourceCollector } from "./base.js";
import type {
  CollectionFrequency,
  CollectorInfo,
  CollectionResult,
  RegistryRunResult,
} from "./types.js";

/**
 * Manages a collection of SourceCollector instances with concurrency control.
 */
export class CollectorRegistry {
  private collectors: Map<string, SourceCollector> = new Map();
  private activeTasks: number = 0;
  private readonly maxConcurrency: number;
  private waitQueue: Array<() => void> = [];

  constructor(maxConcurrency: number = 3) {
    this.maxConcurrency = maxConcurrency;
  }

  /**
   * Register a collector.
   *
   * @throws Error if a collector with the same source name is already registered
   */
  register(collector: SourceCollector): void {
    const source = collector.metadata.source;
    if (this.collectors.has(source)) {
      throw new Error(`Collector already registered: ${source}`);
    }
    this.collectors.set(source, collector);
  }

  /**
   * Unregister a collector by source name.
   *
   * @returns true if collector was found and removed, false otherwise
   */
  unregister(source: string): boolean {
    return this.collectors.delete(source);
  }

  /**
   * Get a collector by source name.
   */
  get(source: string): SourceCollector | undefined {
    return this.collectors.get(source);
  }

  /**
   * Get info for all registered collectors.
   */
  getAll(): CollectorInfo[] {
    return Array.from(this.collectors.values()).map((c) => c.getInfo());
  }

  /**
   * Get collectors matching a specific frequency.
   */
  getByFrequency(frequency: CollectionFrequency): SourceCollector[] {
    return Array.from(this.collectors.values()).filter(
      (c) => c.metadata.frequency === frequency
    );
  }

  /**
   * Wait for an available concurrency slot.
   */
  private waitForSlot(): Promise<void> {
    if (this.activeTasks < this.maxConcurrency) {
      this.activeTasks++;
      return Promise.resolve();
    }

    return new Promise((resolve) => {
      this.waitQueue.push(() => {
        this.activeTasks++;
        resolve();
      });
    });
  }

  /**
   * Release a concurrency slot and notify next waiter.
   */
  private releaseSlot(): void {
    this.activeTasks--;
    const nextWaiter = this.waitQueue.shift();
    if (nextWaiter) {
      nextWaiter();
    }
  }

  /**
   * Run all registered collectors with concurrency control.
   *
   * Collectors are executed in priority order (1=highest).
   */
  async runAll(): Promise<RegistryRunResult> {
    const startTime = Date.now();
    const results = new Map<string, CollectionResult>();

    // Sort by priority (1=highest first)
    const sortedCollectors = Array.from(this.collectors.values()).sort(
      (a, b) => a.metadata.priority - b.metadata.priority
    );

    // Execute with concurrency control
    const promises = sortedCollectors.map(async (collector) => {
      await this.waitForSlot();

      try {
        const result = await collector.run();
        results.set(collector.metadata.source, result);
      } finally {
        this.releaseSlot();
      }
    });

    await Promise.all(promises);

    const totalDuration = Date.now() - startTime;
    let successCount = 0;
    let failureCount = 0;

    for (const result of results.values()) {
      if (result.success) {
        successCount++;
      } else {
        failureCount++;
      }
    }

    return {
      results,
      totalDuration,
      successCount,
      failureCount,
    };
  }

  /**
   * Run only collectors matching the given frequency.
   */
  async runByFrequency(
    frequency: CollectionFrequency
  ): Promise<RegistryRunResult> {
    const startTime = Date.now();
    const results = new Map<string, CollectionResult>();

    // Filter by frequency and sort by priority
    const filteredCollectors = Array.from(this.collectors.values())
      .filter((c) => c.metadata.frequency === frequency)
      .sort((a, b) => a.metadata.priority - b.metadata.priority);

    // Execute with concurrency control
    const promises = filteredCollectors.map(async (collector) => {
      await this.waitForSlot();

      try {
        const result = await collector.run();
        results.set(collector.metadata.source, result);
      } finally {
        this.releaseSlot();
      }
    });

    await Promise.all(promises);

    const totalDuration = Date.now() - startTime;
    let successCount = 0;
    let failureCount = 0;

    for (const result of results.values()) {
      if (result.success) {
        successCount++;
      } else {
        failureCount++;
      }
    }

    return {
      results,
      totalDuration,
      successCount,
      failureCount,
    };
  }

  /**
   * Run a single collector by source name.
   *
   * @throws Error if collector not found
   */
  async runOne(source: string): Promise<CollectionResult> {
    const collector = this.collectors.get(source);
    if (!collector) {
      throw new Error(`Collector not found: ${source}`);
    }
    return collector.run();
  }
}
