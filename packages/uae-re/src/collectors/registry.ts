/**
 * CollectorRegistry
 *
 * Manages collector registration and execution with concurrency control.
 * Supports running all collectors, filtering by frequency, or running individual collectors.
 * Provides factory method to create 7 UAE RE collectors backed by Ninja Scraper API.
 */

import type Database from "better-sqlite3";
import { SourceCollector } from "./base.js";
import { DirectPythonCollector } from "./direct.js";
import type { PythonScriptName } from "../analytics/types.js";
import type {
  CollectionFrequency,
  CollectorInfo,
  CollectionResult,
  CollectorMetadata,
  RegistryRunResult,
  ScraperApiConfig,
} from "./types.js";

/**
 * Collector definitions for 38 UAE RE sources.
 * Each entry maps to a Ninja Scraper YAML mission file (or a DirectPythonCollector source).
 */
const COLLECTOR_DEFINITIONS: Array<{
  missionName: string;
  metadata: CollectorMetadata;
}> = [
  // Phase 7 Tier A — Core transaction and listing sources
  {
    missionName: "dld-sales",
    metadata: { source: "dld-sales", frequency: "weekly", priority: 1, timeout: 120_000 },
  },
  {
    missionName: "ejari-rentals",
    metadata: { source: "ejari-rentals", frequency: "weekly", priority: 1, timeout: 120_000 },
  },
  {
    missionName: "building-permits",
    metadata: { source: "building-permits", frequency: "monthly", priority: 2, timeout: 120_000 },
  },
  {
    missionName: "adrec-abu-dhabi",
    metadata: { source: "adrec-abu-dhabi", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "bayut-listings",
    metadata: { source: "bayut-listings", frequency: "weekly", priority: 3, timeout: 600_000 },
  },
  {
    missionName: "propertyfinder-listings",
    metadata: { source: "propertyfinder-listings", frequency: "weekly", priority: 3, timeout: 600_000 },
  },
  {
    missionName: "dewa-connections",
    metadata: { source: "dewa-connections", frequency: "monthly", priority: 2, timeout: 300_000 },
  },

  // Phase 8 Tier B — Government/Institutional Sources
  {
    missionName: "mohre-permits",
    metadata: { source: "mohre-permits", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "dxb-passengers",
    metadata: { source: "dxb-passengers", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "gdrfa-visas",
    metadata: { source: "gdrfa-visas", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "khda-enrollment",
    metadata: { source: "khda-enrollment", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "rta-vehicles",
    metadata: { source: "rta-vehicles", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "cbuae-remittances",
    metadata: { source: "cbuae-remittances", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },

  // Phase 8 Tier B — Job Platforms (weekly, lower priority)
  {
    missionName: "linkedin-jobs",
    metadata: { source: "linkedin-jobs", frequency: "weekly", priority: 3, timeout: 600_000 },
  },
  {
    missionName: "bayt-jobs",
    metadata: { source: "bayt-jobs", frequency: "weekly", priority: 3, timeout: 600_000 },
  },
  {
    missionName: "indeed-jobs",
    metadata: { source: "indeed-jobs", frequency: "weekly", priority: 3, timeout: 600_000 },
  },
  {
    missionName: "gulftalent-jobs",
    metadata: { source: "gulftalent-jobs", frequency: "weekly", priority: 3, timeout: 600_000 },
  },

  // Phase 8 Tier B — Salary Surveys (quarterly, medium priority)
  {
    missionName: "cooper-fitch-salary",
    metadata: { source: "cooper-fitch-salary", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "hays-salary",
    metadata: { source: "hays-salary", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "roberthalf-salary",
    metadata: { source: "roberthalf-salary", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },

  // Phase 9 Tier C — Daily sources (DirectPythonCollector — no Ninja Scraper)
  {
    missionName: "google-trends",
    metadata: { source: "google-trends", frequency: "daily", priority: 1, timeout: 120_000 },
  },
  {
    missionName: "reddit-sentiment",
    metadata: { source: "reddit-sentiment", frequency: "daily", priority: 1, timeout: 60_000 },
  },

  // Phase 9 Tier C — Weekly sources
  {
    missionName: "google-maps-traffic",
    metadata: { source: "google-maps-traffic", frequency: "weekly", priority: 3, timeout: 3_600_000 },
  },

  // Phase 9 Tier C — Monthly sources
  {
    missionName: "rta-metro",
    metadata: { source: "rta-metro", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "dtcm-tourism",
    metadata: { source: "dtcm-tourism", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "ded-licenses",
    metadata: { source: "ded-licenses", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "jebel-ali-port",
    metadata: { source: "jebel-ali-port", frequency: "monthly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "fb-closures",
    metadata: { source: "fb-closures", frequency: "monthly", priority: 3, timeout: 600_000 },
  },

  // Phase 9 Tier C — Quarterly sources
  {
    missionName: "cbuae-mortgages",
    metadata: { source: "cbuae-mortgages", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "customs-imports",
    metadata: { source: "customs-imports", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "fcsa-demographics",
    metadata: { source: "fcsa-demographics", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "insideairbnb",
    metadata: { source: "insideairbnb", frequency: "quarterly", priority: 2, timeout: 300_000 },
  },
  {
    missionName: "commercial-office-reports",
    metadata: { source: "commercial-office-reports", frequency: "quarterly", priority: 2, timeout: 600_000 },
  },

  // Phase 18 — Macro Economic APIs (DirectPythonCollector)
  {
    missionName: "worldbank-macro",
    metadata: { source: "worldbank-macro", frequency: "quarterly", priority: 2, timeout: 60_000 },
  },
  {
    missionName: "imf-weo",
    metadata: { source: "imf-weo", frequency: "quarterly", priority: 2, timeout: 60_000 },
  },
  {
    missionName: "dfm-stocks",
    metadata: { source: "dfm-stocks", frequency: "monthly", priority: 3, timeout: 60_000 },
  },
  {
    missionName: "spglobal-pmi",
    metadata: { source: "spglobal-pmi", frequency: "monthly", priority: 2, timeout: 120_000 },
  },

  // Phase 19 — Commodity, Sentiment & Cost of Living
  {
    missionName: "commodities",
    metadata: { source: "commodities", frequency: "monthly", priority: 2, timeout: 60_000 },
  },
  {
    missionName: "news-sentiment",
    metadata: { source: "news-sentiment", frequency: "daily", priority: 1, timeout: 60_000 },
  },
];

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
   * Create and register all collectors via factory (Tier A + Tier B + Tier C).
   *
   * Most collectors are SourceCollector instances that delegate scraping to the
   * Ninja Scraper HTTP API. DirectPythonCollector instances are used for API-native
   * sources (Google Trends, Reddit) that bypass the browser automation engine.
   *
   * @param db - Database instance for audit logging
   * @param scraperConfig - Ninja Scraper API connection config
   */
  createCollectors(db: Database.Database, scraperConfig: ScraperApiConfig): void {
    // DirectPythonCollector sources: missionName → Python collect module name
    const DIRECT_PYTHON_SOURCES: Record<string, string> = {
      "google-trends": "collect_trends",
      "reddit-sentiment": "collect_sentiment",
      // Phase 18 — Macro Economic APIs
      "worldbank-macro": "collect_worldbank",
      "imf-weo": "collect_imf",
      "dfm-stocks": "collect_dfm_stocks",
      "spglobal-pmi": "collect_pmi",
      // Phase 19
      "commodities": "collect_commodities",
      "news-sentiment": "collect_news_sentiment",
    };

    for (const def of COLLECTOR_DEFINITIONS) {
      let collector: SourceCollector;
      if (def.missionName in DIRECT_PYTHON_SOURCES) {
        const pythonModule = DIRECT_PYTHON_SOURCES[
          def.missionName
        ] as PythonScriptName;
        collector = new DirectPythonCollector(
          def.metadata,
          db,
          scraperConfig,
          pythonModule
        );
      } else {
        collector = new SourceCollector(
          def.metadata,
          db,
          scraperConfig,
          def.missionName
        );
      }
      this.register(collector);
    }
  }

  /**
   * Check if the Ninja Scraper service is running and healthy.
   *
   * @param baseUrl - Scraper API base URL (defaults to http://127.0.0.1:18791)
   * @returns true if scraper responds with status "ok", false otherwise
   */
  async checkScraperHealth(
    baseUrl: string = "http://127.0.0.1:18791"
  ): Promise<boolean> {
    try {
      const response = await fetch(`${baseUrl}/health`, {
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        return false;
      }

      const data = (await response.json()) as { status: string };
      return data.status === "ok";
    } catch {
      return false;
    }
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
