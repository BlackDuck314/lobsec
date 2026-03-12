/**
 * Default Scraper API Configuration
 *
 * Convenience function to create ScraperApiConfig from environment variables.
 */

import type { ScraperApiConfig } from "./types.js";

/**
 * Create a default ScraperApiConfig from environment variables.
 *
 * Reads SCRAPER_AUTH_TOKEN from process.env. Uses default base URL
 * (http://127.0.0.1:18791) and polling settings (5s interval, 10min max).
 *
 * @returns ScraperApiConfig with defaults
 */
export function createDefaultScraperConfig(): ScraperApiConfig {
  return {
    baseUrl: process.env.SCRAPER_BASE_URL || "http://127.0.0.1:18791",
    authToken: process.env.SCRAPER_AUTH_TOKEN || "",
    pollIntervalMs: 5000,
    maxWaitMs: 600_000,
  };
}
