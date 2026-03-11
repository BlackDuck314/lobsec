/**
 * Bayut Listings Collector
 *
 * Fulfills COLL-05 (partial): Dubai listing market data from Bayut.ae portal.
 *
 * This collector uses Playwright browser automation with anti-bot measures to:
 * 1. Query all Dubai areas from area_names table
 * 2. For each area, scrape listing data from Bayut.ae
 * 3. Extract metrics: listing count, price, bedrooms, sqft, property type
 * 4. Detect price reduction badges (single-scrape metric)
 * 5. Save aggregated data as JSON
 *
 * Anti-bot measures:
 * - Realistic user agent and viewport
 * - Random delays between area scrapes (1-3 seconds)
 * - Graceful handling of 403/CAPTCHA blocks
 * - No immediate retries on block
 */

import { chromium, type Browser, type Page } from "playwright";
import { SourceCollector } from "./base.js";
import type { CollectorMetadata } from "./types.js";
import type Database from "better-sqlite3";
import { insertRawSource } from "../db/queries.js";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

const RAW_DATA_DIR = "/opt/lobsec/data/raw/bayut-listings";
const BAYUT_BASE_URL = "https://www.bayut.com";

interface ListingData {
  price?: number;
  bedrooms?: number;
  sqft?: number;
  type?: string;
  reducedPrice: boolean; // Badge detected by portal
}

interface AreaData {
  area: string;
  listingCount: number;
  listings: ListingData[];
}

interface ScrapedData {
  scrapedAt: string;
  areas: AreaData[];
}

/**
 * Bayut listings collector using Playwright scraping.
 *
 * Metadata:
 * - source: bayut-listings
 * - frequency: weekly
 * - priority: 3 (Tier A)
 * - timeout: 600_000 (10 min for comprehensive scrape)
 */
export class BayutListingsCollector extends SourceCollector {
  private browser?: Browser;

  constructor(db: Database.Database) {
    const metadata: CollectorMetadata = {
      source: "bayut-listings",
      frequency: "weekly",
      priority: 3,
      timeout: 600_000, // 10 minutes
    };
    super(metadata, db);
  }

  /**
   * Get all Dubai areas from area_names table.
   */
  private getDubaiAreas(): string[] {
    const stmt = this.db.prepare(`
      SELECT canonical_name
      FROM area_names
      WHERE emirate = 'dubai'
      ORDER BY canonical_name
    `);

    const rows = stmt.all() as { canonical_name: string }[];
    return rows.map((r) => r.canonical_name);
  }

  /**
   * Convert area name to URL slug (lowercase, spaces to hyphens).
   */
  private toSlug(areaName: string): string {
    return areaName.toLowerCase().replace(/\s+/g, "-");
  }

  /**
   * Scrape listings for a single area.
   */
  private async scrapeArea(
    page: Page,
    area: string
  ): Promise<AreaData | null> {
    const slug = this.toSlug(area);
    const url = `${BAYUT_BASE_URL}/for-sale/property/dubai/${slug}/`;

    console.error(`[bayut-listings] Scraping ${area} (${url})...`);

    try {
      const response = await page.goto(url, {
        waitUntil: "networkidle",
        timeout: 30_000,
      });

      // Check for blocking
      if (!response || response.status() === 403) {
        console.error(
          `[bayut-listings] 403 blocked for ${area}, skipping (do not retry)`
        );
        return null;
      }

      // Check for CAPTCHA
      const captchaPresent = await page
        .locator('text=/captcha|verify/i')
        .first()
        .isVisible()
        .catch(() => false);

      if (captchaPresent) {
        console.error(
          `[bayut-listings] CAPTCHA detected for ${area}, skipping`
        );
        return null;
      }

      // Extract total listing count
      let listingCount = 0;
      const countText = await page
        .locator('text=/\\d+ properties/i')
        .first()
        .textContent()
        .catch(() => null);

      if (countText) {
        const match = countText.match(/(\d+)/);
        if (match && match[1]) {
          listingCount = parseInt(match[1], 10);
        }
      }

      // Scrape listing cards (first page only for MVP)
      const listings: ListingData[] = [];

      const listingCards = await page.$$('[class*="property-card"]');

      for (const card of listingCards) {
        try {
          // Price
          const priceText = await card
            .$eval('[class*="price"]', (el: any) => el.textContent)
            .catch(() => null);
          let price: number | undefined;
          if (priceText) {
            const priceMatch = priceText.match(/[\d,]+/);
            if (priceMatch) {
              price = parseFloat(priceMatch[0].replace(/,/g, ""));
            }
          }

          // Bedrooms
          const bedroomsText = await card
            .$eval('[class*="bedroom"]', (el: any) => el.textContent)
            .catch(() => null);
          let bedrooms: number | undefined;
          if (bedroomsText) {
            const bedroomsMatch = bedroomsText.match(/\d+/);
            if (bedroomsMatch) {
              bedrooms = parseInt(bedroomsMatch[0], 10);
            }
          }

          // Sqft
          const sqftText = await card
            .$eval('[class*="area"]', (el: any) => el.textContent)
            .catch(() => null);
          let sqft: number | undefined;
          if (sqftText) {
            const sqftMatch = sqftText.match(/[\d,]+/);
            if (sqftMatch) {
              sqft = parseFloat(sqftMatch[0].replace(/,/g, ""));
            }
          }

          // Property type
          const type = await card
            .$eval('[class*="type"]', (el: any) => el.textContent)
            .catch(() => undefined) as string | undefined;

          // Price reduction badge
          const reducedBadgePresent = await card
            .$('[class*="badge"]:has-text("Reduced"), [class*="tag"]:has-text("Reduced"), [class*="badge"]:has-text("Price Drop"), [class*="tag"]:has-text("Price Drop")')
            .then(() => true)
            .catch(() => false);

          listings.push({
            price,
            bedrooms,
            sqft,
            type,
            reducedPrice: reducedBadgePresent,
          });
        } catch (err) {
          // Skip malformed listing card
          console.error(
            `[bayut-listings] Failed to parse listing card in ${area}: ${err}`
          );
          continue;
        }
      }

      console.error(
        `[bayut-listings] Scraped ${listings.length} listings from ${area}`
      );

      return {
        area,
        listingCount,
        listings,
      };
    } catch (error) {
      console.error(`[bayut-listings] Error scraping ${area}: ${error}`);
      return null;
    }
  }

  /**
   * Collect Bayut listing data via Playwright scraping.
   *
   * Scrapes all Dubai areas with anti-bot measures.
   * Saves aggregated data as JSON.
   */
  async collect(): Promise<{ filePath: string; rowCount: number }> {
    try {
      // Launch browser with stealth options
      this.browser = await chromium.launch({
        headless: true,
        args: ["--disable-blink-features=AutomationControlled"],
      });

      const context = await this.browser.newContext({
        userAgent:
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        viewport: { width: 1920, height: 1080 },
      });

      const page = await context.newPage();

      // Get all Dubai areas
      const areas = this.getDubaiAreas();
      console.error(
        `[bayut-listings] Found ${areas.length} Dubai areas to scrape`
      );

      const scrapedData: ScrapedData = {
        scrapedAt: new Date().toISOString(),
        areas: [],
      };

      // Scrape each area with anti-bot delays
      for (const area of areas) {
        const areaData = await this.scrapeArea(page, area);

        if (areaData) {
          scrapedData.areas.push(areaData);
        }

        // Random delay between areas (1-3 seconds)
        const delay = Math.random() * 2000 + 1000;
        await new Promise((resolve) => setTimeout(resolve, delay));
      }

      // Save as JSON
      const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
      const filename = `${today}.json`;
      const filePath = join(RAW_DATA_DIR, filename);

      await mkdir(dirname(filePath), { recursive: true });

      const jsonContent = JSON.stringify(scrapedData, null, 2);
      await import("node:fs/promises").then((fs) =>
        fs.writeFile(filePath, jsonContent, "utf-8")
      );

      console.error(`[bayut-listings] Saved data to ${filePath}`);

      // Calculate total listing count
      const totalListings = scrapedData.areas.reduce(
        (sum, area) => sum + area.listings.length,
        0
      );

      // Calculate checksum
      const checksum = createHash("sha256").update(jsonContent).digest("hex");

      // Store raw source metadata
      const stats = await import("node:fs/promises").then((fs) =>
        fs.stat(filePath)
      );
      insertRawSource(this.db, {
        source: this.metadata.source,
        filePath,
        collectedAt: new Date().toISOString(),
        rowCount: totalListings,
        fileSizeBytes: stats.size,
        checksum,
      });

      return {
        filePath,
        rowCount: totalListings,
      };
    } finally {
      // Always close browser
      if (this.browser) {
        await this.browser.close();
        this.browser = undefined;
      }
    }
  }
}
