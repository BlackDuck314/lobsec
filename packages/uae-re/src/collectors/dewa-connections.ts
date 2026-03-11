/**
 * DEWA Connections Collector
 *
 * Fulfills COLL-15: Dubai utilities connections/disconnections data from DEWA press releases.
 *
 * This collector scrapes DEWA's press releases page to find announcements about new
 * connections and disconnections. DEWA publishes monthly updates about utility service
 * additions and closures.
 *
 * Strategy A (PRIMARY): Scrape press releases from DEWA website
 * - Navigate to https://www.dewa.gov.ae/en/about-us/media-publications/latest-news
 * - Search for press releases mentioning "connections", "customers", or "accounts"
 * - Extract connection/disconnection counts from article text
 *
 * Strategy B (FALLBACK): Check monthly statistics publications if press releases
 * don't contain numeric data.
 *
 * Note: DEWA may only publish emirate-level aggregates (not area-level breakdowns).
 * The collector gracefully handles both granularities.
 */

import { chromium, type Browser, type Page } from "playwright";
import { SourceCollector } from "./base.js";
import type { CollectorMetadata } from "./types.js";
import type Database from "better-sqlite3";
import { insertRawSource } from "../db/queries.js";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const RAW_DATA_DIR = "/opt/lobsec/data/raw/dewa-connections";
const DEWA_NEWS_URL = "https://www.dewa.gov.ae/en/about-us/media-publications/latest-news";
const DEWA_PUBLICATIONS_URL = "https://www.dewa.gov.ae/en/about-us/media-publications/dewa-publications";

interface PressReleaseArticle {
  title: string;
  date: string;
  url: string;
  connections_new?: number;
  disconnections?: number;
  areas_mentioned?: string[];
  full_text?: string;
}

interface ScrapedData {
  scrapedAt: string;
  source_url: string;
  articles: PressReleaseArticle[];
}

/**
 * DEWA connections collector using Playwright scraping.
 *
 * Metadata:
 * - source: dewa-connections
 * - frequency: monthly
 * - priority: 4 (utility data - lower priority than transactions/listings)
 * - timeout: 180_000 (3 minutes for press release scanning)
 */
export class DEWAConnectionsCollector extends SourceCollector {
  private browser?: Browser;

  constructor(db: Database.Database) {
    const metadata: CollectorMetadata = {
      source: "dewa-connections",
      frequency: "monthly",
      priority: 4,
      timeout: 180_000, // 3 minutes
    };
    super(metadata, db);
  }

  /**
   * Extract numbers from text using common patterns:
   * - "X new connections"
   * - "X customers"
   * - "X accounts"
   * - "X disconnections"
   */
  private extractNumbers(text: string): { connections?: number; disconnections?: number } {
    const result: { connections?: number; disconnections?: number } = {};

    // Pattern for new connections/customers/accounts
    const connectionPatterns = [
      /(\d+(?:,\d+)*)\s+new\s+connections?/i,
      /(\d+(?:,\d+)*)\s+new\s+customers?/i,
      /(\d+(?:,\d+)*)\s+new\s+accounts?/i,
      /added\s+(\d+(?:,\d+)*)\s+connections?/i,
      /added\s+(\d+(?:,\d+)*)\s+customers?/i,
    ];

    for (const pattern of connectionPatterns) {
      const match = text.match(pattern);
      if (match && match[1]) {
        const num = parseInt(match[1].replace(/,/g, ""), 10);
        if (!isNaN(num)) {
          result.connections = num;
          break;
        }
      }
    }

    // Pattern for disconnections
    const disconnectionPatterns = [
      /(\d+(?:,\d+)*)\s+disconnections?/i,
      /removed\s+(\d+(?:,\d+)*)\s+connections?/i,
      /(\d+(?:,\d+)*)\s+closures?/i,
      /terminated\s+(\d+(?:,\d+)*)\s+services?/i,
    ];

    for (const pattern of disconnectionPatterns) {
      const match = text.match(pattern);
      if (match && match[1]) {
        const num = parseInt(match[1].replace(/,/g, ""), 10);
        if (!isNaN(num)) {
          result.disconnections = num;
          break;
        }
      }
    }

    return result;
  }

  /**
   * Scrape DEWA press releases page for connection/disconnection data.
   */
  private async scrapePressReleases(page: Page): Promise<PressReleaseArticle[]> {
    const articles: PressReleaseArticle[] = [];

    try {
      // Navigate to press releases page
      await page.goto(DEWA_NEWS_URL, { waitUntil: "domcontentloaded", timeout: 30000 });

      // Wait for content to load
      await page.waitForTimeout(2000);

      // Find all news article links
      // (Selector may need adjustment based on actual DEWA website structure)
      const articleLinks = await page.$$eval(
        'a[href*="/news/"], a[href*="/article/"], .news-item a, .article-link',
        (links) => links.map((a) => ({
          title: (a.textContent || "").trim(),
          url: (a as any).href,
        }))
      );

      if (articleLinks.length === 0) {
        console.error("No article links found on DEWA news page. Selector may need adjustment.");
        return articles;
      }

      // Filter for relevant articles (containing keywords)
      const relevantKeywords = ["connection", "customer", "account", "disconnection", "service"];
      const relevantLinks = articleLinks.filter((link) =>
        relevantKeywords.some((keyword) => link.title.toLowerCase().includes(keyword))
      ).slice(0, 10); // Process up to 10 most recent relevant articles

      // Visit each relevant article
      for (const link of relevantLinks) {
        try {
          await page.goto(link.url, { waitUntil: "domcontentloaded", timeout: 30000 });
          await page.waitForTimeout(1000);

          // Extract article date
          const dateText = await page.$eval(
            '.article-date, .news-date, time, [class*="date"]',
            (el) => el.textContent?.trim() || ""
          ).catch(() => "");

          // Extract full article text
          const fullText = await page.$eval(
            'article, .article-body, .news-content, main',
            (el) => el.textContent?.trim() || ""
          ).catch(() => "");

          // Extract connection/disconnection numbers
          const numbers = this.extractNumbers(fullText);

          // Only add article if it contains numeric data
          if (numbers.connections !== undefined || numbers.disconnections !== undefined) {
            articles.push({
              title: link.title,
              date: dateText,
              url: link.url,
              connections_new: numbers.connections,
              disconnections: numbers.disconnections,
              full_text: fullText,
            });
          }
        } catch (err) {
          console.error(`Failed to scrape article ${link.url}: ${err}`);
          // Continue with remaining articles
        }
      }

      return articles;
    } catch (error) {
      throw new Error(`Failed to scrape DEWA press releases: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Fallback: Check DEWA publications page for monthly statistics reports.
   * Only used if press releases yield zero data.
   */
  private async scrapePublications(page: Page): Promise<PressReleaseArticle[]> {
    // Fallback implementation - check for PDF/HTML statistics reports
    // This is a simplified fallback; can be expanded if needed
    console.error("DEWA press releases contained no connection data. Checking publications page...");

    try {
      await page.goto(DEWA_PUBLICATIONS_URL, { waitUntil: "domcontentloaded", timeout: 30000 });
      await page.waitForTimeout(2000);

      // Look for statistics or annual report links
      const reportLinks = await page.$$eval(
        'a[href*="statistic"], a[href*="annual"], a[href*="report"]',
        (links) => links.map((a) => ({
          title: (a.textContent || "").trim(),
          url: (a as any).href,
        }))
      ).catch(() => []);

      console.error(`Found ${reportLinks.length} potential statistics reports`);

      // For MVP, we'll return empty if fallback is triggered
      // Future enhancement: Parse PDF/HTML statistics reports
      return [];
    } catch (error) {
      console.error(`Fallback publications scrape failed: ${error}`);
      return [];
    }
  }

  /**
   * Collect DEWA connections data from press releases.
   */
  async collect(): Promise<{ filePath: string; rowCount: number }> {
    try {
      // Launch browser
      this.browser = await chromium.launch({ headless: true });
      const page = await this.browser.newPage();

      // Set realistic user agent
      await page.setViewportSize({ width: 1920, height: 1080 });

      // Strategy A: Scrape press releases
      let articles = await this.scrapePressReleases(page);

      // Strategy B: Fallback to publications if press releases yield no data
      if (articles.length === 0) {
        articles = await this.scrapePublications(page);
      }

      // Close browser
      await this.browser.close();
      this.browser = undefined;

      // Prepare output data
      const scrapedData: ScrapedData = {
        scrapedAt: new Date().toISOString(),
        source_url: DEWA_NEWS_URL,
        articles,
      };

      // Create output directory
      await mkdir(RAW_DATA_DIR, { recursive: true });

      // Write to JSON file
      const date = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
      const fileName = `${date}.json`;
      const filePath = join(RAW_DATA_DIR, fileName);

      await writeFile(filePath, JSON.stringify(scrapedData, null, 2), "utf-8");

      // Count "rows" as number of articles with data
      const rowCount = articles.length;

      // Log to raw_sources table
      insertRawSource(this.db, {
        source: this.metadata.source,
        filePath,
        collectedAt: new Date().toISOString(),
        rowCount,
      });

      // Graceful degradation: If no data found, return rowCount=0
      // This will trigger empty collection error in base class, which is correct behavior
      return { filePath, rowCount };
    } catch (error) {
      // Ensure browser is closed on error
      if (this.browser) {
        await this.browser.close().catch(() => {});
        this.browser = undefined;
      }
      throw error;
    } finally {
      // Ensure browser is closed
      if (this.browser) {
        await this.browser.close().catch(() => {});
        this.browser = undefined;
      }
    }
  }
}
