/**
 * ADREC Abu Dhabi Collector
 *
 * Fulfills COLL-04: Abu Dhabi transaction data collection.
 * Originally planned as DARI/UAE Pass (see REQUIREMENTS.md), but DARI is abandoned
 * per user decision in CONTEXT.md. ADREC public dashboards (https://adrec.gov.ae)
 * provide transaction, lease, and price index data without authentication.
 *
 * This collector uses Playwright browser automation to:
 * 1. Navigate to ADREC dashboard
 * 2. Set broadest filters (All asset types, districts, etc.)
 * 3. Export CSV files via click-to-download
 * 4. Save to raw storage
 *
 * Data sources:
 * - Transactions: Sale transactions with price, area, rate/sqm
 * - Residential Leases: Rental contracts
 * - Price Indices: Market indices over time
 */

import { chromium, type Browser, type Page } from "playwright";
import { SourceCollector } from "./base.js";
import type { CollectorMetadata } from "./types.js";
import type Database from "better-sqlite3";
import { insertRawSource } from "../db/queries.js";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

const RAW_DATA_DIR = "/opt/lobsec/data/raw/adrec-abu-dhabi";
const ADREC_DASHBOARD_URL =
  "https://adrec.gov.ae/en/property_and_index/adrec-dashboard";

/**
 * ADREC Abu Dhabi collector using Playwright click-to-download.
 *
 * Metadata:
 * - source: adrec-abu-dhabi
 * - frequency: monthly
 * - priority: 2 (Tier A)
 * - timeout: 300_000 (5 min for browser automation)
 */
export class ADRECAbuDhabiCollector extends SourceCollector {
  private browser?: Browser;

  constructor(db: Database.Database) {
    const metadata: CollectorMetadata = {
      source: "adrec-abu-dhabi",
      frequency: "monthly",
      priority: 2,
      timeout: 300_000, // 5 minutes
    };
    super(metadata, db);
  }

  /**
   * Download CSV export from ADREC dashboard section.
   *
   * @param page Playwright page instance
   * @param sectionName Section identifier (for logging)
   * @param fileSuffix Suffix for saved filename (e.g., "transactions", "leases")
   * @returns Object with filePath and rowCount
   */
  private async downloadSection(
    page: Page,
    sectionName: string,
    fileSuffix: string
  ): Promise<{ filePath: string; rowCount: number }> {
    const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
    const filename = `${today}-${fileSuffix}.csv`;
    const filePath = join(RAW_DATA_DIR, filename);

    console.error(
      `[adrec-abu-dhabi] Attempting to download ${sectionName} CSV...`
    );

    // Wait for download event, then trigger export
    const downloadPromise = page.waitForEvent("download", { timeout: 30_000 });

    // Try multiple selectors for export button
    const exportSelectors = [
      'button:has-text("Export")',
      'button:has-text("Download")',
      'a:has-text("CSV")',
      'button[aria-label*="export" i]',
      'button[aria-label*="download" i]',
    ];

    let exportClicked = false;
    for (const selector of exportSelectors) {
      try {
        const button = await page.waitForSelector(selector, { timeout: 2000 });
        if (button) {
          await button.click();
          exportClicked = true;
          console.error(
            `[adrec-abu-dhabi] Clicked export button: ${selector}`
          );
          break;
        }
      } catch (err) {
        // Try next selector
        continue;
      }
    }

    if (!exportClicked) {
      // Fallback: save screenshot for debugging
      const timestamp = Date.now();
      const screenshotPath = `/opt/lobsec/logs/adrec-debug-${timestamp}.png`;
      await page.screenshot({ path: screenshotPath, fullPage: true });
      throw new Error(
        `Export button not found for ${sectionName}. Screenshot saved to ${screenshotPath}`
      );
    }

    // Wait for download to complete
    const download = await downloadPromise;

    // Save immediately (per research pitfall #1: never rely on download.path())
    await mkdir(dirname(filePath), { recursive: true });
    await download.saveAs(filePath);

    console.error(`[adrec-abu-dhabi] Downloaded ${sectionName} to ${filePath}`);

    // Count rows (CSV lines minus header)
    const content = await readFile(filePath, "utf-8");
    const lines = content.trim().split("\n");
    const rowCount = Math.max(0, lines.length - 1); // Exclude header

    // Calculate checksum
    const checksum = createHash("sha256").update(content).digest("hex");

    // Store raw source metadata
    const stats = await import("node:fs/promises").then((fs) =>
      fs.stat(filePath)
    );
    insertRawSource(this.db, {
      source: this.metadata.source,
      filePath,
      collectedAt: new Date().toISOString(),
      rowCount,
      fileSizeBytes: stats.size,
      checksum,
    });

    return { filePath, rowCount };
  }

  /**
   * Navigate to ADREC dashboard and set broadest filters.
   *
   * The dashboard has filters for Asset Type, District, Project, Layout, currency, period.
   * This method clears/selects "All" to export maximum dataset.
   */
  private async setBroadestFilters(page: Page): Promise<void> {
    console.error("[adrec-abu-dhabi] Setting broadest filters...");

    // Wait for filter controls to load
    await page.waitForLoadState("networkidle");

    // Common filter patterns: dropdowns with "All" option or "Select All" checkboxes
    // Try to find and select "All" in common filter dropdowns
    const filterSelectors = [
      'select[name*="asset" i]',
      'select[name*="district" i]',
      'select[name*="project" i]',
      'select[name*="layout" i]',
      'select[name*="currency" i]',
    ];

    for (const selector of filterSelectors) {
      try {
        const dropdown = await page.waitForSelector(selector, {
          timeout: 2000,
        });
        if (dropdown) {
          // Try to select "All" option
          try {
            await dropdown.selectOption({ label: "All" });
          } catch {
            // Try lowercase
            try {
              await dropdown.selectOption({ label: "all" });
            } catch {
              // If "All" not available, use default
              console.error(
                `[adrec-abu-dhabi] "All" option not found in ${selector}, using default`
              );
            }
          }
        }
      } catch (err) {
        // Filter not found, continue
        continue;
      }
    }

    // Look for "Select All" checkboxes
    const selectAllCheckboxes = await page.$$('input[type="checkbox"]');
    for (const checkbox of selectAllCheckboxes) {
      const label = await checkbox.evaluate((el: any) => {
        const parent = el.closest("label");
        return parent?.textContent || "";
      });
      if (/select all|all/i.test(label)) {
        await checkbox.check();
        console.error(`[adrec-abu-dhabi] Checked "Select All" checkbox`);
      }
    }

    console.error("[adrec-abu-dhabi] Filters configured");
  }

  /**
   * Navigate to specific dashboard section/tab.
   *
   * ADREC has multiple sections: Transactions, Residential Leases, Price Indices, Recent Sales.
   * This method clicks the appropriate tab if it exists.
   */
  private async navigateToSection(
    page: Page,
    sectionName: string
  ): Promise<void> {
    // Try to find and click tab/section header
    const tabSelectors = [
      `button:has-text("${sectionName}")`,
      `a:has-text("${sectionName}")`,
      `[role="tab"]:has-text("${sectionName}")`,
      `li:has-text("${sectionName}")`,
    ];

    for (const selector of tabSelectors) {
      try {
        const tab = await page.waitForSelector(selector, { timeout: 2000 });
        if (tab) {
          await tab.click();
          await page.waitForLoadState("networkidle");
          console.error(
            `[adrec-abu-dhabi] Navigated to ${sectionName} section`
          );
          return;
        }
      } catch (err) {
        continue;
      }
    }

    // Section not found - may already be on it or single-page dashboard
    console.error(
      `[adrec-abu-dhabi] Section "${sectionName}" not found, assuming current view`
    );
  }

  /**
   * Collect ADREC data via Playwright browser automation.
   *
   * Downloads:
   * 1. Transactions CSV (primary)
   * 2. Residential Leases CSV (if available)
   * 3. Price Indices CSV (if available)
   *
   * Returns primary file (transactions) info.
   */
  async collect(): Promise<{ filePath: string; rowCount: number }> {
    try {
      // Launch browser with stealth options
      this.browser = await chromium.launch({
        headless: true,
        args: ["--disable-blink-features=AutomationControlled"],
      });

      const context = await this.browser.newContext({
        acceptDownloads: true,
        userAgent:
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        viewport: { width: 1920, height: 1080 },
      });

      const page = await context.newPage();

      // Navigate to ADREC dashboard
      console.error(
        `[adrec-abu-dhabi] Navigating to ${ADREC_DASHBOARD_URL}...`
      );
      await page.goto(ADREC_DASHBOARD_URL, { waitUntil: "networkidle" });

      // Set broadest filters
      await this.setBroadestFilters(page);

      let transactionsResult: { filePath: string; rowCount: number } | null =
        null;
      let totalRowCount = 0;

      // Download Transactions (primary)
      try {
        await this.navigateToSection(page, "Transactions");
        transactionsResult = await this.downloadSection(
          page,
          "Transactions",
          "transactions"
        );
        totalRowCount += transactionsResult.rowCount;
      } catch (error) {
        console.error(
          `[adrec-abu-dhabi] Failed to download Transactions: ${error}`
        );
        throw error; // Transactions are critical
      }

      // Download Residential Leases (optional)
      try {
        await this.navigateToSection(page, "Residential Leases");
        const leasesResult = await this.downloadSection(
          page,
          "Residential Leases",
          "leases"
        );
        totalRowCount += leasesResult.rowCount;
      } catch (error) {
        console.error(
          `[adrec-abu-dhabi] Failed to download Residential Leases (non-critical): ${error}`
        );
      }

      // Download Price Indices (optional)
      try {
        await this.navigateToSection(page, "Price Indices");
        const indicesResult = await this.downloadSection(
          page,
          "Price Indices",
          "indices"
        );
        totalRowCount += indicesResult.rowCount;
      } catch (error) {
        console.error(
          `[adrec-abu-dhabi] Failed to download Price Indices (non-critical): ${error}`
        );
      }

      if (!transactionsResult) {
        throw new Error("Failed to download primary Transactions file");
      }

      // Return primary file info (transactions) with total row count
      return {
        filePath: transactionsResult.filePath,
        rowCount: totalRowCount,
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
