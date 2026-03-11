/**
 * DLD Sales Collector
 *
 * Downloads Dubai Land Department transaction CSV from Dubai Pulse.
 * DLD and Ejari share the same source CSV (filtered during normalization).
 * Frequency: Weekly, Priority: 1 (core transaction data)
 */

import type Database from "better-sqlite3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { SourceCollector } from "./base.js";
import { insertRawSource } from "../db/queries.js";
import type { CollectorMetadata } from "./types.js";

/**
 * Collector for DLD sales transactions from Dubai Pulse.
 */
export class DLDSalesCollector extends SourceCollector {
  private static readonly METADATA: CollectorMetadata = {
    source: "dld-sales",
    frequency: "weekly",
    priority: 1,
    timeout: 120_000,
  };

  private static readonly SOURCE_URL =
    "https://www.dubaipulse.gov.ae/data/dld-transactions/dld_transactions-open";
  private static readonly RAW_DIR = "/opt/lobsec/data/raw/dld-sales";

  constructor(db: Database.Database) {
    super(DLDSalesCollector.METADATA, db);
  }

  /**
   * Download DLD transactions CSV from Dubai Pulse.
   *
   * @returns Object with filePath and rowCount
   * @throws Error if download fails or response is not OK
   */
  async collect(): Promise<{ filePath: string; rowCount: number }> {
    // Download CSV from Dubai Pulse
    const response = await fetch(DLDSalesCollector.SOURCE_URL);

    if (!response.ok) {
      throw new Error(
        `Failed to download DLD CSV: HTTP ${response.status} ${response.statusText}`
      );
    }

    const csvData = await response.text();

    // Prepare output path
    const date = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
    const fileName = `${date}.csv`;
    const filePath = path.join(DLDSalesCollector.RAW_DIR, fileName);

    // Create directory recursively
    await fs.mkdir(DLDSalesCollector.RAW_DIR, { recursive: true });

    // Write CSV to disk
    await fs.writeFile(filePath, csvData, "utf-8");

    // Count rows (subtract 1 for header)
    const lines = csvData.trim().split("\n");
    const rowCount = Math.max(0, lines.length - 1);

    // Log to raw_sources table
    insertRawSource(this.db, {
      source: this.metadata.source,
      filePath,
      collectedAt: new Date().toISOString(),
      rowCount,
    });

    return { filePath, rowCount };
  }
}
