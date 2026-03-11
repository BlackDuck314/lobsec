/**
 * Ejari Rentals Collector
 *
 * Downloads the same Dubai Pulse CSV as DLD collector (both from dld-transactions).
 * Filtering by trans_group_en=Rent happens during Python normalization.
 * Frequency: Weekly, Priority: 1 (core rental data)
 */

import type Database from "better-sqlite3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { SourceCollector } from "./base.js";
import { insertRawSource } from "../db/queries.js";
import type { CollectorMetadata } from "./types.js";

/**
 * Collector for Ejari rental transactions from Dubai Pulse.
 */
export class EjariRentalsCollector extends SourceCollector {
  private static readonly METADATA: CollectorMetadata = {
    source: "ejari-rentals",
    frequency: "weekly",
    priority: 1,
    timeout: 120_000,
  };

  private static readonly SOURCE_URL =
    "https://www.dubaipulse.gov.ae/data/dld-transactions/dld_transactions-open";
  private static readonly RAW_DIR = "/opt/lobsec/data/raw/ejari-rentals";

  constructor(db: Database.Database) {
    super(EjariRentalsCollector.METADATA, db);
  }

  /**
   * Download DLD transactions CSV from Dubai Pulse (same as DLD collector).
   * The filtering by trans_group_en=Rent happens in normalize_ejari.py.
   *
   * @returns Object with filePath and rowCount
   * @throws Error if download fails or response is not OK
   */
  async collect(): Promise<{ filePath: string; rowCount: number }> {
    // Download CSV from Dubai Pulse (same URL as DLD)
    const response = await fetch(EjariRentalsCollector.SOURCE_URL);

    if (!response.ok) {
      throw new Error(
        `Failed to download Ejari CSV: HTTP ${response.status} ${response.statusText}`
      );
    }

    const csvData = await response.text();

    // Prepare output path
    const date = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
    const fileName = `${date}.csv`;
    const filePath = path.join(EjariRentalsCollector.RAW_DIR, fileName);

    // Create directory recursively
    await fs.mkdir(EjariRentalsCollector.RAW_DIR, { recursive: true });

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
