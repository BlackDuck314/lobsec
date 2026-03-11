/**
 * Building Permits Collector
 *
 * Downloads Dubai Municipality building permits CSV from Dubai Pulse.
 * Provides supply pipeline data (new construction permits by area/type).
 * Frequency: Monthly, Priority: 2 (supply indicator, lower priority than transactions)
 */

import type Database from "better-sqlite3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { SourceCollector } from "./base.js";
import { insertRawSource } from "../db/queries.js";
import type { CollectorMetadata } from "./types.js";

/**
 * Collector for Dubai building permits from Dubai Pulse.
 */
export class BuildingPermitsCollector extends SourceCollector {
  private static readonly METADATA: CollectorMetadata = {
    source: "building-permits",
    frequency: "monthly",
    priority: 2,
    timeout: 120_000,
  };

  private static readonly SOURCE_URL =
    "https://www.dubaipulse.gov.ae/data/dm_building_permits/dm_building_permits-open";
  private static readonly RAW_DIR = "/opt/lobsec/data/raw/building-permits";

  constructor(db: Database.Database) {
    super(BuildingPermitsCollector.METADATA, db);
  }

  /**
   * Download building permits CSV from Dubai Pulse.
   *
   * @returns Object with filePath and rowCount
   * @throws Error if download fails or response is not OK
   */
  async collect(): Promise<{ filePath: string; rowCount: number }> {
    // Download CSV from Dubai Pulse
    const response = await fetch(BuildingPermitsCollector.SOURCE_URL);

    if (!response.ok) {
      throw new Error(
        `Failed to download building permits CSV: HTTP ${response.status} ${response.statusText}`
      );
    }

    const csvData = await response.text();

    // Prepare output path
    const date = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
    const fileName = `${date}.csv`;
    const filePath = path.join(BuildingPermitsCollector.RAW_DIR, fileName);

    // Create directory recursively
    await fs.mkdir(BuildingPermitsCollector.RAW_DIR, { recursive: true });

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
