/**
 * Volume Validation (NORM-05)
 *
 * Compares current collection volume to rolling baseline and warns
 * when volume drops below 50%.
 */

import type Database from "better-sqlite3";
import type { VolumeWarning } from "./types.js";

/**
 * Number of past successful collections to use for rolling average baseline.
 */
const BASELINE_WINDOW = 4;

/**
 * Threshold ratio (currentCount / rollingAverage) to trigger warning.
 */
const WARNING_THRESHOLD = 0.5; // 50%

/**
 * Validate current collection volume against rolling baseline.
 *
 * @param db - Database instance
 * @param source - Data source identifier
 * @param currentRowCount - Current collection row count
 * @returns Volume warning if validation fails, undefined if passes or baseline not established
 */
export function validateVolume(
  db: Database.Database,
  source: string,
  currentRowCount: number
): VolumeWarning | undefined {
  // Query last N successful collections (excluding current run)
  const stmt = db.prepare(`
    SELECT row_count
    FROM collection_log
    WHERE source = ? AND status = 'success' AND row_count IS NOT NULL
    ORDER BY timestamp DESC
    LIMIT ?
  `);

  const rows = stmt.all(source, BASELINE_WINDOW) as Array<{ row_count: number }>;

  // Need at least BASELINE_WINDOW runs to establish baseline
  if (rows.length < BASELINE_WINDOW) {
    return undefined;
  }

  // Calculate rolling average
  const sum = rows.reduce((acc, row) => acc + row.row_count, 0);
  const rollingAverage = sum / rows.length;

  // Check if current count is below threshold
  const ratio = currentRowCount / rollingAverage;

  if (ratio < WARNING_THRESHOLD) {
    return {
      source,
      currentCount: currentRowCount,
      rollingAverage,
      ratio,
    };
  }

  return undefined;
}
