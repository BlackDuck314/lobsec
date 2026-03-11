/**
 * Gap Detection (NORM-03)
 *
 * Detects collection gaps and flags sources as STALE when gaps exceed
 * 2x expected frequency.
 */

import type Database from "better-sqlite3";
import type { CollectionFrequency } from "../collectors/types.js";
import type { GapWarning } from "./types.js";

/**
 * Expected interval in days for each collection frequency.
 */
const FREQUENCY_INTERVALS: Record<CollectionFrequency, number> = {
  daily: 1,
  weekly: 7,
  monthly: 30,
  quarterly: 90,
};

/**
 * Detect collection gaps for a data source.
 *
 * @param db - Database instance
 * @param source - Data source identifier
 * @param expectedFrequency - Expected collection frequency
 * @returns Array of gap warnings (empty if no gaps detected)
 */
export function detectGaps(
  db: Database.Database,
  source: string,
  expectedFrequency: CollectionFrequency
): GapWarning[] {
  // Query last successful collection
  const stmt = db.prepare(`
    SELECT timestamp, status
    FROM collection_log
    WHERE source = ? AND status = 'success'
    ORDER BY timestamp DESC
    LIMIT 1
  `);

  const lastRun = stmt.get(source) as
    | { timestamp: string; status: string }
    | undefined;

  if (!lastRun) {
    // No successful collections yet - not a gap, just hasn't run
    return [];
  }

  // Calculate gap in days
  const lastDate = new Date(lastRun.timestamp);
  const now = new Date();
  const gapMs = now.getTime() - lastDate.getTime();
  const gapDays = Math.floor(gapMs / (1000 * 60 * 60 * 24));

  const expectedInterval = FREQUENCY_INTERVALS[expectedFrequency];
  const staleThreshold = expectedInterval * 2;

  // If gap exceeds 2x expected frequency, flag as stale
  if (gapDays > staleThreshold) {
    return [
      {
        source,
        lastDate: lastRun.timestamp,
        expectedFrequency,
        gapDays,
        isStale: true,
      },
    ];
  }

  return [];
}
