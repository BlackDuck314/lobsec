/**
 * Normalization Orchestrator (NORM-02)
 *
 * Auto-triggers normalization after collection, calls per-source Python
 * normalization module, and upserts to normalized_monthly table.
 */

import type Database from "better-sqlite3";
import { runPython } from "../analytics/bridge.js";
import { insertNormalized, deleteNormalizedRange } from "../db/queries.js";
import type { CollectionResult, CollectionFrequency } from "../collectors/types.js";
import type {
  NormalizationInput,
  NormalizationResult,
  NormalizedRecord,
} from "./types.js";
import { SOURCE_MODULE_MAP } from "./types.js";
import { detectGaps } from "./gap-detection.js";
import { validateVolume } from "./volume-validation.js";

/**
 * Timeout for Python normalization calls (120s for larger datasets).
 */
const NORMALIZATION_TIMEOUT_MS = 120000;

/**
 * Normalize collection result and upsert to normalized_monthly table.
 *
 * Called automatically after each successful collection.
 * - Looks up per-source Python normalization module
 * - Calls Python with collection file path
 * - Upserts normalized records (DELETE+INSERT for date range)
 * - Runs gap detection and volume validation
 *
 * @param db - Database instance
 * @param source - Data source identifier
 * @param collectionResult - Result from collector
 * @param expectedFrequency - Expected collection frequency for gap detection
 * @returns Normalization result with gap/volume warnings
 */
export async function normalizeCollectionResult(
  db: Database.Database,
  source: string,
  collectionResult: CollectionResult,
  expectedFrequency: CollectionFrequency
): Promise<NormalizationResult> {
  // Validate inputs
  if (!collectionResult.success || !collectionResult.filePath) {
    throw new Error(`Cannot normalize failed collection for source: ${source}`);
  }

  // Look up Python normalization module
  const moduleName = SOURCE_MODULE_MAP[source];
  if (!moduleName) {
    throw new Error(`No normalization module mapped for source: ${source}`);
  }

  // Prepare input for Python normalization module
  const input: NormalizationInput = {
    filePath: collectionResult.filePath,
    source,
    collectedAt: new Date().toISOString(),
  };

  // Call Python normalization module
  const pythonResult = await runPython<NormalizedRecord[]>(
    moduleName as any, // Type assertion - module names are validated via SOURCE_MODULE_MAP
    input,
    { defaultTimeoutMs: NORMALIZATION_TIMEOUT_MS }
  );

  if (!pythonResult.success || !pythonResult.data) {
    throw new Error(
      `Python normalization failed for ${source}: ${pythonResult.error || "Unknown error"}`
    );
  }

  const normalizedRecords = pythonResult.data;

  if (normalizedRecords.length === 0) {
    throw new Error(`Python normalization returned 0 records for ${source}`);
  }

  // Compute measurement date range
  const measurementDates = normalizedRecords.map((r) => r.measurement_date);
  const startDate = measurementDates.reduce((min, date) =>
    date < min ? date : min
  );
  const endDate = measurementDates.reduce((max, date) =>
    date > max ? date : max
  );

  // Upsert: DELETE existing data in date range, then INSERT new data
  const upsert = db.transaction(() => {
    // Step 1: Delete existing data for this date range
    deleteNormalizedRange(db, source, startDate, endDate);

    // Step 2: Insert normalized records
    const monthlyDataPoints = normalizedRecords.map((record) => ({
      source: record.source,
      measurementDate: record.measurement_date,
      metricName: record.metric_name,
      value: record.value,
      availableDate: record.available_date,
    }));

    insertNormalized(db, monthlyDataPoints);
  });

  upsert();

  // Run gap detection
  const gapWarnings = detectGaps(db, source, expectedFrequency);

  // Run volume validation
  const volumeWarning = validateVolume(
    db,
    source,
    collectionResult.rowCount ?? normalizedRecords.length
  );

  return {
    source,
    recordCount: normalizedRecords.length,
    measurementDateRange: { start: startDate, end: endDate },
    gapWarnings,
    volumeWarning,
  };
}
