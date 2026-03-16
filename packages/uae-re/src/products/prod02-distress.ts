/**
 * PROD-02: Distress Detection System
 *
 * Computes a 17-signal distress score for a given area:
 *   - 8 market signals from normalized_monthly
 *   - 9 lifecycle signals from intelligence_cache (expat_funnel_latest)
 *
 * Weighting: Granger-derived (1/p-value) where available, equal weight (1.0) otherwise.
 * Score: tanh(weighted_avg_z / 2) scaled to [-1, +1], positive = more distress.
 * Alert threshold: >= 0.6 at area level ONLY (no city-wide threshold).
 *
 * SEC-06: Area validated against area_names table before querying.
 * Null returned gracefully when area not found. Missing data handled gracefully.
 */

import type Database from "better-sqlite3";
import {
  truncate4K,
  freshnessFooter,
} from "./format.js";

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/**
 * A single market signal contributing to the distress score.
 */
export interface MarketSignal {
  name: string;
  value: number | null;
  weight: number;
  direction: "up" | "down" | "flat" | "unavailable";
}

/**
 * A single expat lifecycle signal (stages 2–10) contributing to the distress score.
 */
export interface LifecycleSignal {
  stage: string;
  zscore: number | null;
  direction: "up" | "down" | "flat" | "unavailable";
}

/**
 * Result from queryDistress.
 *
 * formattedText is ready for Telegram delivery (4K truncated).
 * alertTriggered is true when score >= 0.6 (area-level only).
 */
export interface DistressResult {
  area: string;
  score: number;
  zone: "normal" | "elevated" | "critical";
  marketSignals: MarketSignal[];
  lifecycleSignals: LifecycleSignal[];
  alertTriggered: boolean;
  computedAt: string;
  formattedText: string;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Map a numeric z-score to a direction string.
 */
function zscoreDirection(
  z: number | null
): "up" | "down" | "flat" | "unavailable" {
  if (z === null) return "unavailable";
  if (z > 0.1) return "up";
  if (z < -0.1) return "down";
  return "flat";
}

/**
 * Classify distress score into zone.
 */
function distressZone(score: number): "normal" | "elevated" | "critical" {
  if (score >= 0.6) return "critical";
  if (score >= 0.3) return "elevated";
  return "normal";
}

/**
 * Retrieve the Granger-derived weight (1/pvalue) for a given signal+target pair.
 * Returns 1.0 (equal weight) when no significant Granger result exists.
 */
function getGrangerWeight(
  db: Database.Database,
  signalSource: string,
  signalMetric: string
): number {
  const row = db
    .prepare(
      `SELECT pvalue
       FROM granger_results
       WHERE signal_source = ?
         AND signal_metric = ?
         AND significant = 1
       ORDER BY tested_at DESC
       LIMIT 1`
    )
    .get(signalSource, signalMetric) as { pvalue: number } | undefined;

  if (row && row.pvalue > 0) {
    return 1.0 / row.pvalue;
  }
  return 1.0;
}

/**
 * Query the most recent value and the prior month value for a normalized_monthly metric.
 * Returns [current, previous] where either may be null.
 */
function getLatestTwoValues(
  db: Database.Database,
  source: string,
  metricPattern: string
): [number | null, number | null] {
  const rows = db
    .prepare(
      `SELECT value
       FROM normalized_monthly
       WHERE source = ?
         AND metric_name LIKE ?
       ORDER BY measurement_date DESC
       LIMIT 2`
    )
    .all(source, metricPattern) as { value: number | null }[];

  return [rows[0]?.value ?? null, rows[1]?.value ?? null];
}

/**
 * Compute a z-score by comparing current vs the rolling recent window.
 * Simple approach: z = (current - mean) / stddev using last 12 months.
 */
function computeZScore(
  db: Database.Database,
  source: string,
  metricPattern: string
): number | null {
  const rows = db
    .prepare(
      `SELECT value
       FROM normalized_monthly
       WHERE source = ?
         AND metric_name LIKE ?
         AND value IS NOT NULL
       ORDER BY measurement_date DESC
       LIMIT 12`
    )
    .all(source, metricPattern) as { value: number }[];

  if (rows.length < 3) return null;

  const values = rows.map((r) => r.value);
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance =
    values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
  const stddev = Math.sqrt(variance);
  if (stddev === 0) return 0;

  const current = values[0];
  if (current === undefined) return null;
  return (current - mean) / stddev;
}

/**
 * Read the expat funnel cache entry and extract stage z-scores.
 * Returns null[] for all stages if cache absent.
 */
function getLifecycleZScores(
  db: Database.Database
): Record<string, number | null> {
  const row = db
    .prepare(
      `SELECT result_json
       FROM intelligence_cache
       WHERE cache_key = 'expat_funnel_latest'
         AND expires_at > datetime('now')
       LIMIT 1`
    )
    .get() as { result_json: string } | undefined;

  if (!row) {
    return {};
  }

  try {
    const data = JSON.parse(row.result_json) as Record<string, unknown>;
    const result: Record<string, number | null> = {};

    // Expected structure: { stages: [{ name, zscore }, ...] }
    // or flat: { stage_name: zscore, ... }
    if (Array.isArray(data["stages"])) {
      for (const s of data["stages"] as Array<{
        name?: string;
        stage?: string;
        zscore?: number | null;
      }>) {
        const name = s.name ?? s.stage ?? "unknown";
        result[name] = s.zscore ?? null;
      }
    } else {
      // Flat format: keys are stage names, values are zscores
      for (const [k, v] of Object.entries(data)) {
        if (typeof v === "number" || v === null) {
          result[k] = v as number | null;
        }
      }
    }
    return result;
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// Expat lifecycle stage names (stages 2–10)
// ---------------------------------------------------------------------------

const EXPAT_STAGES = [
  "Job Search",
  "Visa Application",
  "Relocation",
  "Housing Search",
  "Settlement",
  "Integration",
  "Long-term Residence",
  "Pre-exit Planning",
  "Exit",
];

// ---------------------------------------------------------------------------
// Main query function
// ---------------------------------------------------------------------------

/**
 * Query the distress detection score for a given area.
 *
 * Validates area against area_names, queries 8 market signals and 9 lifecycle
 * signals, applies Granger-derived weighting, computes tanh-scaled score,
 * and formats for Telegram delivery.
 *
 * Alert threshold >= 0.6 is applied at area level ONLY.
 *
 * @param db - SQLite database instance
 * @param area - Canonical area name (validated against area_names)
 * @returns Structured DistressResult with formattedText, or null if area unknown
 */
export function queryDistress(
  db: Database.Database,
  area: string
): DistressResult | null {
  // SEC-06: Validate area against area_names (parameterized SQL)
  const areaRow = db
    .prepare(
      "SELECT canonical_name FROM area_names WHERE LOWER(canonical_name) = LOWER(?)"
    )
    .get(area) as { canonical_name: string } | undefined;

  if (!areaRow) {
    return null;
  }

  const canonicalArea = areaRow.canonical_name;

  // ---------------------------------------------------------------------------
  // 8 market signals
  // ---------------------------------------------------------------------------

  // Signal 1: DLD price YoY decline — negative = distress
  // metric_name format: "{area}|median_price_yoy" from dld-sales source
  const areaKey = canonicalArea.toLowerCase().replace(/\s+/g, "_");
  const [dldCurrent, dldPrevious] = getLatestTwoValues(
    db,
    "dld-sales",
    `%${areaKey}%|median_price_yoy`
  );
  const dldPriceZ = computeZScore(
    db,
    "dld-sales",
    `%${areaKey}%|median_price_yoy`
  );
  // Negative price YoY = distress → invert sign
  const dldPriceDistressZ =
    dldPriceZ !== null ? -dldPriceZ : null;

  // Signal 2: Listing DOM increase — higher DOM = distress
  const [domCurrent, domPrevious] = getLatestTwoValues(
    db,
    "bayut",
    `%${areaKey}%|avg_dom`
  );
  const domZ = computeZScore(db, "bayut", `%${areaKey}%|avg_dom`);
  // Higher DOM = distress → keep sign positive
  const domDistressZ = domZ;

  // Signal 3: Price reduction count — more reductions = distress
  const [prReducedCurrent, prReducedPrevious] = getLatestTwoValues(
    db,
    "bayut",
    `%${areaKey}%|price_reduced`
  );
  const prReducedZ = computeZScore(
    db,
    "bayut",
    `%${areaKey}%|price_reduced`
  );
  const prReducedDistressZ = prReducedZ;

  // Signal 4: Permit withdrawal rate — higher = distress
  // Metric may not be area-specific; use city-level if area-level absent
  const [permWithdrawnCurrent, permWithdrawnPrevious] = getLatestTwoValues(
    db,
    "permits",
    `%withdrawn_count%`
  );
  const permWithdrawnZ = computeZScore(db, "permits", `%withdrawn_count%`);
  const permWithdrawnDistressZ = permWithdrawnZ;

  // Signal 5: DEWA disconnection surge — higher = distress
  const [dewaCurrent, dewaPrevious] = getLatestTwoValues(
    db,
    "dewa",
    `%disconnections%`
  );
  const dewaZ = computeZScore(db, "dewa", `%disconnections%`);
  const dewaDistressZ = dewaZ;

  // Signal 6: F&B closure rate — higher = distress
  const [fbClosureCurrent, fbClosurePrevious] = getLatestTwoValues(
    db,
    "fb_closures",
    `%closure_count%`
  );
  const fbClosureZ = computeZScore(db, "fb_closures", `%closure_count%`);
  const fbClosureDistressZ = fbClosureZ;

  // Signal 7: Mortgage rate increase — higher = distress
  const [mortgageCurrent, mortgagePrevious] = getLatestTwoValues(
    db,
    "mortgages",
    `%mortgage_rate%`
  );
  const mortgageZ = computeZScore(db, "mortgages", `%mortgage_rate%`);
  const mortgageDistressZ = mortgageZ;

  // Signal 8: Listing-to-transaction ratio (derived) — higher = oversupply = distress
  const bayutListingZ = computeZScore(
    db,
    "bayut",
    `%${areaKey}%|listing_count`
  );
  const dldTransZ = computeZScore(
    db,
    "dld-sales",
    `%${areaKey}%|transaction_count`
  );
  let ltRatioDistressZ: number | null = null;
  {
    const rows = db
      .prepare(
        `SELECT b.value AS listing_count,
                d.value AS trans_count,
                b.measurement_date
         FROM normalized_monthly b
         LEFT JOIN normalized_monthly d
           ON d.source = 'dld-sales'
          AND d.measurement_date = b.measurement_date
          AND d.metric_name LIKE ?
         WHERE b.source = 'bayut'
           AND b.metric_name LIKE ?
           AND b.value IS NOT NULL
         ORDER BY b.measurement_date DESC
         LIMIT 12`
      )
      .all(
        `%${areaKey}%|transaction_count`,
        `%${areaKey}%|listing_count`
      ) as { listing_count: number; trans_count: number | null }[];

    const ratios = rows
      .filter(
        (r) =>
          r.trans_count !== null &&
          r.trans_count > 0 &&
          r.listing_count !== null
      )
      .map((r) => r.listing_count / r.trans_count!);

    if (ratios.length >= 3) {
      const mean = ratios.reduce((a, b) => a + b, 0) / ratios.length;
      const variance =
        ratios.reduce((a, b) => a + (b - mean) ** 2, 0) / ratios.length;
      const std = Math.sqrt(variance);
      if (std > 0 && ratios[0] !== undefined) {
        ltRatioDistressZ = (ratios[0] - mean) / std;
      }
    }
  }

  // Collect market signals with their distress z-scores
  const rawMarketSignals: Array<{
    name: string;
    source: string;
    metric: string;
    current: number | null;
    previous: number | null;
    distressZ: number | null;
  }> = [
    {
      name: "Price YoY Decline",
      source: "dld-sales",
      metric: `${areaKey}|median_price_yoy`,
      current: dldCurrent,
      previous: dldPrevious,
      distressZ: dldPriceDistressZ,
    },
    {
      name: "Listing DOM Increase",
      source: "bayut",
      metric: `${areaKey}|avg_dom`,
      current: domCurrent,
      previous: domPrevious,
      distressZ: domDistressZ,
    },
    {
      name: "Price Reduction Count",
      source: "bayut",
      metric: `${areaKey}|price_reduced`,
      current: prReducedCurrent,
      previous: prReducedPrevious,
      distressZ: prReducedDistressZ,
    },
    {
      name: "Permit Withdrawal Rate",
      source: "permits",
      metric: "withdrawn_count",
      current: permWithdrawnCurrent,
      previous: permWithdrawnPrevious,
      distressZ: permWithdrawnDistressZ,
    },
    {
      name: "DEWA Disconnection Surge",
      source: "dewa",
      metric: "disconnections",
      current: dewaCurrent,
      previous: dewaPrevious,
      distressZ: dewaDistressZ,
    },
    {
      name: "F&B Closure Rate",
      source: "fb_closures",
      metric: "closure_count",
      current: fbClosureCurrent,
      previous: fbClosurePrevious,
      distressZ: fbClosureDistressZ,
    },
    {
      name: "Mortgage Rate Increase",
      source: "mortgages",
      metric: "mortgage_rate",
      current: mortgageCurrent,
      previous: mortgagePrevious,
      distressZ: mortgageDistressZ,
    },
    {
      name: "Listing-to-Transaction Ratio",
      source: "bayut",
      metric: `${areaKey}|listing_count`,
      current: null, // derived ratio
      previous: null,
      distressZ: ltRatioDistressZ,
    },
  ];

  // Build MarketSignal[] with Granger-derived weights
  const marketSignals: MarketSignal[] = rawMarketSignals.map((s) => {
    const weight = getGrangerWeight(db, s.source, s.metric);
    let direction: MarketSignal["direction"] = "unavailable";
    if (s.distressZ !== null) {
      if (s.distressZ > 0.1) direction = "up";
      else if (s.distressZ < -0.1) direction = "down";
      else direction = "flat";
    }
    return {
      name: s.name,
      value: s.current,
      weight,
      direction,
    };
  });

  // ---------------------------------------------------------------------------
  // 9 lifecycle signals (stages 2–10) from intelligence_cache
  // ---------------------------------------------------------------------------

  const lcZScores = getLifecycleZScores(db);

  const lifecycleSignals: LifecycleSignal[] = EXPAT_STAGES.map((stage) => {
    // Try exact match or partial match in cache keys
    const zscore =
      lcZScores[stage] ??
      lcZScores[stage.toLowerCase().replace(/\s+/g, "_")] ??
      null;
    return {
      stage,
      zscore,
      direction: zscoreDirection(zscore),
    };
  });

  // ---------------------------------------------------------------------------
  // Score computation
  // ---------------------------------------------------------------------------

  // Collect all (z, weight) pairs for available signals
  const weightedPairs: Array<{ z: number; w: number }> = [];

  for (let i = 0; i < rawMarketSignals.length; i++) {
    const s = rawMarketSignals[i];
    const m = marketSignals[i];
    if (s === undefined || m === undefined) continue;
    if (s.distressZ !== null) {
      weightedPairs.push({ z: s.distressZ, w: m.weight });
    }
  }

  for (const ls of lifecycleSignals) {
    if (ls.zscore !== null) {
      // Negative lifecycle z-score = deterioration = distress → invert
      weightedPairs.push({ z: -ls.zscore, w: 1.0 });
    }
  }

  let score = 0;
  if (weightedPairs.length > 0) {
    const totalWeight = weightedPairs.reduce((a, b) => a + b.w, 0);
    if (totalWeight > 0) {
      const weightedAvg =
        weightedPairs.reduce((a, b) => a + b.z * b.w, 0) / totalWeight;
      score = Math.tanh(weightedAvg / 2);
    }
  }

  // Clamp to [0, 1] for distress (positive direction only in final output)
  // tanh output is already in (-1, +1); positive means distress
  const clampedScore = Math.max(0, score);
  const zone = distressZone(clampedScore);
  const alertTriggered = clampedScore >= 0.6; // Area level ONLY

  // ---------------------------------------------------------------------------
  // Format Telegram text
  // ---------------------------------------------------------------------------

  const computedAt = new Date().toISOString();
  const lines: string[] = [];

  lines.push(`⚠️ DISTRESS DETECTION — ${canonicalArea.toUpperCase()}`);
  lines.push("");
  lines.push(
    `Distress Score: ${clampedScore.toFixed(3)} (${zone.toUpperCase()})`
  );

  if (alertTriggered) {
    lines.push(`🚨 ALERT THRESHOLD EXCEEDED`);
  }

  lines.push(
    `Signals: ${weightedPairs.length}/17 available`
  );

  // Top 3–5 distress signals (highest positive distress z-scores)
  const topMarket = [...rawMarketSignals]
    .filter((s) => s.distressZ !== null && s.distressZ > 0)
    .sort((a, b) => (b.distressZ ?? 0) - (a.distressZ ?? 0))
    .slice(0, 3);

  if (topMarket.length > 0) {
    lines.push("");
    lines.push("Top distress signals:");
    for (const s of topMarket) {
      const severity =
        (s.distressZ ?? 0) > 1.5
          ? "HIGH"
          : (s.distressZ ?? 0) > 0.75
          ? "MED"
          : "LOW";
      lines.push(`  🔴 ${s.name} [${severity}]`);
    }
  }

  // Lifecycle signals summary (only mention if any negative z-score stages)
  const deterioratingStages = lifecycleSignals
    .filter((ls) => ls.zscore !== null && ls.zscore < -0.5)
    .map((ls) => ls.stage);

  if (deterioratingStages.length > 0) {
    lines.push("");
    lines.push(
      `Lifecycle: ${deterioratingStages.slice(0, 3).join(", ")} deteriorating`
    );
  }

  lines.push("");
  lines.push(freshnessFooter(computedAt.slice(0, 10)));

  const rawText = lines.join("\n");
  const formattedText = truncate4K(rawText);

  return {
    area: canonicalArea,
    score: clampedScore,
    zone,
    marketSignals,
    lifecycleSignals,
    alertTriggered,
    computedAt,
    formattedText,
  };
}
