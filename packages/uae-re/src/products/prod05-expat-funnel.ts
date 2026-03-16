/**
 * PROD-05: Expat Population Flow Dashboard
 *
 * Reads the pre-computed expat funnel from the intelligence_cache and renders
 * a 10-stage lifecycle visualization with z-score bars and direction indicators.
 *
 * Data source: intelligence_cache WHERE cache_key = 'expat_funnel_latest'
 * (populated by analyze_expat_funnel.py in the pipeline)
 *
 * City-wide product — no area parameter. The funnel represents an
 * emirate-level view of expat population flow.
 */

import type Database from "better-sqlite3";
import { truncate4K, freshnessFooter } from "./format.js";

/** A single stage in the expat lifecycle funnel. */
export interface FunnelStage {
  name: string;
  stageNum: number;
  zscore: number;
  direction: "up" | "down" | "flat";
}

/** Result of the expat funnel query. */
export interface ExpatFunnelResult {
  stages: FunnelStage[];
  overallDirection: string;
  digestText: string;
  computedAt: string;
  formattedText: string;
}

/** Raw row from intelligence_cache. */
interface CacheRow {
  result_json: string;
  computed_at: string;
}

/** Raw stage shape from the cache JSON. */
interface RawStage {
  name?: string;
  stage_num?: number;
  zscore?: number;
  direction?: string;
}

/** Raw shape of the expat_funnel_latest cache entry. */
interface RawFunnelCache {
  stages?: RawStage[];
  digest_text?: string;
  summary?: string;
}

/**
 * Query the expat population flow dashboard.
 *
 * Reads from the intelligence_cache table populated by the analysis pipeline.
 * Returns null if the cache entry is absent (pipeline hasn't run yet).
 *
 * @param db - Open better-sqlite3 database instance
 * @returns Expat funnel result or null if cache is absent
 */
export function queryExpatFunnel(db: Database.Database): ExpatFunnelResult | null {
  const row = db
    .prepare(
      "SELECT result_json, computed_at FROM intelligence_cache WHERE cache_key = 'expat_funnel_latest'"
    )
    .get() as CacheRow | undefined;

  if (!row) return null;

  let parsed: RawFunnelCache;
  try {
    parsed = JSON.parse(row.result_json) as RawFunnelCache;
  } catch {
    return null;
  }

  const rawStages = parsed.stages ?? [];
  const stages: FunnelStage[] = rawStages.map((s) => ({
    name: s.name ?? "Unknown",
    stageNum: s.stage_num ?? 0,
    zscore: s.zscore ?? 0,
    direction:
      s.direction === "up" || s.direction === "down" || s.direction === "flat"
        ? s.direction
        : s.direction === "positive"
          ? "up"
          : s.direction === "negative"
            ? "down"
            : "flat",
  }));

  // Count positive vs negative z-scores for overall direction
  const positiveCount = stages.filter((s) => s.zscore > 0).length;
  const negativeCount = stages.filter((s) => s.zscore < 0).length;
  const total = stages.length;

  let overallDirection: string;
  if (positiveCount > negativeCount) {
    overallDirection = `${positiveCount}/${total} stages positive — net inflow trend`;
  } else if (negativeCount > positiveCount) {
    overallDirection = `Net outflow detected (${negativeCount}/${total} stages negative)`;
  } else {
    overallDirection = `${total} stages balanced — neutral flow`;
  }

  const digestText =
    parsed.digest_text ?? parsed.summary ?? "Funnel computed (no summary available)";

  const computedAt = row.computed_at ?? new Date().toISOString();
  const lastDate = computedAt.slice(0, 10);

  const lines: string[] = [
    "EXPAT LIFECYCLE FUNNEL",
    "",
    digestText,
    "",
    overallDirection,
    "",
    freshnessFooter(lastDate),
  ];

  const formattedText = truncate4K(lines.join("\n"));

  return {
    stages,
    overallDirection,
    digestText,
    computedAt,
    formattedText,
  };
}
