/**
 * PROD-08: Salary-Rent Pressure Map
 *
 * Maps 5 income brackets to area-level rent affordability ratios with
 * flight-risk classification. Reads pre-computed affordability data from
 * the intelligence_cache (populated by analyze_affordability.py).
 *
 * Income brackets (AED/month):
 *   Low:        < 10,000
 *   Lower-Mid:  10,000 – 14,999
 *   Mid:        15,000 – 24,999
 *   Upper-Mid:  25,000 – 49,999
 *   High:       >= 50,000
 *
 * Flight risk thresholds (rent as % of income):
 *   critical  > 50%  — rent exceeds half of income
 *   high      > 35%
 *   moderate  > 25%
 *   low       <= 25%
 */

import type Database from "better-sqlite3";
import { truncate4K, freshnessFooter } from "./format.js";

/** Flight risk classification for an area×bracket pair. */
export type FlightRisk = "critical" | "high" | "moderate" | "low";

/** A single area within an income bracket. */
export interface AffordabilityArea {
  area: string;
  ratio: number;
  flightRisk: FlightRisk;
}

/** An income bracket with its area-level affordability data. */
export interface AffordabilityBracket {
  bracket: string;
  areas: AffordabilityArea[];
}

/** Result of the salary-rent pressure query. */
export interface SalaryRentResult {
  brackets: AffordabilityBracket[];
  formattedText: string;
}

/** Raw row from intelligence_cache. */
interface CacheRow {
  result_json: string;
  created_at: string;
}

/** Raw area shape from the cache JSON. */
interface RawArea {
  area?: string;
  ratio?: number;
  flight_risk?: string;
}

/** Raw bracket shape from the cache JSON. */
interface RawBracket {
  bracket?: string;
  areas?: RawArea[];
}

/** Raw shape of the affordability_latest cache entry. */
interface RawAffordabilityCache {
  brackets?: RawBracket[];
}

/**
 * Classify flight risk from an affordability ratio.
 *
 * @param ratio - Rent as a fraction of monthly income (0–1+)
 * @returns Flight risk classification
 */
function classifyFlightRisk(ratio: number): FlightRisk {
  if (ratio > 0.5) return "critical";
  if (ratio > 0.35) return "high";
  if (ratio > 0.25) return "moderate";
  return "low";
}

/**
 * Return a warning indicator for high-pressure flight risk.
 */
function flightRiskIndicator(risk: FlightRisk): string {
  if (risk === "critical") return " !!!";
  if (risk === "high") return " !!";
  return "";
}

/**
 * Query the salary-rent pressure map.
 *
 * Reads from the intelligence_cache table populated by the analysis pipeline.
 * Re-classifies flight risk using canonical thresholds (overrides any cached
 * classification to ensure consistency).
 *
 * @param db - Open better-sqlite3 database instance
 * @param incomeBracket - Optional bracket name to filter to a single bracket
 * @returns SalaryRentResult or null if cache is absent
 */
export function querySalaryRent(
  db: Database.Database,
  incomeBracket?: string
): SalaryRentResult | null {
  const row = db
    .prepare(
      "SELECT result_json, created_at FROM intelligence_cache WHERE cache_key = 'affordability_latest'"
    )
    .get() as CacheRow | undefined;

  if (!row) return null;

  let parsed: RawAffordabilityCache;
  try {
    parsed = JSON.parse(row.result_json) as RawAffordabilityCache;
  } catch {
    return null;
  }

  const rawBrackets = parsed.brackets ?? [];

  let brackets: AffordabilityBracket[] = rawBrackets.map((rb) => {
    const areas: AffordabilityArea[] = (rb.areas ?? []).map((ra) => {
      const ratio = ra.ratio ?? 0;
      return {
        area: ra.area ?? "Unknown",
        ratio,
        flightRisk: classifyFlightRisk(ratio),
      };
    });

    // Sort areas by ratio descending (most pressured first)
    areas.sort((a, b) => b.ratio - a.ratio);

    return {
      bracket: rb.bracket ?? "Unknown",
      areas,
    };
  });

  // Filter to a single bracket if requested
  if (incomeBracket !== undefined && incomeBracket.trim() !== "") {
    const normalized = incomeBracket.toLowerCase().trim();
    brackets = brackets.filter(
      (b) => b.bracket.toLowerCase().includes(normalized)
    );
  }

  const computedAt = row.created_at ?? new Date().toISOString();
  const lastDate = computedAt.slice(0, 10);
  const singleBracket = incomeBracket !== undefined && brackets.length === 1;

  const lines: string[] = ["SALARY-RENT PRESSURE MAP", ""];

  for (const bracket of brackets) {
    lines.push(`${bracket.bracket}:`);

    // Show all areas for single-bracket queries, top 5 for full view
    const displayAreas = singleBracket
      ? bracket.areas
      : bracket.areas.slice(0, 5);

    for (const area of displayAreas) {
      const pct = (area.ratio * 100).toFixed(1);
      const indicator = flightRiskIndicator(area.flightRisk);
      lines.push(`  ${area.area}: ${pct}% of income -> ${area.flightRisk}${indicator}`);
    }

    if (!singleBracket && bracket.areas.length > 5) {
      const remaining = bracket.areas.length - 5;
      lines.push(`  ...and ${remaining} more areas`);
    }

    lines.push("");
  }

  lines.push(freshnessFooter(lastDate));

  const formattedText = truncate4K(lines.join("\n"));

  return {
    brackets,
    formattedText,
  };
}
