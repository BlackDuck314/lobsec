/**
 * PROD-01: Area Buy/Sell Signal Score
 *
 * Queries the composite_scores table for the most recent area signal,
 * formats it for Telegram delivery, and returns a structured result
 * for use by Phase 12 plugin tools.
 *
 * SEC-06: Area validated against area_names table before querying.
 * Null returned gracefully when area not found or no data available.
 */

import type Database from "better-sqlite3";
import {
  truncate4K,
  freshnessFooter,
  trendArrow,
  zoneLabel,
} from "./format.js";

/**
 * A single contributing signal in the composite score.
 */
export interface AreaSignalComponent {
  source: string;
  metric: string;
  weight: number;
  zscore: number;
}

/**
 * Result from queryAreaSignal.
 *
 * formattedText is ready for Telegram delivery (4K truncated).
 * All numeric fields are available for Phase 12 tool integration.
 */
export interface AreaSignalResult {
  area: string;
  score: number;
  zone: string;
  componentCount: number;
  totalComponents: number;
  components: AreaSignalComponent[];
  computedAt: string;
  formattedText: string;
}

/**
 * Raw row from composite_scores table.
 */
interface CompositeRow {
  area: string;
  score: number;
  zone: string;
  component_count: number;
  total_components: number;
  components_json: string | null;
  computed_at: string;
}

/**
 * Raw component from components_json.
 */
interface RawComponent {
  source?: string;
  metric?: string;
  weight?: number;
  zscore?: number;
  // Python may use different field names
  signal_source?: string;
  signal_metric?: string;
}

/**
 * Query the area buy/sell signal score for a given area.
 *
 * Validates the area against area_names, fetches the most recent
 * composite score, parses components, computes a trend arrow vs the
 * prior period, and formats the result as a Telegram message.
 *
 * @param db - SQLite database instance
 * @param area - Canonical area name (validated against area_names)
 * @returns Structured result with formattedText, or null if area unknown or no data
 */
export function queryAreaSignal(
  db: Database.Database,
  area: string
): AreaSignalResult | null {
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

  // Fetch the two most recent composite scores for trend comparison
  const rows = db
    .prepare(
      `SELECT area, score, zone, component_count, total_components,
              components_json, computed_at
       FROM composite_scores
       WHERE area = ?
       ORDER BY computed_at DESC
       LIMIT 2`
    )
    .all(canonicalArea) as CompositeRow[];

  const current = rows[0];
  if (!current) {
    return null;
  }

  const previous = rows[1] ?? null;

  // Parse components_json into typed array
  let components: AreaSignalComponent[] = [];
  if (current.components_json) {
    try {
      const parsed = JSON.parse(current.components_json) as RawComponent[];
      components = parsed.map((c) => ({
        source: c.signal_source ?? c.source ?? "unknown",
        metric: c.signal_metric ?? c.metric ?? "unknown",
        weight: c.weight ?? 1.0,
        zscore: c.zscore ?? 0,
      }));
    } catch {
      // Malformed JSON — proceed with empty components
      components = [];
    }
  }

  // Sort by absolute zscore descending to find top contributors
  const topComponents = [...components]
    .sort((a, b) => Math.abs(b.zscore) - Math.abs(a.zscore))
    .slice(0, 5);

  // Build formatted Telegram text
  const trend = trendArrow(current.score, previous?.score ?? null);
  const label = zoneLabel(current.zone);
  const scoreStr = current.score.toFixed(3);

  const lines: string[] = [];

  lines.push(`📊 AREA SIGNAL — ${canonicalArea.toUpperCase()}`);
  lines.push("");
  lines.push(`Score: ${scoreStr} (${label}) ${trend}`);
  lines.push(
    `Coverage: ${current.component_count}/${current.total_components} components`
  );

  if (topComponents.length > 0) {
    lines.push("");
    lines.push("Top signals:");
    for (const comp of topComponents) {
      const dir = comp.zscore > 0 ? "^" : comp.zscore < 0 ? "v" : "=";
      const wt = comp.weight.toFixed(2);
      const zs = comp.zscore.toFixed(2);
      const shortMetric = comp.metric.split("|").pop() ?? comp.metric;
      lines.push(`  ${dir} ${comp.source}/${shortMetric} (w=${wt}, z=${zs})`);
    }
  }

  lines.push("");
  lines.push(freshnessFooter(current.computed_at.slice(0, 10)));

  const rawText = lines.join("\n");
  const formattedText = truncate4K(rawText);

  return {
    area: canonicalArea,
    score: current.score,
    zone: current.zone,
    componentCount: current.component_count,
    totalComponents: current.total_components,
    components,
    computedAt: current.computed_at,
    formattedText,
  };
}
