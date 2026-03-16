/**
 * PROD-06: Macro Health Dashboard
 *
 * Computes a traffic light (green/amber/red) health assessment across 6
 * signal groups. Each group is evaluated by averaging z-scores of 2 signals
 * from the normalized_monthly table.
 *
 * Traffic light thresholds:
 *   green  = avg z-score >= 0.3
 *   red    = avg z-score <= -0.3
 *   amber  = -0.3 < z < 0.3
 *
 * Note: sentiment.bearish_ratio z-score is INVERTED (multiply by -1) because
 * lower bearish activity indicates a more positive macro signal.
 */

import type Database from "better-sqlite3";
import { truncate4K, freshnessFooter } from "./format.js";

/** Traffic light colour for a group or the overall dashboard. */
type TrafficLight = "green" | "amber" | "red";

/** A single signal within a macro health group. */
export interface MacroSignal {
  source: string;
  metric: string;
  zscore: number | null;
  available: boolean;
}

/** A signal group with its aggregated traffic light. */
export interface MacroHealthGroup {
  name: string;
  light: TrafficLight;
  avgZscore: number | null;
  signals: MacroSignal[];
}

/** Result of the macro health query. */
export interface MacroHealthResult {
  groups: MacroHealthGroup[];
  overallLight: TrafficLight;
  formattedText: string;
}

/** Raw row from normalized_monthly. */
interface NormalizedRow {
  measurement_date: string;
  value: number;
}

/** Signal group definition. */
interface SignalGroupDef {
  name: string;
  signals: Array<{ source: string; metric: string; invertScore?: boolean }>;
}

/** The 6 macro health signal groups. */
const SIGNAL_GROUPS: SignalGroupDef[] = [
  {
    name: "Employment",
    signals: [
      { source: "jobs", metric: "total_postings" },
      { source: "mohre", metric: "new_permits_total" },
    ],
  },
  {
    name: "Housing",
    signals: [
      { source: "ejari", metric: "new_contracts" },
      { source: "bayut", metric: "listing_count" },
    ],
  },
  {
    name: "Spending",
    signals: [
      { source: "licenses", metric: "new_licenses" },
      { source: "rta", metric: "new_registrations" },
    ],
  },
  {
    name: "Mobility",
    signals: [
      { source: "dxb", metric: "passenger_arrivals" },
      { source: "metro", metric: "ridership" },
    ],
  },
  {
    name: "Sentiment",
    signals: [
      { source: "sentiment", metric: "bearish_ratio", invertScore: true },
      { source: "trends", metric: "expat_interest" },
    ],
  },
  {
    name: "Population",
    signals: [
      { source: "gdrfa", metric: "visa_issuances" },
      { source: "demographics", metric: "population_total" },
    ],
  },
];

/**
 * Determine traffic light colour from an average z-score.
 */
function toTrafficLight(avgZscore: number | null): TrafficLight {
  if (avgZscore === null) return "amber";
  if (avgZscore >= 0.3) return "green";
  if (avgZscore <= -0.3) return "red";
  return "amber";
}

/**
 * Compute the z-score of the most recent value in a 12-month series.
 *
 * Mirrors analyze_composite.py fetch_signal_zscore:
 *   (latest_value - mean(series)) / std(series)
 *
 * Returns null when fewer than 3 observations are available
 * (insufficient for a meaningful z-score).
 */
function computeZscore(values: number[]): number | null {
  if (values.length < 3) return null;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance =
    values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
  const std = Math.sqrt(variance);
  if (std === 0) return 0;
  const latest = values[values.length - 1]!;
  return (latest - mean) / std;
}

/**
 * Return the traffic light emoji for display.
 */
function lightEmoji(light: TrafficLight): string {
  switch (light) {
    case "green":
      return "🟢";
    case "red":
      return "🔴";
    case "amber":
    default:
      return "🟡";
  }
}

/**
 * Query the macro health dashboard.
 *
 * Computes z-scores from the last 12 months of normalized data per signal.
 * Returns null only if ALL signals across ALL groups are unavailable.
 * Partial data is valid — unavailable signals are omitted from averages.
 *
 * @param db - Open better-sqlite3 database instance
 * @returns MacroHealthResult or null if no data at all
 */
export function queryMacroHealth(db: Database.Database): MacroHealthResult | null {
  const stmt = db.prepare(
    "SELECT measurement_date, value FROM normalized_monthly WHERE source = ? AND metric_name = ? ORDER BY measurement_date DESC LIMIT 12"
  );

  let anyDataFound = false;
  const groups: MacroHealthGroup[] = [];
  let allGroupZscores: number[] = [];

  // Track the latest measurement_date across all signals for the freshness footer
  let latestDate = "unknown";

  for (const groupDef of SIGNAL_GROUPS) {
    const macroSignals: MacroSignal[] = [];
    const groupZscores: number[] = [];

    for (const sigDef of groupDef.signals) {
      const rows = stmt.all(sigDef.source, sigDef.metric) as NormalizedRow[];

      if (rows.length === 0) {
        macroSignals.push({
          source: sigDef.source,
          metric: sigDef.metric,
          zscore: null,
          available: false,
        });
        continue;
      }

      anyDataFound = true;

      // rows come back DESC — track latest date
      const rowLatest = rows[0]?.measurement_date ?? "";
      if (rowLatest > latestDate) latestDate = rowLatest;

      // Reverse to ascending order for z-score computation
      const values = rows.map((r) => r.value).reverse();
      let zscore = computeZscore(values);

      // Invert sentiment.bearish_ratio (lower bearish = more positive)
      if (zscore !== null && sigDef.invertScore === true) {
        zscore = zscore * -1;
      }

      macroSignals.push({
        source: sigDef.source,
        metric: sigDef.metric,
        zscore,
        available: true,
      });

      if (zscore !== null) {
        groupZscores.push(zscore);
      }
    }

    const avgZscore =
      groupZscores.length > 0
        ? groupZscores.reduce((a, b) => a + b, 0) / groupZscores.length
        : null;

    if (avgZscore !== null) {
      allGroupZscores.push(avgZscore);
    }

    groups.push({
      name: groupDef.name,
      light: toTrafficLight(avgZscore),
      avgZscore,
      signals: macroSignals,
    });
  }

  if (!anyDataFound) return null;

  const overallAvg =
    allGroupZscores.length > 0
      ? allGroupZscores.reduce((a, b) => a + b, 0) / allGroupZscores.length
      : null;
  const overallLight = toTrafficLight(overallAvg);

  // Format the Telegram message
  const lines: string[] = [
    "MACRO HEALTH DASHBOARD",
    "",
  ];

  for (const group of groups) {
    const emoji = lightEmoji(group.light);
    const avgStr =
      group.avgZscore !== null ? group.avgZscore.toFixed(2) : "n/a";
    lines.push(`${emoji} ${group.name}: ${avgStr}`);

    for (const sig of group.signals) {
      const zStr = sig.zscore !== null ? sig.zscore.toFixed(2) : "n/a";
      const tag = sig.available ? zStr : "no data";
      lines.push(`  ${sig.source}/${sig.metric}: ${tag}`);
    }
    lines.push("");
  }

  lines.push(`Overall: ${lightEmoji(overallLight)} ${overallLight.toUpperCase()}`);
  lines.push("");
  lines.push(freshnessFooter(latestDate !== "unknown" ? latestDate.slice(0, 10) : new Date().toISOString().slice(0, 10)));

  const formattedText = truncate4K(lines.join("\n"));

  return {
    groups,
    overallLight,
    formattedText,
  };
}
