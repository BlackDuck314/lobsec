/**
 * PROD-07: Off-Plan vs Ready Arbitrage Tracker
 *
 * Identifies off-plan vs ready pricing arbitrage by querying DLD procedure_name_en
 * segmented metrics produced by the extended normalize_dld.py module.
 *
 * Premium spread: (offplan_avg_price - ready_avg_price) / ready_avg_price * 100
 * Positive = off-plan commands a premium over ready stock.
 * Negative = off-plan is discounted vs ready stock.
 *
 * Data source: normalized_monthly (source='dld-sales', metrics produced by normalize_dld.py)
 * Area validation: SEC-06 — parameterized SQL against area_names table
 * Null handling: returns null for premium when either price is absent
 * Format: truncated to 4K for Telegram delivery
 */

import type Database from "better-sqlite3";
import {
  truncate4K,
  freshnessFooter,
  trendArrow,
} from "./format.js";

/** Result of the off-plan vs ready arbitrage query. */
export interface ArbitrageResult {
  /** Canonical area name from area_names table */
  area: string;
  /** Off-plan average transaction price (AED) or null if insufficient data */
  offplanAvgPrice: number | null;
  /** Ready average transaction price (AED) or null if insufficient data */
  readyAvgPrice: number | null;
  /** Off-plan premium/discount as percentage vs ready, or null if either price absent */
  premiumPct: number | null;
  /** Off-plan transaction volume (count) in latest month or null */
  offplanVolume: number | null;
  /** Ready transaction volume (count) in latest month or null */
  readyVolume: number | null;
  /** Trend direction for premium spread: "^", "v", "=", or "-" */
  trend: string;
  /** ISO timestamp of the most recent data point used */
  computedAt: string;
  /** Note about data availability if premium cannot be computed */
  dataNote: string | null;
  /** Formatted Telegram message text (truncated to 4K) */
  formattedText: string;
}

/** Row shape returned from normalized_monthly queries */
interface MetricRow {
  value: number;
  measurement_date: string;
}

/**
 * Query latest 2 values for a given metric from normalized_monthly (dld-sales source).
 */
function queryMetric(
  db: Database.Database,
  metricName: string
): MetricRow[] {
  return db
    .prepare(
      `SELECT value, measurement_date
       FROM normalized_monthly
       WHERE source = 'dld-sales'
         AND metric_name = ?
       ORDER BY measurement_date DESC
       LIMIT 2`
    )
    .all(metricName) as MetricRow[];
}

/**
 * Query the off-plan vs ready arbitrage metrics for a given area.
 *
 * Returns null if the area is not found in area_names.
 * Returns a result with null prices and premium if DLD segmentation data is absent.
 *
 * @param db - better-sqlite3 database instance
 * @param area - Canonical area name to query
 * @returns ArbitrageResult or null if area not found
 */
export function queryArbitrage(
  db: Database.Database,
  area: string
): ArbitrageResult | null {
  // SEC-06: Validate area against canonical area_names table
  const areaRow = db
    .prepare(
      `SELECT canonical_name FROM area_names WHERE LOWER(canonical_name) = LOWER(?) LIMIT 1`
    )
    .get(area) as { canonical_name: string } | undefined;

  if (!areaRow) {
    return null;
  }

  const canonicalArea = areaRow.canonical_name;

  // Query off-plan and ready metrics (latest 2 months for trend)
  const offplanPriceRows = queryMetric(db, `${canonicalArea}|offplan_avg_price`);
  const readyPriceRows = queryMetric(db, `${canonicalArea}|ready_avg_price`);
  const offplanVolumeRows = queryMetric(db, `${canonicalArea}|offplan_volume`);
  const readyVolumeRows = queryMetric(db, `${canonicalArea}|ready_volume`);

  // Extract current (most recent) values
  const offplanAvgPrice = offplanPriceRows[0]?.value ?? null;
  const readyAvgPrice = readyPriceRows[0]?.value ?? null;
  const offplanVolume = offplanVolumeRows[0]?.value ?? null;
  const readyVolume = readyVolumeRows[0]?.value ?? null;

  // Determine most recent data date across all metrics
  const dates = [
    offplanPriceRows[0]?.measurement_date,
    readyPriceRows[0]?.measurement_date,
    offplanVolumeRows[0]?.measurement_date,
    readyVolumeRows[0]?.measurement_date,
  ].filter((d): d is string => d !== undefined);
  const computedAt = dates.length > 0 ? dates.sort().reverse()[0]! : new Date().toISOString().slice(0, 10);

  // Compute premium spread
  let premiumPct: number | null = null;
  let dataNote: string | null = null;

  if (offplanAvgPrice !== null && readyAvgPrice !== null && readyAvgPrice !== 0) {
    premiumPct = ((offplanAvgPrice - readyAvgPrice) / readyAvgPrice) * 100;
  } else {
    dataNote = "insufficient data — off-plan/ready segmentation requires DLD procedure_name_en field";
  }

  // Compute previous month's premium for trend
  const prevOffplanPrice = offplanPriceRows[1]?.value ?? null;
  const prevReadyPrice = readyPriceRows[1]?.value ?? null;
  let prevPremiumPct: number | null = null;
  if (prevOffplanPrice !== null && prevReadyPrice !== null && prevReadyPrice !== 0) {
    prevPremiumPct = ((prevOffplanPrice - prevReadyPrice) / prevReadyPrice) * 100;
  }

  const trend = trendArrow(premiumPct, prevPremiumPct);

  // Format numbers for display
  const fmtPrice = (p: number | null): string =>
    p !== null ? `AED ${(p / 1_000_000).toFixed(2)}M` : "N/A";
  const fmtVol = (v: number | null): string =>
    v !== null ? Math.round(v).toString() : "N/A";
  const fmtPct = (p: number | null): string =>
    p !== null ? `${p >= 0 ? "+" : ""}${p.toFixed(1)}%` : "N/A";

  // Build formatted Telegram message
  const lines: string[] = [
    `Off-Plan vs Ready — ${canonicalArea.toUpperCase()}`,
    ``,
  ];

  lines.push(`Off-Plan:  ${fmtPrice(offplanAvgPrice)}  (${fmtVol(offplanVolume)} units)`);
  lines.push(`Ready:     ${fmtPrice(readyAvgPrice)}  (${fmtVol(readyVolume)} units)`);
  lines.push(``);

  if (premiumPct !== null) {
    const spreadLine = `Premium Spread: ${fmtPct(premiumPct)} ${trend}`;
    lines.push(spreadLine);
    if (premiumPct >= 0) {
      lines.push(`Off-plan commands a ${fmtPct(premiumPct)} premium over ready stock`);
    } else {
      lines.push(`Off-plan is discounted by ${fmtPct(Math.abs(premiumPct))} vs ready stock`);
    }
  } else {
    lines.push(`Premium Spread: N/A`);
    if (dataNote) {
      lines.push(`Note: ${dataNote}`);
    }
  }

  lines.push(``);
  lines.push(freshnessFooter(computedAt));

  const formattedText = truncate4K(lines.join("\n"));

  return {
    area: canonicalArea,
    offplanAvgPrice,
    readyAvgPrice,
    premiumPct,
    offplanVolume,
    readyVolume,
    trend,
    computedAt,
    dataNote,
    formattedText,
  };
}
