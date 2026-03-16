/**
 * PROD-04: Supply Pipeline Tracker
 *
 * Tracks 4 supply indicators with 12-24 month forward curve extrapolation:
 *   1. Building permits (residential + commercial)
 *   2. DEWA new connections
 *   3. Jebel Ali cargo (construction material volumes, city-wide)
 *   4. Customs household imports (city-wide)
 *
 * Forward curve: simple linear trend on 6-month rolling window, extrapolated 12 months.
 * Requires >= 3 data points for extrapolation; skips otherwise.
 *
 * Area validation: SEC-06 — parameterized SQL against area_names table
 * Null handling: each signal returns null independently if data absent
 * Format: truncated to 4K for Telegram delivery
 */

import type Database from "better-sqlite3";
import {
  truncate4K,
  freshnessFooter,
  trendArrow,
} from "./format.js";

/** A single forward curve projection point */
export interface ForwardPoint {
  /** Month label, e.g. "2026-04" */
  month: string;
  /** Projected value (may be negative — extrapolation artefact, interpret as floor=0) */
  projectedValue: number;
}

/** Supply signal with trend and recent history */
interface SupplySignal {
  /** Latest value, or null if unavailable */
  latest: number | null;
  /** Second-most-recent value for trend comparison */
  previous: number | null;
  /** ISO date of latest data point */
  latestDate: string | null;
  /** 6-month trend slope (units/month) */
  slope: number | null;
  /** 12-month forward curve projections */
  forwardCurve: ForwardPoint[];
}

/** Building permits signal */
interface PermitsSignal extends SupplySignal {
  residential: number | null;
  commercial: number | null;
}

/** Result of the supply pipeline query */
export interface SupplyPipelineResult {
  /** Area queried, or "dubai" for city-wide aggregate */
  area: string;
  /** Building permits signal */
  permits: PermitsSignal;
  /** DEWA new connections signal */
  dewaConnections: SupplySignal;
  /** Jebel Ali port cargo (city-wide only) */
  portCargo: SupplySignal;
  /** Customs household imports (city-wide only) */
  customsImports: SupplySignal;
  /** 12-month forward curve combining permits + DEWA connections */
  forwardCurve: ForwardPoint[];
  /** ISO date of most recent data across all signals */
  computedAt: string;
  /** Formatted Telegram message (truncated to 4K) */
  formattedText: string;
}

/** Row returned from normalized_monthly */
interface MonthlyRow {
  value: number;
  measurement_date: string;
}

/**
 * Compute simple linear regression slope over a series of values.
 * Returns null if fewer than 3 points.
 */
function linearSlope(values: number[]): number | null {
  if (values.length < 3) return null;
  const n = values.length;
  const x = Array.from({ length: n }, (_, i) => i);
  const meanX = x.reduce((a, b) => a + b, 0) / n;
  const meanY = values.reduce((a, b) => a + b, 0) / n;
  const ssXX = x.reduce((sum, xi) => sum + (xi - meanX) ** 2, 0);
  const ssXY = x.reduce((sum, xi, i) => sum + (xi - meanX) * ((values[i] ?? 0) - meanY), 0);
  if (ssXX === 0) return 0;
  return ssXY / ssXX;
}

/**
 * Build a 12-month forward curve given the last known value, slope, and starting date.
 * Returns empty array if slope is null.
 */
function buildForwardCurve(
  lastValue: number,
  slope: number | null,
  lastDateStr: string,
  months = 12
): ForwardPoint[] {
  if (slope === null) return [];
  const curve: ForwardPoint[] = [];
  const lastDate = new Date(lastDateStr);
  for (let i = 1; i <= months; i++) {
    const futureDate = new Date(lastDate);
    futureDate.setMonth(futureDate.getMonth() + i);
    const monthLabel = futureDate.toISOString().slice(0, 7);
    curve.push({
      month: monthLabel,
      projectedValue: Math.max(0, lastValue + slope * i),
    });
  }
  return curve;
}

/** Query latest 6 values for a metric LIKE pattern */
function queryLatest6Like(
  db: Database.Database,
  source: string,
  pattern: string
): MonthlyRow[] {
  return db
    .prepare(
      `SELECT value, measurement_date
       FROM normalized_monthly
       WHERE source = ?
         AND metric_name LIKE ?
       ORDER BY measurement_date DESC
       LIMIT 6`
    )
    .all(source, pattern) as MonthlyRow[];
}

/** Query latest 6 values for an exact metric name */
function queryLatest6Exact(
  db: Database.Database,
  source: string,
  metricName: string
): MonthlyRow[] {
  return db
    .prepare(
      `SELECT value, measurement_date
       FROM normalized_monthly
       WHERE source = ?
         AND metric_name = ?
       ORDER BY measurement_date DESC
       LIMIT 6`
    )
    .all(source, metricName) as MonthlyRow[];
}

/** Build a SupplySignal from a list of rows (newest first) */
function buildSignal(rows: MonthlyRow[]): SupplySignal {
  if (rows.length === 0) {
    return {
      latest: null,
      previous: null,
      latestDate: null,
      slope: null,
      forwardCurve: [],
    };
  }
  const latest = rows[0]?.value ?? null;
  const previous = rows[1]?.value ?? null;
  const latestDate = rows[0]?.measurement_date ?? null;

  // Values in chronological order for slope calculation
  const values = rows.map((r) => r.value).reverse();
  const slope = linearSlope(values);
  const forwardCurve =
    latest !== null && latestDate !== null
      ? buildForwardCurve(latest, slope, latestDate)
      : [];

  return { latest, previous, latestDate, slope, forwardCurve };
}

/**
 * Query the supply pipeline for a given area (or city-wide if area is omitted).
 *
 * Returns null if area is specified but not found in area_names.
 * City-wide sources (port, customs) are always queried at the city level.
 *
 * @param db - better-sqlite3 database instance
 * @param area - Canonical area name to query, or omit for city-wide aggregate
 * @returns SupplyPipelineResult or null if area not found
 */
export function querySupplyPipeline(
  db: Database.Database,
  area?: string
): SupplyPipelineResult | null {
  let canonicalArea = "dubai";

  if (area !== undefined && area !== "dubai") {
    // SEC-06: Validate area against canonical area_names table
    const areaRow = db
      .prepare(
        `SELECT canonical_name FROM area_names WHERE LOWER(canonical_name) = LOWER(?) LIMIT 1`
      )
      .get(area) as { canonical_name: string } | undefined;

    if (!areaRow) {
      return null;
    }
    canonicalArea = areaRow.canonical_name;
  }

  const areaPrefix = `${canonicalArea}|`;

  // --- Signal 1: Building permits ---
  // Try area-level first, fall back to city-wide
  const permitsResRows =
    queryLatest6Like(db, "permits", `${areaPrefix}%residential_count`).length > 0
      ? queryLatest6Like(db, "permits", `${areaPrefix}%residential_count`)
      : queryLatest6Exact(db, "permits", "residential_count");

  const permitsCommRows =
    queryLatest6Like(db, "permits", `${areaPrefix}%commercial_count`).length > 0
      ? queryLatest6Like(db, "permits", `${areaPrefix}%commercial_count`)
      : queryLatest6Exact(db, "permits", "commercial_count");

  // Combine residential + commercial for total permits signal
  const permitsTotalRows: MonthlyRow[] = permitsResRows.map((resRow, i) => {
    const commRow = permitsCommRows[i];
    return {
      value: resRow.value + (commRow?.value ?? 0),
      measurement_date: resRow.measurement_date,
    };
  });

  const permitsSignal = buildSignal(permitsTotalRows);
  const permitsRes = permitsResRows[0]?.value ?? null;
  const permitsComm = permitsCommRows[0]?.value ?? null;

  const permits: PermitsSignal = {
    ...permitsSignal,
    residential: permitsRes,
    commercial: permitsComm,
  };

  // --- Signal 2: DEWA new connections ---
  const dewaRows =
    queryLatest6Like(db, "dewa", `${areaPrefix}%new_connections`).length > 0
      ? queryLatest6Like(db, "dewa", `${areaPrefix}%new_connections`)
      : queryLatest6Exact(db, "dewa", "new_connections");
  const dewaConnections = buildSignal(dewaRows);

  // --- Signal 3: Jebel Ali port cargo (city-wide only) ---
  const portRows = queryLatest6Like(db, "port", "%construction%");
  const portCargo = buildSignal(portRows);

  // --- Signal 4: Customs household imports (city-wide only) ---
  const customsRows = queryLatest6Exact(db, "customs", "household_imports");
  const customsImports = buildSignal(customsRows);

  // --- Combined forward curve (permits + DEWA) ---
  // Combine the 12-month projections for permits and DEWA if both available
  const combinedForwardCurve: ForwardPoint[] = [];
  if (permits.forwardCurve.length > 0 || dewaConnections.forwardCurve.length > 0) {
    const months = new Set([
      ...permits.forwardCurve.map((p) => p.month),
      ...dewaConnections.forwardCurve.map((p) => p.month),
    ]);
    for (const month of [...months].sort()) {
      const permitsPoint = permits.forwardCurve.find((p) => p.month === month);
      const dewaPoint = dewaConnections.forwardCurve.find((p) => p.month === month);
      combinedForwardCurve.push({
        month,
        projectedValue: (permitsPoint?.projectedValue ?? 0) + (dewaPoint?.projectedValue ?? 0),
      });
    }
  }

  // --- Determine most recent data date ---
  const allDates = [
    permits.latestDate,
    dewaConnections.latestDate,
    portCargo.latestDate,
    customsImports.latestDate,
  ].filter((d): d is string => d !== null);
  const computedAt =
    allDates.length > 0
      ? allDates.sort().reverse()[0]!
      : new Date().toISOString().slice(0, 10);

  // --- Format output ---
  const fmtVal = (v: number | null): string =>
    v !== null ? Math.round(v).toLocaleString() : "N/A";

  const fmtTrend = (signal: SupplySignal): string => {
    const arrow = trendArrow(signal.latest, signal.previous);
    if (signal.slope !== null) {
      const direction = signal.slope > 0 ? "+" : signal.slope < 0 ? "-" : "=";
      const abs = Math.abs(signal.slope);
      return `${arrow} (${direction}${Math.round(abs)}/mo trend)`;
    }
    return arrow;
  };

  const lines: string[] = [
    `Supply Pipeline — ${canonicalArea.toUpperCase()}`,
    ``,
  ];

  // Permits section
  lines.push(`Building Permits:`);
  if (permits.latest !== null) {
    lines.push(`  Total: ${fmtVal(permits.latest)} ${fmtTrend(permits)}`);
    if (permitsRes !== null) lines.push(`  Residential: ${fmtVal(permitsRes)}`);
    if (permitsComm !== null) lines.push(`  Commercial: ${fmtVal(permitsComm)}`);
    if (permits.latestDate) lines.push(`  As of: ${permits.latestDate}`);
  } else {
    lines.push(`  No permits data available`);
  }

  lines.push(``);

  // DEWA section
  lines.push(`DEWA New Connections:`);
  if (dewaConnections.latest !== null) {
    lines.push(`  ${fmtVal(dewaConnections.latest)} ${fmtTrend(dewaConnections)}`);
    if (dewaConnections.latestDate) lines.push(`  As of: ${dewaConnections.latestDate}`);
  } else {
    lines.push(`  No DEWA data available`);
  }

  lines.push(``);

  // Port section
  lines.push(`Jebel Ali Cargo (construction):`);
  if (portCargo.latest !== null) {
    lines.push(`  ${fmtVal(portCargo.latest)} ${fmtTrend(portCargo)}`);
    if (portCargo.latestDate) lines.push(`  As of: ${portCargo.latestDate}`);
  } else {
    lines.push(`  No port data available`);
  }

  lines.push(``);

  // Customs section
  lines.push(`Customs Household Imports:`);
  if (customsImports.latest !== null) {
    lines.push(`  ${fmtVal(customsImports.latest)} ${fmtTrend(customsImports)}`);
    if (customsImports.latestDate) lines.push(`  As of: ${customsImports.latestDate}`);
  } else {
    lines.push(`  No customs data available`);
  }

  lines.push(``);

  // Forward curve summary
  if (combinedForwardCurve.length >= 12) {
    const month12 = combinedForwardCurve[11];
    const permitsMonth12 = permits.forwardCurve[11];
    const dewaMonth12 = dewaConnections.forwardCurve[11];
    if (month12) {
      lines.push(`Expected 12mo supply:`);
      if (permitsMonth12) {
        lines.push(`  Permits: ~${fmtVal(permitsMonth12.projectedValue)}`);
      }
      if (dewaMonth12) {
        lines.push(`  DEWA connections: ~${fmtVal(dewaMonth12.projectedValue)}`);
      }
      lines.push(`  Combined: ~${fmtVal(month12.projectedValue)} units est.`);
    }
  } else if (permits.forwardCurve.length === 0 && dewaConnections.forwardCurve.length === 0) {
    lines.push(`Forward curve: insufficient data (< 3 months)`);
  }

  lines.push(``);
  lines.push(freshnessFooter(computedAt));

  const formattedText = truncate4K(lines.join("\n"));

  return {
    area: canonicalArea,
    permits,
    dewaConnections,
    portCargo,
    customsImports,
    forwardCurve: combinedForwardCurve,
    computedAt,
    formattedText,
  };
}
