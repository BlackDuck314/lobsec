/**
 * PROD-03: Rental Intelligence Dashboard
 *
 * Computes 10 rental market metrics per area from normalized_monthly data
 * and intelligence_cache (affordability data).
 *
 * Metrics:
 *   1. Gross yield          - (annual rent / sale price) * 100
 *   2. Rental momentum      - ejari new_contracts MoM change
 *   3. Vacancy proxy        - listing_count / (new_contracts + listing_count)
 *   4. Renewal rate         - ejari renewal_rate if available
 *   5. Listing absorption   - dld trans_count / bayut listing_count
 *   6. Pipeline pressure    - permits residential_count / dewa new_connections
 *   7. Affordability ratio  - from intelligence_cache affordability_latest
 *   8. STR premium          - airbnb avg_adr vs ejari daily implied rate
 *   9. Rent-to-income       - from affordability cache
 *  10. DOM trend            - bayut avg_dom direction over last 2 months
 *
 * Area validation: SEC-06 — parameterized SQL against area_names table
 * Null handling: each metric returns null independently if data absent
 * Format: truncated to 4K for Telegram delivery
 */

import type Database from "better-sqlite3";
import {
  truncate4K,
  freshnessFooter,
  trendArrow,
} from "./format.js";

/** Individual metric value with metadata */
interface MetricValue {
  value: number | null;
  trend: string;
  date: string | null;
}

/** 10 rental metrics computed per area */
export interface RentalMetrics {
  /** Gross yield (%) = annual_rent / sale_price * 100 */
  grossYield: number | null;
  /** Rental momentum: MoM % change in ejari new_contracts */
  rentalMomentum: number | null;
  /** Vacancy proxy (0–1): listing_count / (new_contracts + listing_count) */
  vacancyProxy: number | null;
  /** Renewal rate from ejari if available */
  renewalRate: number | null;
  /** Listing absorption: dld trans_count / bayut listing_count */
  listingAbsorption: number | null;
  /** Pipeline pressure: permits residential_count / dewa new_connections */
  pipelinePressure: number | null;
  /** Affordability ratio from intelligence_cache */
  affordabilityRatio: number | null;
  /** STR premium: airbnb avg_adr / (ejari avg_rent_per_sqft * 750 / 30) */
  strPremium: number | null;
  /** Rent-to-income ratio from affordability cache */
  rentToIncome: number | null;
  /** Days-on-market current value and direction */
  domTrend: number | null;
  /** DOM direction: "^" rising, "v" falling, "=" flat, "-" unknown */
  domDirection: string;
}

/** Result of the rental intelligence query */
export interface RentalIntelResult {
  /** Canonical area name */
  area: string;
  /** 10 computed rental metrics */
  metrics: RentalMetrics;
  /** ISO date of most recent data point used */
  computedAt: string;
  /** Formatted Telegram message (truncated to 4K) */
  formattedText: string;
}

/** Row returned from normalized_monthly */
interface MonthlyRow {
  value: number;
  measurement_date: string;
}

/** Query latest N values for a given source+metric combination */
function queryLatest(
  db: Database.Database,
  source: string,
  metricName: string,
  limit = 2
): MonthlyRow[] {
  return db
    .prepare(
      `SELECT value, measurement_date
       FROM normalized_monthly
       WHERE source = ?
         AND metric_name = ?
       ORDER BY measurement_date DESC
       LIMIT ?`
    )
    .all(source, metricName, limit) as MonthlyRow[];
}

/** Query latest N values for a LIKE pattern (area-prefixed metrics) */
function queryLatestLike(
  db: Database.Database,
  source: string,
  pattern: string,
  limit = 2
): MonthlyRow[] {
  return db
    .prepare(
      `SELECT value, measurement_date
       FROM normalized_monthly
       WHERE source = ?
         AND metric_name LIKE ?
       ORDER BY measurement_date DESC
       LIMIT ?`
    )
    .all(source, pattern, limit) as MonthlyRow[];
}

/**
 * Query rental intelligence metrics for a given area.
 *
 * Returns null if area not found in area_names.
 * Each metric is computed independently — null means data is absent, not zero.
 *
 * @param db - better-sqlite3 database instance
 * @param area - Canonical area name to query
 * @returns RentalIntelResult or null if area not found
 */
export function queryRentalIntel(
  db: Database.Database,
  area: string
): RentalIntelResult | null {
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
  const areaPrefix = `${canonicalArea}|`;
  const areaPrefixLike = `${canonicalArea}|%`;

  // --- Metric 1: Gross yield ---
  // (ejari avg_rent_per_sqft * 750 * 12) / (dld median_price or bayut avg_asking_price) * 100
  // Using 750 sqft as representative 1BR size
  let grossYield: number | null = null;
  const ejariRentRows = queryLatestLike(db, "ejari", `${areaPrefix}%avg_rent_per_sqft`);
  const dldPriceRows = queryLatestLike(db, "dld-sales", `${areaPrefix}%median_price`);
  const bayutPriceRows = queryLatestLike(db, "bayut", `${areaPrefix}%avg_asking_price`);

  const rentPerSqft = ejariRentRows[0]?.value ?? null;
  const salePrice = dldPriceRows[0]?.value ?? bayutPriceRows[0]?.value ?? null;

  if (rentPerSqft !== null && salePrice !== null && salePrice > 0) {
    const annualRent = rentPerSqft * 750 * 12;
    grossYield = (annualRent / salePrice) * 100;
  }

  // --- Metric 2: Rental momentum ---
  // ejari new_contracts MoM % change
  let rentalMomentum: number | null = null;
  const contractRows = queryLatestLike(db, "ejari", `${areaPrefix}%new_contracts`);
  const currContracts = contractRows[0]?.value ?? null;
  const prevContracts = contractRows[1]?.value ?? null;
  if (currContracts !== null && prevContracts !== null && prevContracts > 0) {
    rentalMomentum = ((currContracts - prevContracts) / prevContracts) * 100;
  }

  // --- Metric 3: Vacancy proxy ---
  // listing_count / (new_contracts + listing_count)
  let vacancyProxy: number | null = null;
  const bayutListingRows = queryLatestLike(db, "bayut", `${areaPrefix}%listing_count`);
  const listingCount = bayutListingRows[0]?.value ?? null;
  const contractsForVacancy = contractRows[0]?.value ?? null;
  if (listingCount !== null && contractsForVacancy !== null) {
    const denom = contractsForVacancy + listingCount;
    if (denom > 0) {
      vacancyProxy = listingCount / denom;
    }
  }

  // --- Metric 4: Renewal rate ---
  // ejari renewal_rate metric (direct, if available from normalization)
  let renewalRate: number | null = null;
  const renewalRows = queryLatestLike(db, "ejari", `${areaPrefix}%renewal_rate`);
  renewalRate = renewalRows[0]?.value ?? null;

  // --- Metric 5: Listing absorption ---
  // dld trans_count / bayut listing_count
  let listingAbsorption: number | null = null;
  const dldVolumeRows = queryLatestLike(db, "dld-sales", `${areaPrefix}%volume`);
  const dldTransCount = dldVolumeRows[0]?.value ?? null;
  const listingCountForAbsorption = bayutListingRows[0]?.value ?? null;
  if (dldTransCount !== null && listingCountForAbsorption !== null && listingCountForAbsorption > 0) {
    listingAbsorption = dldTransCount / listingCountForAbsorption;
  }

  // --- Metric 6: Pipeline pressure ---
  // permits residential_count / dewa new_connections
  // Both are city-wide or area-level depending on available data
  let pipelinePressure: number | null = null;
  const permitsRows = queryLatestLike(db, "permits", `${areaPrefix}%residential_count`);
  // Try area-level first, then city-wide
  const permitsRowsCitywide = permitsRows.length > 0
    ? permitsRows
    : queryLatest(db, "permits", "residential_count");
  const dewaRows = queryLatestLike(db, "dewa", `${areaPrefix}%new_connections`);
  const dewaRowsCitywide = dewaRows.length > 0
    ? dewaRows
    : queryLatest(db, "dewa", "new_connections");

  const permitsCount = permitsRowsCitywide[0]?.value ?? null;
  const dewaConnections = dewaRowsCitywide[0]?.value ?? null;
  if (permitsCount !== null && dewaConnections !== null && dewaConnections > 0) {
    pipelinePressure = permitsCount / dewaConnections;
  }

  // --- Metric 7: Affordability ratio & Metric 9: Rent-to-income ---
  // From intelligence_cache affordability_latest JSON
  let affordabilityRatio: number | null = null;
  let rentToIncome: number | null = null;
  const affordCache = db
    .prepare(
      `SELECT result_json FROM intelligence_cache
       WHERE cache_key = 'affordability_latest'
       LIMIT 1`
    )
    .get() as { result_json: string } | undefined;

  if (affordCache) {
    try {
      const affordData = JSON.parse(affordCache.result_json) as Record<string, unknown>;
      // Look for area-specific entry (case-insensitive)
      const areaKey = Object.keys(affordData).find(
        (k) => k.toLowerCase() === canonicalArea.toLowerCase()
      );
      if (areaKey) {
        const areaEntry = affordData[areaKey] as Record<string, unknown>;
        if (typeof areaEntry === "object" && areaEntry !== null) {
          if (typeof areaEntry["affordability_ratio"] === "number") {
            affordabilityRatio = areaEntry["affordability_ratio"] as number;
          }
          if (typeof areaEntry["rent_to_income"] === "number") {
            rentToIncome = areaEntry["rent_to_income"] as number;
          }
        }
      }
    } catch {
      // Cache parse error — treat as absent
    }
  }

  // --- Metric 8: STR premium ---
  // airbnb avg_adr / (ejari avg_rent_per_sqft * 750 / 30)
  // Comparing daily STR rate vs implied daily long-term rent
  let strPremium: number | null = null;
  const airbnbRows = queryLatestLike(db, "airbnb", `${areaPrefix}%avg_adr`);
  const avgAdr = airbnbRows[0]?.value ?? null;
  const ejariRentForStr = rentPerSqft; // reuse from metric 1
  if (avgAdr !== null && ejariRentForStr !== null && ejariRentForStr > 0) {
    const dailyLongTermRate = (ejariRentForStr * 750) / 30;
    if (dailyLongTermRate > 0) {
      strPremium = avgAdr / dailyLongTermRate;
    }
  }

  // --- Metric 10: DOM trend ---
  let domTrend: number | null = null;
  let domDirection = "-";
  const domRows = queryLatestLike(db, "bayut", `${areaPrefix}%avg_dom`);
  const currDom = domRows[0]?.value ?? null;
  const prevDom = domRows[1]?.value ?? null;
  domTrend = currDom;
  domDirection = trendArrow(currDom, prevDom);

  // --- Determine most recent data date ---
  const allDates = [
    ejariRentRows[0]?.measurement_date,
    dldPriceRows[0]?.measurement_date,
    bayutListingRows[0]?.measurement_date,
    domRows[0]?.measurement_date,
    airbnbRows[0]?.measurement_date,
  ].filter((d): d is string => d !== undefined);
  const computedAt =
    allDates.length > 0
      ? allDates.sort().reverse()[0]!
      : new Date().toISOString().slice(0, 10);

  // --- Format output ---
  const fmtPct = (v: number | null, decimals = 1): string =>
    v !== null ? `${v.toFixed(decimals)}%` : null!;
  const fmtRatio = (v: number | null, decimals = 2): string =>
    v !== null ? v.toFixed(decimals) : null!;
  const fmtDom = (v: number | null): string =>
    v !== null ? `${Math.round(v)}d` : null!;

  const lines: string[] = [
    `Rental Intelligence — ${canonicalArea.toUpperCase()}`,
    ``,
  ];

  const addMetric = (label: string, value: string | null, extra?: string): void => {
    if (value !== null) {
      const suffix = extra ? `  ${extra}` : "";
      lines.push(`${label}: ${value}${suffix}`);
    }
  };

  addMetric(
    "Gross Yield",
    grossYield !== null ? fmtPct(grossYield) : null,
    trendArrow(grossYield, null) === "-" ? undefined : undefined
  );
  addMetric(
    "Rental Momentum",
    rentalMomentum !== null ? `${rentalMomentum >= 0 ? "+" : ""}${fmtPct(rentalMomentum)}` : null,
    trendArrow(rentalMomentum, 0)
  );
  addMetric(
    "Vacancy Proxy",
    vacancyProxy !== null ? fmtPct(vacancyProxy * 100) : null
  );
  addMetric(
    "Renewal Rate",
    renewalRate !== null ? fmtPct(renewalRate) : null
  );
  addMetric(
    "Listing Absorption",
    listingAbsorption !== null ? fmtRatio(listingAbsorption) : null
  );
  addMetric(
    "Pipeline Pressure",
    pipelinePressure !== null ? fmtRatio(pipelinePressure) : null
  );
  addMetric(
    "Affordability Ratio",
    affordabilityRatio !== null ? fmtRatio(affordabilityRatio) : null
  );
  addMetric(
    "STR Premium",
    strPremium !== null ? `${fmtRatio(strPremium)}x` : null
  );
  addMetric(
    "Rent-to-Income",
    rentToIncome !== null ? fmtPct(rentToIncome * 100) : null
  );
  addMetric(
    "DOM Trend",
    domTrend !== null ? fmtDom(domTrend) : null,
    domDirection !== "-" ? domDirection : undefined
  );

  // If no metrics available, indicate data gap
  if (lines.length <= 2) {
    lines.push("No rental data available for this area.");
  }

  lines.push(``);
  lines.push(freshnessFooter(computedAt));

  const formattedText = truncate4K(lines.join("\n"));

  const metrics: RentalMetrics = {
    grossYield,
    rentalMomentum,
    vacancyProxy,
    renewalRate,
    listingAbsorption,
    pipelinePressure,
    affordabilityRatio,
    strPremium,
    rentToIncome,
    domTrend,
    domDirection,
  };

  return {
    area: canonicalArea,
    metrics,
    computedAt,
    formattedText,
  };
}
