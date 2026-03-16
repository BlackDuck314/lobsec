/**
 * Telegram Monthly Digest Formatter
 *
 * Reads the latest analysis results from 4 tables and formats
 * a Telegram-friendly monthly intelligence briefing.
 *
 * Format inspired by a "magazine feel" per locked decision in 10-CONTEXT.md.
 * Message kept under 4000 chars (Telegram message limit).
 */

import type Database from "better-sqlite3";

/** Composite score summary for the digest. */
interface CompositeScore {
  score: number;
  zone: string;
  componentCount: number;
}

/** Top area movers by composite score. */
interface AreaMover {
  area: string;
  score: number;
  change: number;
}

/** Newly significant Granger signals. */
interface GrangerSignal {
  source: string;
  target: string;
  lag: number;
}

/** Detected anomalies ordered by absolute z-score. */
interface AnomalyFlag {
  source: string;
  metric: string;
  zScore: number;
}

/** An area flagged as a potential distress candidate. */
export interface DistressCandidate {
  area: string;
  score: number;
}

/** Structured data for the monthly digest. */
export interface DigestData {
  compositeScore: CompositeScore;
  topMovers: Array<AreaMover>;
  newGrangerSignals: Array<GrangerSignal>;
  anomaliesDetected: Array<AnomalyFlag>;
  funnelSummary: string;
  distressAreas: Array<DistressCandidate>;
}

/** Row types for raw DB queries */
interface CompositeRow {
  score: number;
  zone: string;
  component_count: number;
}

interface AreaScoreRow {
  area: string;
  score: number;
  computed_at: string;
}

interface GrangerRow {
  signal_source: string;
  signal_metric: string;
  target: string;
  best_lag: number;
}

interface AnomalyRow {
  source: string;
  metric_name: string;
  z_score: number;
}

interface CacheRow {
  result_json: string;
}

interface DistressAreaRow {
  area: string;
  score: number;
}

/**
 * Read the latest analysis results from the database and assemble digest data.
 *
 * Uses parameterized statements where query parameters are variables (SEC-06).
 * Constants like 'dubai' and 'expat_funnel_latest' are literal strings — safe.
 *
 * @param db - Open better-sqlite3 database instance
 * @returns Structured digest data ready for formatting
 */
export function generateDigest(db: Database.Database): DigestData {
  // ── City-wide composite score ─────────────────────────────────────────────
  const compositeRow = db
    .prepare(
      "SELECT score, zone, component_count FROM composite_scores WHERE area = 'dubai' ORDER BY computed_at DESC LIMIT 1"
    )
    .get() as CompositeRow | undefined;

  const compositeScore: CompositeScore = compositeRow
    ? {
        score: compositeRow.score,
        zone: compositeRow.zone,
        componentCount: compositeRow.component_count,
      }
    : { score: 0, zone: "neutral", componentCount: 0 };

  // ── Top movers: compare latest vs previous area scores ────────────────────
  // Get the two most recent computed_at timestamps to calculate delta
  const recentScores = db
    .prepare(
      "SELECT area, score, computed_at FROM composite_scores WHERE area != 'dubai' ORDER BY computed_at DESC LIMIT 40"
    )
    .all() as AreaScoreRow[];

  // Group by area, take latest two entries to compute change
  const areaMap = new Map<string, { latest: number; previous: number }>();
  for (const row of recentScores) {
    if (!areaMap.has(row.area)) {
      areaMap.set(row.area, { latest: row.score, previous: row.score });
    } else {
      const entry = areaMap.get(row.area)!;
      entry.previous = row.score;
    }
  }

  const movers: AreaMover[] = Array.from(areaMap.entries())
    .map(([area, { latest, previous }]) => ({
      area,
      score: latest,
      change: latest - previous,
    }))
    .sort((a, b) => Math.abs(b.change) - Math.abs(a.change))
    .slice(0, 5);

  // ── New Granger signals (last 32 days) ────────────────────────────────────
  const grangerRows = db
    .prepare(
      "SELECT signal_source, signal_metric, target, best_lag FROM granger_results WHERE significant = 1 AND tested_at > datetime('now', '-32 days') ORDER BY pvalue ASC LIMIT 5"
    )
    .all() as GrangerRow[];

  const newGrangerSignals: GrangerSignal[] = grangerRows.map((r) => ({
    source: `${r.signal_source}/${r.signal_metric}`,
    target: r.target,
    lag: r.best_lag,
  }));

  // ── Recent anomalies (last 32 days) ───────────────────────────────────────
  const anomalyRows = db
    .prepare(
      "SELECT source, metric_name, z_score FROM anomaly_flags WHERE flagged_at > datetime('now', '-32 days') ORDER BY ABS(z_score) DESC LIMIT 5"
    )
    .all() as AnomalyRow[];

  const anomaliesDetected: AnomalyFlag[] = anomalyRows.map((r) => ({
    source: r.source,
    metric: r.metric_name,
    zScore: r.z_score,
  }));

  // ── Expat funnel summary from cache ───────────────────────────────────────
  let funnelSummary = "No funnel data available";
  const cacheRow = db
    .prepare(
      "SELECT result_json FROM intelligence_cache WHERE cache_key = 'expat_funnel_latest'"
    )
    .get() as CacheRow | undefined;

  if (cacheRow) {
    try {
      const parsed = JSON.parse(cacheRow.result_json) as {
        digest_text?: string;
        summary?: string;
      };
      funnelSummary = parsed.digest_text ?? parsed.summary ?? "Funnel computed (no summary)";
    } catch {
      funnelSummary = "Funnel data parse error";
    }
  }

  // ── Distress candidates: areas with strongly negative composite scores ────
  // Approximation: areas with composite score <= -0.6 are flagged as potential
  // distress candidates. Full PROD-02 distress calculation uses 17 signals;
  // this digest check uses the pre-computed composite score as a proxy.
  const distressRows = db
    .prepare(
      "SELECT area, score FROM composite_scores WHERE area != 'dubai' AND score <= -0.6 ORDER BY computed_at DESC LIMIT 20"
    )
    .all() as DistressAreaRow[];

  // Deduplicate — keep worst score per area (rows ordered by computed_at DESC)
  const distressAreaMap = new Map<string, number>();
  for (const row of distressRows) {
    if (!distressAreaMap.has(row.area)) {
      distressAreaMap.set(row.area, row.score);
    }
  }

  const distressAreas: DistressCandidate[] = Array.from(distressAreaMap.entries())
    .map(([area, score]) => ({ area, score }))
    .sort((a, b) => a.score - b.score); // most negative first

  return {
    compositeScore,
    topMovers: movers,
    newGrangerSignals,
    anomaliesDetected,
    funnelSummary,
    distressAreas,
  };
}

/**
 * Format digest data as a Telegram-friendly message.
 *
 * Uses plain text (no Markdown) for maximum compatibility.
 * Truncates to 4000 chars to respect Telegram's message limit.
 *
 * @param data - Structured digest data
 * @returns Formatted message string <= 4000 chars
 */
export function formatDigestMessage(data: DigestData): string {
  const now = new Date();
  const monthYear = now.toLocaleString("en-US", {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  });

  const zoneLabel = zoneToLabel(data.compositeScore.zone);
  const scoreDisplay = data.compositeScore.score.toFixed(2);

  const lines: string[] = [
    `UAE RE MONTHLY INTELLIGENCE — ${monthYear}`,
    "",
    `MARKET SIGNAL: ${zoneLabel} (${scoreDisplay})`,
    `Based on ${data.compositeScore.componentCount} validated indicators`,
    "",
  ];

  // Top movers
  if (data.topMovers.length > 0) {
    lines.push("TOP MOVERS:");
    for (let i = 0; i < data.topMovers.length; i++) {
      const m = data.topMovers[i]!;
      const arrow = m.change > 0 ? "^" : m.change < 0 ? "v" : "=";
      const changeStr =
        m.change !== 0 ? ` (${m.change > 0 ? "+" : ""}${m.change.toFixed(2)})` : "";
      lines.push(`${i + 1}. ${m.area} ${m.score.toFixed(2)} ${arrow}${changeStr}`);
    }
    lines.push("");
  }

  // New Granger signals
  if (data.newGrangerSignals.length > 0) {
    lines.push("NEW GRANGER SIGNALS:");
    for (const s of data.newGrangerSignals) {
      lines.push(`- ${s.source} leads ${s.target} by ${s.lag} month(s) (NEW)`);
    }
    lines.push("");
  } else {
    lines.push("NEW GRANGER SIGNALS: none this period");
    lines.push("");
  }

  // Anomalies
  if (data.anomaliesDetected.length > 0) {
    lines.push("ANOMALIES DETECTED:");
    for (const a of data.anomaliesDetected) {
      const direction = a.zScore > 0 ? "spike" : "drop";
      lines.push(
        `- ${a.source} ${a.metric}: ${direction} (z=${a.zScore.toFixed(2)})`
      );
    }
    lines.push("");
  } else {
    lines.push("ANOMALIES DETECTED: none this period");
    lines.push("");
  }

  // Expat funnel
  lines.push("EXPAT FUNNEL:");
  lines.push(data.funnelSummary);

  // Distress alerts (only shown when areas are flagged)
  if (data.distressAreas.length > 0) {
    lines.push("");
    lines.push("DISTRESS ALERTS:");
    for (const area of data.distressAreas) {
      lines.push(
        `- ${area.area}: distress score ${area.score.toFixed(2)} — investigate with /uae_distress`
      );
    }
  }

  const full = lines.join("\n");

  // Enforce 4000 char limit (Telegram message limit)
  if (full.length <= 4000) {
    return full;
  }

  // Truncate with indicator
  return full.slice(0, 3990) + "\n[truncated]";
}

/**
 * Map a zone identifier to a human-readable label.
 */
function zoneToLabel(zone: string): string {
  switch (zone) {
    case "strong_buy":
      return "STRONG BUY";
    case "strong_sell":
      return "STRONG SELL";
    case "neutral":
    default:
      return "NEUTRAL";
  }
}
