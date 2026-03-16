/**
 * Shared Telegram formatting utilities for all 8 intelligence products.
 *
 * All product formatters (Plans 02-04) import from this module.
 * Functions follow Telegram's 4096-character message limit and
 * support standard product metadata presentation.
 */

import { getNextAnalysisDate } from "../analytics/pipeline.js";

/**
 * Truncate text to fit Telegram's 4096-character message limit.
 *
 * Truncates to 4000 characters with a "[truncated]" suffix to leave
 * headroom for decorative characters.
 *
 * @param text - Message text to truncate if needed
 * @returns Original text if <= 4000 chars, or truncated version with suffix
 */
export function truncate4K(text: string): string {
  if (text.length <= 4000) return text;
  return text.slice(0, 3990) + "\n[truncated]";
}

/**
 * Generate a standard data freshness footer line.
 *
 * Indicates the date of the most recent data and when the next
 * pipeline run will refresh it.
 *
 * @param lastDate - ISO date string (YYYY-MM-DD) of most recent data point
 * @returns Footer string e.g. "Data as of: 2026-02-01 | Next update: 2026-03-25"
 */
export function freshnessFooter(lastDate: string): string {
  const nextRun = getNextAnalysisDate();
  return `Data as of: ${lastDate} | Next update: ${nextRun.toISOString().slice(0, 10)}`;
}

/**
 * Generate a staleness warning if data is overdue.
 *
 * Returns a warning string if the source date is more than 2x
 * the expected frequency behind today, or null if data is fresh.
 *
 * @param sourceDate - ISO date string of the most recent data point
 * @param expectedFreqDays - Expected update frequency in days (e.g. 30 for monthly)
 * @returns Warning string if stale (e.g. "WARNING: 65d since last update"), or null
 */
export function stalenessWarning(
  sourceDate: string,
  expectedFreqDays: number
): string | null {
  const daysSince =
    (Date.now() - new Date(sourceDate).getTime()) / 86400000;
  if (daysSince > expectedFreqDays * 2) {
    return `\u26a0\ufe0f STALE: ${Math.floor(daysSince)}d since last update`;
  }
  return null;
}

/**
 * Return a directional trend arrow comparing two values.
 *
 * @param current - Most recent value (or null if unavailable)
 * @param previous - Prior period value (or null if unavailable)
 * @returns "^" for increase, "v" for decrease, "=" for flat, "-" if data missing
 */
export function trendArrow(
  current: number | null,
  previous: number | null
): string {
  if (current === null || previous === null) return "-";
  return current > previous ? "^" : current < previous ? "v" : "=";
}

/**
 * Convert an internal zone key to a human-readable label.
 *
 * @param zone - Zone key from composite_scores table: "strong_buy", "strong_sell", or "neutral"
 * @returns Display label: "STRONG BUY", "STRONG SELL", or "NEUTRAL"
 */
export function zoneLabel(zone: string): string {
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
