/**
 * @lobsec/uae-re - UAE Real Estate Intelligence System
 *
 * Provides data collection, normalization, statistical analysis, and
 * intelligence products for UAE real estate market monitoring.
 *
 * OpenClaw plugin entry point with uae_collection_status tool.
 */

// Product query functions
import { queryAreaSignal } from "./products/prod01-area-signal.js";
import { queryDistress } from "./products/prod02-distress.js";
import { queryRentalIntel } from "./products/prod03-rental.js";
import { querySupplyPipeline } from "./products/prod04-supply.js";
import { queryExpatFunnel } from "./products/prod05-expat-funnel.js";
import { queryMacroHealth } from "./products/prod06-macro-health.js";
import { queryArbitrage } from "./products/prod07-arbitrage.js";
import { querySalaryRent } from "./products/prod08-salary-rent.js";
import { resolveArea, type ResolveResult } from "./tools/area-normalizer.js";

// Database layer
export { initDatabase, closeDatabase } from "./db/connection.js";
export { initSchema } from "./db/schema.js";
export {
  insertRawSource,
  insertNormalized,
  queryNormalized,
  insertCollectionLog,
  getLatestCollection,
  insertArea,
  getCanonicalName,
  getAllAreas,
  addAreaAlias,
  deleteNormalizedRange,
} from "./db/queries.js";
export type {
  MonthlyDataPoint,
  RawSourceEntry,
  CollectionLogEntry,
  AreaEntry,
} from "./db/queries.js";

// Cache layer
export { IntelligenceCache } from "./cache/manager.js";
export { DEFAULT_CACHE_CONFIG } from "./cache/types.js";
export type { CacheEntry, CacheConfig } from "./cache/types.js";

// Collector framework
export { SourceCollector } from "./collectors/base.js";
export { CollectorRegistry } from "./collectors/registry.js";
export type {
  CollectorMetadata,
  CollectionResult,
  CollectorStatus,
  CollectorInfo,
  RegistryRunResult,
  CollectionFrequency,
  ScraperApiConfig,
} from "./collectors/types.js";
export { createDefaultScraperConfig } from "./collectors/config.js";

// Analytics bridge
export {
  runPython,
  checkPythonAvailable,
  checkDependencies,
} from "./analytics/bridge.js";
export type {
  PythonResult,
  PythonScriptName,
  BridgeConfig,
} from "./analytics/types.js";

// Area mapping
export {
  initAreaTable,
  getCanonicalArea,
  getAreaAliases,
  addDiscoveredArea,
  getAllAreas as getAllAreasFromMapping,
} from "./areas/mapping.js";
export type { AreaLookupResult } from "./areas/mapping.js";
export { SEED_AREAS } from "./areas/seed-areas.js";
export type { AreaSeed } from "./areas/seed-areas.js";

// Normalization pipeline
export { normalizeCollectionResult } from "./normalization/orchestrator.js";
export { detectGaps } from "./normalization/gap-detection.js";
export { validateVolume } from "./normalization/volume-validation.js";
export {
  SOURCE_MODULE_MAP,
  type NormalizationInput,
  type NormalizationResult,
  type GapWarning,
  type VolumeWarning,
  type NormalizedRecord,
} from "./normalization/types.js";

// ── OpenClaw Plugin Entry Point ─────────────────────────────────────────────

import { initDatabase } from "./db/connection.js";
import { CollectorRegistry } from "./collectors/registry.js";
import { IntelligenceCache } from "./cache/manager.js";
import { getLatestCollection } from "./db/queries.js";
import { initAreaTable } from "./areas/mapping.js";
import { runPython } from "./analytics/bridge.js";
import { detectGaps } from "./normalization/gap-detection.js";
import path from "node:path";

import type { ScraperApiConfig } from "./collectors/types.js";

// OpenClaw type stubs (matches pi-agent-core AgentTool shape)
interface AgentToolResult {
  content: Array<{ type: "text"; text: string }>;
  details: unknown;
}

interface AgentTool {
  name: string;
  label: string;
  description: string;
  parameters: unknown; // TypeBox TSchema
  execute: (
    toolCallId: string,
    params: Record<string, unknown>,
    signal?: AbortSignal
  ) => Promise<AgentToolResult>;
}

interface PluginApi {
  id: string;
  config: Record<string, unknown>;
  pluginConfig?: Record<string, unknown>;
  logger: {
    info: (...args: unknown[]) => void;
    warn: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
  };
  registerTool: (tool: AgentTool) => void;
}

// Helpers
function textResult(text: string): AgentToolResult {
  return { content: [{ type: "text", text }], details: { text } };
}

function getEnv(key: string, defaultValue?: string): string {
  const val = process.env[key];
  if (!val) {
    if (defaultValue !== undefined) return defaultValue;
    throw new Error(`Missing env var: ${key}`);
  }
  return val;
}

// JSON Schema helpers (TypeBox-compatible shapes)
const OPTIONAL_MARKER = Symbol("optional");

const Type = {
  Object: (props: Record<string, unknown>, opts?: Record<string, unknown>) => {
    const required = Object.keys(props).filter(
      (k) => !(props[k] && typeof props[k] === "object" && OPTIONAL_MARKER in (props[k] as Record<symbol, unknown>))
    );
    // Strip optional markers from properties before emitting schema
    const cleanProps: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(props)) {
      if (v && typeof v === "object" && OPTIONAL_MARKER in (v as Record<symbol, unknown>)) {
        const { [OPTIONAL_MARKER]: _, ...rest } = v as Record<string | symbol, unknown>;
        cleanProps[k] = rest;
      } else {
        cleanProps[k] = v;
      }
    }
    return {
      type: "object" as const,
      properties: cleanProps,
      ...(required.length > 0 ? { required } : {}),
      ...opts,
    };
  },
  String: (opts?: Record<string, unknown>) => ({ type: "string" as const, ...opts }),
  Number: (opts?: Record<string, unknown>) => ({ type: "number" as const, ...opts }),
  Optional: (schema: unknown) => ({ ...(schema as Record<string, unknown>), [OPTIONAL_MARKER]: true }),
};

// Plugin entry point
export default {
  id: "lobsec-uae-re",

  register(api: PluginApi) {
    const log = api.logger;

    try {
      // Initialize database
      const dataDir = getEnv("UAE_RE_DATA_DIR", "/opt/lobsec/data");
      log.info(`[lobsec-uae-re] initializing database at ${dataDir}`);
      const db = initDatabase(dataDir);
      log.info(`[lobsec-uae-re] database initialized successfully`);

      // Seed area names table on startup
      initAreaTable(db);
      log.info(`[lobsec-uae-re] area names table seeded`);

    // Create registry and cache
    const registry = new CollectorRegistry();
    const cache = new IntelligenceCache(db);

    // Create scraper API config from environment
    const scraperConfig: ScraperApiConfig = {
      baseUrl: process.env.SCRAPER_BASE_URL || "http://127.0.0.1:18791",
      authToken: getEnv("SCRAPER_AUTH_TOKEN", ""),
      pollIntervalMs: 5000,
      maxWaitMs: 600_000,
    };

    // Register all 7 collectors via factory (all are SourceCollector instances)
    registry.createCollectors(db, scraperConfig);

    // Shared area resolution helper
    function resolveAreaOrError(
      input: string
    ): { result: ResolveResult; prefix: string } | { error: string } {
      const resolved = resolveArea(input, db);
      if (!resolved)
        return {
          error: `Unknown area: "${input}". Use uae_collection_status() to see valid areas.`,
        };
      if (resolved.alternatives && resolved.alternatives.length > 1) {
        return {
          error: `Ambiguous area "${input}". Did you mean:\n${resolved.alternatives.slice(0, 8).join("\n")}`,
        };
      }
      const prefix = resolved.correctedFrom
        ? `Showing results for "${resolved.canonical}" (from "${resolved.correctedFrom}")\n\n`
        : "";
      return { result: resolved, prefix };
    }

    // TOOL-01: uae_area_signal
    api.registerTool({
      name: "uae_area_signal",
      label: "UAE Area Signal",
      description:
        "Returns buy/sell signal score (-1 to +1) with component breakdown for a Dubai area.",
      parameters: Type.Object({
        area: Type.String({
          description: "Area name or abbreviation (e.g. JVC, Dubai Marina)",
        }),
        property_type: Type.Optional(
          Type.String({
            description: "apartment | villa | townhouse",
          })
        ),
      }),
      execute: async (_id, params) => {
        try {
          const area = String(params.area ?? "");
          const property_type = params.property_type
            ? String(params.property_type)
            : undefined;
          const resolved = resolveAreaOrError(area);
          if ("error" in resolved) return textResult(resolved.error);
          const cacheKey = { area: resolved.result.canonical, property_type };
          const cached = cache.get<{ formattedText: string }>(
            "area_signal",
            cacheKey
          );
          if (cached) return textResult(resolved.prefix + cached.formattedText);
          const result = queryAreaSignal(db, resolved.result.canonical);
          if (!result)
            return textResult(
              `No area signal data available for "${resolved.result.canonical}".`
            );
          cache.set("area_signal", cacheKey, result, 3600000);
          return textResult(resolved.prefix + result.formattedText);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-02: uae_distress
    api.registerTool({
      name: "uae_distress",
      label: "UAE Distress Signals",
      description:
        "Returns distress signals. With area: detailed 17-signal breakdown. Without: top 5 most distressed areas.",
      parameters: Type.Object({
        area: Type.Optional(
          Type.String({
            description: "Area name or abbreviation. Omit for top-5 ranking.",
          })
        ),
      }),
      execute: async (_id, params) => {
        try {
          if (params.area) {
            const area = String(params.area);
            const resolved = resolveAreaOrError(area);
            if ("error" in resolved) return textResult(resolved.error);
            const cacheKey = { area: resolved.result.canonical };
            const cached = cache.get<{ formattedText: string }>(
              "distress",
              cacheKey
            );
            if (cached)
              return textResult(resolved.prefix + cached.formattedText);
            const result = queryDistress(db, resolved.result.canonical);
            if (!result)
              return textResult(
                `No distress data available for "${resolved.result.canonical}".`
              );
            cache.set("distress", cacheKey, result, 3600000);
            return textResult(resolved.prefix + result.formattedText);
          } else {
            // Top-5 mode
            const cacheKey = { product: "distress_topN" };
            const cached = cache.get<{ formattedText: string }>(
              "distress_topN",
              cacheKey
            );
            if (cached) return textResult(cached.formattedText);
            const rows = db
              .prepare(
                `SELECT area, score FROM composite_scores
                 WHERE computed_at = (SELECT MAX(computed_at) FROM composite_scores)
                 ORDER BY score DESC LIMIT 5`
              )
              .all() as Array<{ area: string; score: number }>;
            if (rows.length === 0)
              return textResult("No composite scores available yet.");
            const lines = [
              "Top 5 Most Distressed Areas (latest month)",
              "",
              ...rows.map(
                (r, i) => `${i + 1}. ${r.area}: ${r.score.toFixed(2)}`
              ),
            ];
            const text = lines.join("\n");
            cache.set("distress_topN", cacheKey, { formattedText: text }, 3600000);
            return textResult(text);
          }
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-03: uae_rental_intel
    api.registerTool({
      name: "uae_rental_intel",
      label: "UAE Rental Intelligence",
      description:
        "Returns rental intelligence: gross yield, momentum, vacancy proxy, renewal rate, DOM trend, affordability.",
      parameters: Type.Object({
        area: Type.String({
          description: "Area name or abbreviation (e.g. JBR, Dubai Marina)",
        }),
      }),
      execute: async (_id, params) => {
        try {
          const area = String(params.area ?? "");
          const resolved = resolveAreaOrError(area);
          if ("error" in resolved) return textResult(resolved.error);
          const cacheKey = { area: resolved.result.canonical };
          const cached = cache.get<{ formattedText: string }>(
            "rental_intel",
            cacheKey
          );
          if (cached) return textResult(resolved.prefix + cached.formattedText);
          const result = queryRentalIntel(db, resolved.result.canonical);
          if (!result)
            return textResult(
              `No rental intelligence data available for "${resolved.result.canonical}".`
            );
          cache.set("rental_intel", cacheKey, result, 3600000);
          return textResult(resolved.prefix + result.formattedText);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-04: uae_supply_pipeline
    api.registerTool({
      name: "uae_supply_pipeline",
      label: "UAE Supply Pipeline",
      description:
        "Returns supply pipeline: permits, DEWA connections, cargo, delivery timeline. Omit area for city-wide.",
      parameters: Type.Object({
        area: Type.Optional(
          Type.String({
            description: "Area name or abbreviation. Omit for city-wide view.",
          })
        ),
      }),
      execute: async (_id, params) => {
        try {
          let canonicalArea: string | undefined;
          let prefix = "";
          if (params.area) {
            const area = String(params.area);
            const resolved = resolveAreaOrError(area);
            if ("error" in resolved) return textResult(resolved.error);
            canonicalArea = resolved.result.canonical;
            prefix = resolved.prefix;
          }
          const cacheKey = { area: canonicalArea ?? "all" };
          const cached = cache.get<{ formattedText: string }>(
            "supply_pipeline",
            cacheKey
          );
          if (cached) return textResult(prefix + cached.formattedText);
          const result = querySupplyPipeline(db, canonicalArea);
          if (!result)
            return textResult("No supply pipeline data available.");
          cache.set("supply_pipeline", cacheKey, result, 3600000);
          return textResult(prefix + result.formattedText);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-05: uae_expat_flow
    api.registerTool({
      name: "uae_expat_flow",
      label: "UAE Expat Flow",
      description:
        "Returns the 10-stage expat lifecycle funnel with current metrics at each stage.",
      parameters: Type.Object({}),
      execute: async (_id, _params) => {
        try {
          const cacheKey = {};
          const cached = cache.get<{ formattedText: string }>(
            "expat_flow",
            cacheKey
          );
          if (cached) return textResult(cached.formattedText);
          const result = queryExpatFunnel(db);
          if (!result)
            return textResult("No expat flow data available.");
          cache.set("expat_flow", cacheKey, result, 3600000);
          return textResult(result.formattedText);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-06: uae_macro_health
    api.registerTool({
      name: "uae_macro_health",
      label: "UAE Macro Health",
      description:
        "Returns macro health dashboard with traffic light (green/amber/red) for 9 signal groups: Employment, Housing, Spending, Mobility, Sentiment, Population, Macro Economy, RE Stocks, Commodities.",
      parameters: Type.Object({}),
      execute: async (_id, _params) => {
        try {
          const cacheKey = {};
          const cached = cache.get<{ formattedText: string }>(
            "macro_health",
            cacheKey
          );
          if (cached) return textResult(cached.formattedText);
          const result = queryMacroHealth(db);
          if (!result)
            return textResult("No macro health data available.");
          cache.set("macro_health", cacheKey, result, 3600000);
          return textResult(result.formattedText);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-07: uae_arbitrage
    api.registerTool({
      name: "uae_arbitrage",
      label: "UAE Off-Plan Arbitrage",
      description:
        "Returns off-plan vs ready premium spread for an area.",
      parameters: Type.Object({
        area: Type.String({
          description: "Area name or abbreviation",
        }),
        property_type: Type.Optional(
          Type.String({ description: "apartment | villa | townhouse" })
        ),
      }),
      execute: async (_id, params) => {
        try {
          const area = String(params.area ?? "");
          const property_type = params.property_type
            ? String(params.property_type)
            : undefined;
          const resolved = resolveAreaOrError(area);
          if ("error" in resolved) return textResult(resolved.error);
          const cacheKey = {
            area: resolved.result.canonical,
            property_type,
          };
          const cached = cache.get<{ formattedText: string }>(
            "arbitrage",
            cacheKey
          );
          if (cached) return textResult(resolved.prefix + cached.formattedText);
          const result = queryArbitrage(db, resolved.result.canonical);
          if (!result)
            return textResult(
              `No arbitrage data available for "${resolved.result.canonical}".`
            );
          cache.set("arbitrage", cacheKey, result, 3600000);
          return textResult(resolved.prefix + result.formattedText);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-08: uae_salary_rent
    api.registerTool({
      name: "uae_salary_rent",
      label: "UAE Salary-Rent Pressure",
      description:
        "Returns salary-rent pressure map with affordable areas by income bracket.",
      parameters: Type.Object({
        income_bracket: Type.Optional(
          Type.String({
            description: "junior | mid | senior | executive | all",
          })
        ),
      }),
      execute: async (_id, params) => {
        try {
          const income_bracket = params.income_bracket
            ? String(params.income_bracket)
            : undefined;
          const cacheKey = { bracket: income_bracket ?? "all" };
          const cached = cache.get<{ formattedText: string }>(
            "salary_rent",
            cacheKey
          );
          if (cached) return textResult(cached.formattedText);
          const result = querySalaryRent(db, income_bracket);
          if (!result)
            return textResult("No salary-rent data available.");
          cache.set("salary_rent", cacheKey, result, 3600000);
          return textResult(result.formattedText);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // Helper: compute next scheduled run time based on frequency
    function nextScheduledRun(frequency: string): string {
      const now = new Date();
      const nextDate = new Date(now);
      switch (frequency) {
        case "daily": {
          // Tomorrow at 23:00 GST (19:00 UTC)
          nextDate.setUTCDate(nextDate.getUTCDate() + 1);
          nextDate.setUTCHours(19, 0, 0, 0);
          break;
        }
        case "weekly": {
          // Next Monday at 02:00 UTC
          const daysUntilMonday = (8 - nextDate.getUTCDay()) % 7 || 7;
          nextDate.setUTCDate(nextDate.getUTCDate() + daysUntilMonday);
          nextDate.setUTCHours(2, 0, 0, 0);
          break;
        }
        case "monthly": {
          // 1st of next month at 02:00 UTC
          nextDate.setUTCMonth(nextDate.getUTCMonth() + 1, 1);
          nextDate.setUTCHours(2, 0, 0, 0);
          break;
        }
        case "quarterly": {
          // Next 15th of Jan/Apr/Jul/Oct at 05:00 UTC
          const quarterMonths = [0, 3, 6, 9]; // Jan, Apr, Jul, Oct (0-indexed)
          const currentMonth = nextDate.getUTCMonth();
          const currentDay = nextDate.getUTCDate();
          let nextQMonth = quarterMonths.find(
            (m) => m > currentMonth || (m === currentMonth && currentDay < 15)
          );
          if (nextQMonth === undefined) nextQMonth = 0; // wrap to Jan next year
          const nextYear =
            nextQMonth <= currentMonth && currentDay >= 15
              ? nextDate.getUTCFullYear() + 1
              : nextDate.getUTCFullYear();
          nextDate.setUTCFullYear(nextYear, nextQMonth, 15);
          nextDate.setUTCHours(5, 0, 0, 0);
          break;
        }
      }
      return nextDate.toISOString();
    }

    // TOOL-10: uae_collection_status (enhanced with staleness, row counts, next run)
    api.registerTool({
      name: "uae_collection_status",
      label: "UAE Collection Status",
      description:
        "Show collection status for all UAE RE data sources. Returns last run times, staleness flags, normalized row counts, and next scheduled run.",
      parameters: Type.Object({}),
      execute: async (_id, _params) => {
        try {
          const collectors = registry.getAll();

          if (collectors.length === 0) {
            return textResult(
              "No collectors registered. This should not happen."
            );
          }

          const lines = ["UAE Real Estate Collection Status", ""];

          for (const info of collectors) {
            const lastRun = getLatestCollection(db, info.metadata.source);
            const gaps = detectGaps(db, info.metadata.source, info.metadata.frequency);
            const isStale = gaps.length > 0;

            // Count normalized rows
            const rowCountRow = db
              .prepare(
                "SELECT COUNT(*) as cnt FROM normalized_monthly WHERE source = ?"
              )
              .get(info.metadata.source) as { cnt: number } | undefined;
            const normalizedRows = rowCountRow?.cnt ?? 0;

            const staleMarker = isStale ? " [STALE]" : "";
            lines.push(`Source: ${info.metadata.source}${staleMarker}`);
            lines.push(
              `  Frequency: ${info.metadata.frequency} | Priority: ${info.metadata.priority}`
            );

            if (lastRun) {
              lines.push(`  Last run: ${lastRun.timestamp} (${lastRun.status})`);
              lines.push(`  Rows: ${normalizedRows} normalized`);
              if (isStale && gaps[0] !== undefined) {
                lines.push(`  Staleness: ${gaps[0].gapDays} days overdue`);
              }
            } else {
              lines.push(`  Last run: (never)`);
              lines.push(`  Rows: ${normalizedRows} normalized`);
            }

            const nextRun = nextScheduledRun(info.metadata.frequency);
            lines.push(`  Next scheduled: ${nextRun}`);
            lines.push("");
          }

          return textResult(lines.join("\n"));
        } catch (error) {
          const msg =
            error instanceof Error ? error.message : String(error);
          return textResult(`Error querying collection status: ${msg}`);
        }
      },
    });

    // TOOL-09: uae_raw_data
    api.registerTool({
      name: "uae_raw_data",
      label: "UAE Raw Data",
      description:
        "Returns normalized data rows for a source in CSV format. Specify date range or get last 12 months.",
      parameters: Type.Object({
        source: Type.String({
          description:
            "Data source name (e.g. dld-sales, ejari-rentals, bayut-listings)",
        }),
        start_date: Type.Optional(
          Type.String({ description: "Start date YYYY-MM-DD (default: 12 months ago)" })
        ),
        end_date: Type.Optional(
          Type.String({ description: "End date YYYY-MM-DD (default: today)" })
        ),
      }),
      execute: async (_id, params) => {
        try {
          const source = String(params.source ?? "");
          const collectorInfo = registry.get(source);
          if (!collectorInfo) {
            const allSources = registry
              .getAll()
              .map((c) => c.metadata.source)
              .join(", ");
            return textResult(
              `Unknown source: "${source}". Valid sources: ${allSources}`
            );
          }

          const now = new Date();
          const defaultStart = new Date(now);
          defaultStart.setFullYear(defaultStart.getFullYear() - 1);

          const startDate = String(
            params.start_date ?? defaultStart.toISOString().slice(0, 10)
          );
          const endDate = String(
            params.end_date ?? now.toISOString().slice(0, 10)
          );

          const rows = db
            .prepare(
              `SELECT source, measurement_date, metric_name, value
               FROM normalized_monthly
               WHERE source = ? AND measurement_date >= ? AND measurement_date <= ?
               ORDER BY measurement_date, metric_name`
            )
            .all(source, startDate, endDate) as Array<{
            source: string;
            measurement_date: string;
            metric_name: string;
            value: number;
          }>;

          if (rows.length === 0) {
            return textResult(
              `No data for "${source}" between ${startDate} and ${endDate}.`
            );
          }

          // Build CSV from normalized rows
          const csvLines: string[] = ["source,measurement_date,metric_name,value"];
          for (const row of rows) {
            csvLines.push(`${row.source},${row.measurement_date},${row.metric_name},${row.value}`);
          }

          const csv = csvLines.join("\n");
          const truncated =
            csv.length > 4000
              ? csv.slice(0, 4000) + "\n[truncated — use date range to narrow results]"
              : csv;

          return textResult(truncated);
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-11: uae_trigger_collection
    api.registerTool({
      name: "uae_trigger_collection",
      label: "UAE Trigger Collection",
      description:
        "Manually trigger data collection for one source or all. Returns immediately; use uae_collection_status() to monitor.",
      parameters: Type.Object({
        source: Type.Optional(
          Type.String({
            description:
              "Source to collect (e.g. dld-sales). Omit to trigger all sources.",
          })
        ),
      }),
      execute: async (_id, params) => {
        try {
          const source = params.source ? String(params.source) : undefined;

          if (source) {
            const collectorInfo = registry.get(source);
            if (!collectorInfo) {
              const allSources = registry
                .getAll()
                .map((c) => c.metadata.source)
                .join(", ");
              return textResult(
                `Unknown source: "${source}". Valid sources: ${allSources}`
              );
            }
            setImmediate(() => {
              registry.runOne(source).catch((err: unknown) => {
                const msg =
                  err instanceof Error ? err.message : String(err);
                log.error(
                  `[lobsec-uae-re] trigger_collection error for ${source}: ${msg}`
                );
              });
            });
            return textResult(
              `Collection triggered for: ${source}. Use uae_collection_status() to monitor progress.`
            );
          } else {
            setImmediate(() => {
              registry.runAll().catch((err: unknown) => {
                const msg =
                  err instanceof Error ? err.message : String(err);
                log.error(
                  `[lobsec-uae-re] trigger_collection error for all: ${msg}`
                );
              });
            });
            return textResult(
              `Collection triggered for: all sources. Use uae_collection_status() to monitor progress.`
            );
          }
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-12: uae_granger_test
    api.registerTool({
      name: "uae_granger_test",
      label: "UAE Granger Causality Test",
      description:
        "Run live Granger causality test between any two data series. Signal format: source|metric.",
      parameters: Type.Object({
        signal: Type.String({
          description:
            "Signal series as source|metric, e.g. 'bayut-listings|avg_asking_price'",
        }),
        target: Type.String({
          description:
            "Target series as source|metric, e.g. 'dld-sales|avg_price_per_sqft'",
        }),
        max_lag: Type.Optional(
          Type.Number({ description: "Maximum lag in months (default: 6)" })
        ),
      }),
      execute: async (_id, params) => {
        try {
          const signal = String(params.signal ?? "");
          const target = String(params.target ?? "");
          if (!signal.includes("|"))
            return textResult(
              `signal must be 'source|metric', e.g. 'bayut-listings|avg_asking_price'`
            );
          if (!target.includes("|"))
            return textResult(
              `target must be 'source|metric', e.g. 'dld-sales|avg_price_per_sqft'`
            );

          const dbPath = path.join(dataDir, "uae-re.db");
          const result = await runPython("granger_ondemand", {
            signal,
            target,
            db_path: dbPath,
            max_lag: params.max_lag ?? 6,
          });

          if (!result.success) {
            return textResult(
              `Granger test failed: ${result.error ?? "unknown error"}`
            );
          }

          const data = result.data as
            | { output?: string; error?: string }
            | undefined;
          if (data?.error) {
            return textResult(`Granger test failed: ${data.error}`);
          }
          return textResult(
            data?.output ?? JSON.stringify(data)
          );
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

    // TOOL-13: uae_correlation
    api.registerTool({
      name: "uae_correlation",
      label: "UAE Cross-Correlation",
      description:
        "Run live cross-correlation analysis between any two data series. Signal format: source|metric.",
      parameters: Type.Object({
        signal: Type.String({
          description:
            "Signal series as source|metric, e.g. 'bayut-listings|avg_asking_price'",
        }),
        target: Type.String({
          description:
            "Target series as source|metric, e.g. 'dld-sales|avg_price_per_sqft'",
        }),
        max_lag: Type.Optional(
          Type.Number({ description: "Maximum lag in months (default: 12)" })
        ),
      }),
      execute: async (_id, params) => {
        try {
          const signal = String(params.signal ?? "");
          const target = String(params.target ?? "");
          if (!signal.includes("|"))
            return textResult(
              `signal must be 'source|metric', e.g. 'bayut-listings|avg_asking_price'`
            );
          if (!target.includes("|"))
            return textResult(
              `target must be 'source|metric', e.g. 'dld-sales|avg_price_per_sqft'`
            );

          const dbPath = path.join(dataDir, "uae-re.db");
          const result = await runPython("correlation_ondemand", {
            signal,
            target,
            db_path: dbPath,
            max_lag: params.max_lag ?? 12,
          });

          if (!result.success) {
            return textResult(
              `Correlation analysis failed: ${result.error ?? "unknown error"}`
            );
          }

          const data = result.data as
            | { output?: string; error?: string }
            | undefined;
          if (data?.error) {
            return textResult(`Correlation analysis failed: ${data.error}`);
          }
          return textResult(
            data?.output ?? JSON.stringify(data)
          );
        } catch (err) {
          return textResult(
            `Error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      },
    });

      log.info(
        "[lobsec-uae-re] registered 34 collectors + 13 tools"
      );
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      const stack = error instanceof Error ? error.stack : "";
      log.error(`[lobsec-uae-re] failed to initialize: ${msg}`);
      if (stack) {
        log.error(`[lobsec-uae-re] stack: ${stack}`);
      }
      throw error;
    }
  },
};
