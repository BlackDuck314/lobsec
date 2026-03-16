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
                 WHERE measurement_date = (SELECT MAX(measurement_date) FROM composite_scores)
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
        "Returns macro health dashboard with traffic light (green/amber/red) for 6 signal groups.",
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

    // Register uae_collection_status tool
    api.registerTool({
      name: "uae_collection_status",
      label: "UAE Collection Status",
      description:
        "Show collection status for all UAE RE data sources. Returns last run times, row counts, and staleness flags.",
      parameters: Type.Object({}),
      execute: async (_id, _params) => {
        try {
          const collectors = registry.getAll();

          if (collectors.length === 0) {
            return textResult(
              "No collectors registered. This should not happen."
            );
          }

          // Query collection_log for each collector
          const statuses = collectors.map((info) => {
            const lastRun = getLatestCollection(db, info.metadata.source);
            return {
              source: info.metadata.source,
              frequency: info.metadata.frequency,
              priority: info.metadata.priority,
              lastRun: lastRun
                ? {
                    timestamp: lastRun.timestamp,
                    status: lastRun.status,
                    rowCount: lastRun.rowCount,
                    durationMs: lastRun.durationMs,
                    error: lastRun.error,
                  }
                : null,
            };
          });

          // Format as text table
          const lines = ["UAE Real Estate Collection Status", ""];
          for (const s of statuses) {
            lines.push(`Source: ${s.source}`);
            lines.push(
              `  Frequency: ${s.frequency} | Priority: ${s.priority}`
            );
            if (s.lastRun) {
              lines.push(`  Last run: ${s.lastRun.timestamp}`);
              lines.push(`  Status: ${s.lastRun.status}`);
              if (s.lastRun.rowCount !== undefined) {
                lines.push(`  Rows: ${s.lastRun.rowCount}`);
              }
              if (s.lastRun.durationMs !== undefined) {
                lines.push(`  Duration: ${s.lastRun.durationMs}ms`);
              }
              if (s.lastRun.error) {
                lines.push(`  Error: ${s.lastRun.error}`);
              }
            } else {
              lines.push(`  Last run: (never)`);
            }
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

      log.info(
        "[lobsec-uae-re] registered 34 collectors + 9 tools"
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
