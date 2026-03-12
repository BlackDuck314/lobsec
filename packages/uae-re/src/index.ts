/**
 * @lobsec/uae-re - UAE Real Estate Intelligence System
 *
 * Provides data collection, normalization, statistical analysis, and
 * intelligence products for UAE real estate market monitoring.
 *
 * OpenClaw plugin entry point with uae_collection_status tool.
 */

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
        "[lobsec-uae-re] registered 7 collectors + 1 tool"
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
