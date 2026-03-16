/**
 * DirectPythonCollector — Python-native data source collector
 *
 * Extends SourceCollector to bypass the Ninja Scraper API entirely.
 * Instead, collect() calls runPython() directly, suitable for API-native
 * sources like Google Trends (pytrends) and Reddit (PRAW) that do not
 * require browser automation.
 *
 * The Python module receives { outputDir } via stdin and returns
 * { filePath, rowCount } on stdout — same bridge contract as normalizers.
 */

import type Database from "better-sqlite3";
import { SourceCollector } from "./base.js";
import { runPython } from "../analytics/bridge.js";
import type { PythonScriptName } from "../analytics/types.js";
import type { CollectorMetadata, ScraperApiConfig } from "./types.js";

/**
 * Collector that executes a Python script directly via the subprocess bridge,
 * bypassing the Ninja Scraper HTTP API.
 *
 * Use for sources that have native Python client libraries (pytrends, praw)
 * and do not require browser automation or the Ninja Scraper crawler engine.
 *
 * The Python module must:
 * - Accept JSON on stdin: { outputDir: string }
 * - Print JSON on stdout: { filePath: string, rowCount: number }
 * - Exit 0 on success, non-zero on failure (with error on stderr)
 */
export class DirectPythonCollector extends SourceCollector {
  readonly pythonModule: PythonScriptName;

  constructor(
    metadata: CollectorMetadata,
    db: Database.Database,
    scraperConfig: ScraperApiConfig,
    pythonModule: PythonScriptName
  ) {
    // missionName stores the python module name as the collector identifier
    super(metadata, db, scraperConfig, pythonModule);
    this.pythonModule = pythonModule;
  }

  /**
   * Execute Python collect script via subprocess bridge.
   *
   * Passes outputDir to the Python script and returns filePath + rowCount.
   * If NINJA_PROXY_URL env var is present, passes it so the script can
   * route outbound requests through the proxy.
   *
   * @returns Object with filePath and rowCount on success
   * @throws Error on Python script failure
   */
  override async collect(): Promise<{ filePath: string; rowCount: number }> {
    const inputPayload: Record<string, string> = {
      outputDir: "/opt/lobsec/data/raw",
    };

    // Pass proxy URL if configured — Python scripts use it optionally
    const proxyUrl = process.env["NINJA_PROXY_URL"];
    if (proxyUrl) {
      inputPayload["proxyUrl"] = proxyUrl;
    }

    const result = await runPython<{ filePath: string; rowCount: number }>(
      this.pythonModule,
      inputPayload,
      { defaultTimeoutMs: this.metadata.timeout }
    );

    if (!result.success) {
      throw new Error(result.error ?? "Python collection failed");
    }

    if (!result.data) {
      throw new Error("Python script returned no data");
    }

    return {
      filePath: result.data.filePath,
      rowCount: result.data.rowCount,
    };
  }
}
