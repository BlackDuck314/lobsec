#!/usr/bin/env node

/**
 * UAE RE CLI Orchestrator
 *
 * Entry point for systemd collector service.
 * Commands: run-all, run-frequency, run-one, check-deps, init-db
 */

import { initDatabase, closeDatabase } from "./db/connection.js";
import { CollectorRegistry } from "./collectors/registry.js";
import { checkPythonAvailable, checkDependencies } from "./analytics/bridge.js";
import type { CollectionFrequency } from "./collectors/types.js";

// Parse command line args
const args = process.argv.slice(2);
const command = args[0];

// Get data directory from env or use default
const dataDir = process.env.UAE_RE_DATA_DIR || "/opt/lobsec/data";

/**
 * Print usage message and exit
 */
function usage(): never {
  console.error(`
Usage: uae-re-cli <command> [args]

Commands:
  run-all                Run all registered collectors
  run-frequency <freq>   Run collectors matching frequency (daily/weekly/monthly/quarterly/adhoc)
  run-one <source>       Run a specific collector by source name
  check-deps             Check Python availability and package dependencies
  init-db                Initialize database schema

Environment:
  UAE_RE_DATA_DIR        Data directory (default: /opt/lobsec/data)
`);
  process.exit(1);
}

/**
 * Run all collectors
 */
async function runAll(): Promise<void> {
  const db = initDatabase(dataDir);
  const registry = new CollectorRegistry();

  // No collectors registered yet — Phase 7+ adds them
  // This will run successfully with 0 collectors
  const result = await registry.runAll();

  console.log(
    `Ran ${result.successCount + result.failureCount} collectors in ${result.totalDuration}ms`
  );
  console.log(`  Success: ${result.successCount}`);
  console.log(`  Failure: ${result.failureCount}`);

  if (result.failureCount > 0) {
    for (const [source, res] of result.results.entries()) {
      if (!res.success) {
        console.error(`  ${source}: ${res.error}`);
      }
    }
  }

  closeDatabase(db);

  // Exit with failure if any collector failed
  if (result.failureCount > 0) {
    process.exit(1);
  }
}

/**
 * Run collectors by frequency
 */
async function runFrequency(freq: string): Promise<void> {
  const validFreqs = ["daily", "weekly", "monthly", "quarterly", "adhoc"];
  if (!validFreqs.includes(freq)) {
    console.error(`Invalid frequency: ${freq}`);
    console.error(`Valid frequencies: ${validFreqs.join(", ")}`);
    process.exit(1);
  }

  const db = initDatabase(dataDir);
  const registry = new CollectorRegistry();

  const result = await registry.runByFrequency(freq as CollectionFrequency);

  console.log(
    `Ran ${result.successCount + result.failureCount} collectors (${freq}) in ${result.totalDuration}ms`
  );
  console.log(`  Success: ${result.successCount}`);
  console.log(`  Failure: ${result.failureCount}`);

  if (result.failureCount > 0) {
    for (const [source, res] of result.results.entries()) {
      if (!res.success) {
        console.error(`  ${source}: ${res.error}`);
      }
    }
  }

  closeDatabase(db);

  if (result.failureCount > 0) {
    process.exit(1);
  }
}

/**
 * Run a single collector
 */
async function runOne(source: string): Promise<void> {
  const db = initDatabase(dataDir);
  const registry = new CollectorRegistry();

  try {
    const result = await registry.runOne(source);

    if (result.success) {
      console.log(
        `${source}: success (${result.rowCount} rows, ${result.duration}ms)`
      );
    } else {
      console.error(`${source}: failed — ${result.error}`);
      process.exit(1);
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${msg}`);
    process.exit(1);
  } finally {
    closeDatabase(db);
  }
}

/**
 * Check Python dependencies
 */
async function checkDeps(): Promise<void> {
  console.log("Checking Python availability...");
  const pythonResult = await checkPythonAvailable();

  if (!pythonResult.available) {
    console.error("Python 3.13+ not found in PATH or venv");
    if (pythonResult.error) {
      console.error(`  Error: ${pythonResult.error}`);
    }
    process.exit(1);
  }

  console.log(`Python: OK (${pythonResult.version})`);

  console.log("Checking Python packages...");
  const depsResult = await checkDependencies();

  if (!depsResult.available) {
    console.error("Python dependencies check failed:");
    for (const pkg of depsResult.missing) {
      console.error(`  Missing: ${pkg}`);
    }
    if (depsResult.error) {
      console.error(`  Error: ${depsResult.error}`);
    }
    process.exit(1);
  }

  console.log("Python packages: OK");
  console.log("All dependencies satisfied.");
}

/**
 * Initialize database
 */
async function initDb(): Promise<void> {
  console.log(`Initializing database at ${dataDir}...`);
  const db = initDatabase(dataDir);
  console.log("Database initialized successfully.");
  console.log(`  Location: ${dataDir}/uae-re.db`);
  closeDatabase(db);
}

// Main entry point
async function main(): Promise<void> {
  try {
    if (!command) {
      usage();
    }

    switch (command) {
      case "run-all":
        await runAll();
        break;

      case "run-frequency": {
        const freq = args[1];
        if (!freq) {
          console.error("Missing frequency argument");
          usage();
        }
        await runFrequency(freq);
        break;
      }

      case "run-one": {
        const source = args[1];
        if (!source) {
          console.error("Missing source argument");
          usage();
        }
        await runOne(source);
        break;
      }

      case "check-deps":
        await checkDeps();
        break;

      case "init-db":
        await initDb();
        break;

      default:
        console.error(`Unknown command: ${command}`);
        usage();
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Fatal error: ${msg}`);
    if (error instanceof Error && error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main();
