/**
 * Area Name Mapping
 *
 * Provides canonical area name lookup and management for UAE RE data normalization.
 */

import type Database from "better-sqlite3";
import { SEED_AREAS, type AreaSeed } from "./seed-areas.js";

/**
 * Area lookup result.
 */
export interface AreaLookupResult {
  /** Whether the area was found. */
  found: boolean;
  /** Canonical area name (if found). */
  canonicalName?: string;
  /** Emirate (if found). */
  emirate?: "dubai" | "abu_dhabi";
}

/**
 * Initialize area_names table with seed data.
 * Idempotent: uses INSERT OR IGNORE.
 *
 * @param db - Database instance
 */
export function initAreaTable(db: Database.Database): void {
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO area_names (canonical_name, emirate, aliases, source_variants)
    VALUES (?, ?, ?, ?)
  `);

  const insertMany = db.transaction((areas: AreaSeed[]) => {
    for (const area of areas) {
      stmt.run(
        area.canonicalName,
        area.emirate,
        area.aliases ? JSON.stringify(area.aliases) : null,
        area.sourceVariants ? JSON.stringify(area.sourceVariants) : null
      );
    }
  });

  insertMany(SEED_AREAS);
}

/**
 * Normalize raw area name to canonical form.
 * Strategy: Case-insensitive exact match against canonical_name, aliases, and source_variants.
 *
 * @param db - Database instance
 * @param rawName - Raw area name from data source
 * @returns Lookup result with canonical name and emirate if found
 */
export function getCanonicalArea(
  db: Database.Database,
  rawName: string
): AreaLookupResult {
  const normalized = rawName.trim().toUpperCase();

  // 1. Try exact match on canonical_name (case-insensitive)
  const directStmt = db.prepare(`
    SELECT canonical_name, emirate
    FROM area_names
    WHERE UPPER(canonical_name) = ?
  `);

  const directMatch = directStmt.get(normalized) as
    | { canonical_name: string; emirate: string }
    | undefined;

  if (directMatch) {
    return {
      found: true,
      canonicalName: directMatch.canonical_name,
      emirate: directMatch.emirate as "dubai" | "abu_dhabi",
    };
  }

  // 2. Search in aliases JSON array
  const aliasStmt = db.prepare(`
    SELECT canonical_name, emirate, aliases
    FROM area_names
    WHERE aliases IS NOT NULL
  `);

  const aliasRows = aliasStmt.all() as Array<{
    canonical_name: string;
    emirate: string;
    aliases: string;
  }>;

  for (const row of aliasRows) {
    const aliases: string[] = JSON.parse(row.aliases);
    if (aliases.some((alias) => alias.toUpperCase() === normalized)) {
      return {
        found: true,
        canonicalName: row.canonical_name,
        emirate: row.emirate as "dubai" | "abu_dhabi",
      };
    }
  }

  // 3. Search in source_variants JSON array
  const variantStmt = db.prepare(`
    SELECT canonical_name, emirate, source_variants
    FROM area_names
    WHERE source_variants IS NOT NULL
  `);

  const variantRows = variantStmt.all() as Array<{
    canonical_name: string;
    emirate: string;
    source_variants: string;
  }>;

  for (const row of variantRows) {
    const variants: string[] = JSON.parse(row.source_variants);
    if (variants.some((variant) => variant.toUpperCase() === normalized)) {
      return {
        found: true,
        canonicalName: row.canonical_name,
        emirate: row.emirate as "dubai" | "abu_dhabi",
      };
    }
  }

  // Not found
  return { found: false };
}

/**
 * Get all aliases for a canonical area name.
 *
 * @param db - Database instance
 * @param canonicalName - Canonical area name
 * @returns Array of aliases (empty if none exist)
 */
export function getAreaAliases(
  db: Database.Database,
  canonicalName: string
): string[] {
  const stmt = db.prepare(`
    SELECT aliases
    FROM area_names
    WHERE canonical_name = ?
  `);

  const row = stmt.get(canonicalName) as { aliases: string | null } | undefined;

  if (!row || !row.aliases) {
    return [];
  }

  return JSON.parse(row.aliases);
}

/**
 * Add a newly discovered area (not in seed list).
 * Used when normalization encounters an unknown area.
 *
 * @param db - Database instance
 * @param rawName - Raw area name to use as canonical
 * @param emirate - Emirate (dubai or abu_dhabi)
 */
export function addDiscoveredArea(
  db: Database.Database,
  rawName: string,
  emirate: "dubai" | "abu_dhabi"
): void {
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO area_names (canonical_name, emirate, aliases, source_variants)
    VALUES (?, ?, NULL, NULL)
  `);

  stmt.run(rawName.trim(), emirate);
}

/**
 * Get all areas, optionally filtered by emirate.
 *
 * @param db - Database instance
 * @param emirate - Optional emirate filter
 * @returns Array of area records
 */
export function getAllAreas(
  db: Database.Database,
  emirate?: "dubai" | "abu_dhabi"
): Array<{ canonicalName: string; emirate: string }> {
  let stmt: Database.Statement;

  if (emirate) {
    stmt = db.prepare(`
      SELECT canonical_name, emirate
      FROM area_names
      WHERE emirate = ?
      ORDER BY canonical_name ASC
    `);
  } else {
    stmt = db.prepare(`
      SELECT canonical_name, emirate
      FROM area_names
      ORDER BY canonical_name ASC
    `);
  }

  const rows = (
    emirate ? stmt.all(emirate) : stmt.all()
  ) as Array<{ canonical_name: string; emirate: string }>;

  return rows.map((row) => ({
    canonicalName: row.canonical_name,
    emirate: row.emirate,
  }));
}
