/**
 * Area Name Normalizer
 *
 * Resolves user-supplied area names (abbreviations, typos, alternate spellings)
 * to canonical area names used throughout the UAE RE intelligence system.
 *
 * Resolution order:
 * 1. Alias table (exact abbreviation match)
 * 2. Exact case-insensitive match against DB (normalized_monthly + area_names)
 * 3. Levenshtein fuzzy match (threshold <= 2 edits)
 */

import type Database from "better-sqlite3";
import { getCanonicalArea } from "../areas/mapping.js";

export interface ResolveResult {
  canonical: string;
  confidence: "exact" | "alias" | "fuzzy";
  alternatives?: string[]; // for ambiguous fuzzy matches (>1 match)
  correctedFrom?: string; // original input for inline correction message
}

/**
 * Common UAE area abbreviations mapped to canonical names.
 * Keys are uppercase abbreviations.
 */
const ALIASES: Record<string, string> = {
  JVC: "Jumeirah Village Circle",
  JBR: "Jumeirah Beach Residence",
  DIFC: "Dubai International Financial Centre",
  DIP: "Dubai Investment Park",
  JLT: "Jumeirah Lake Towers",
  MBR: "Mohammed Bin Rashid City",
  "MBR CITY": "Mohammed Bin Rashid City",
  IMPZ: "International Media Production Zone",
  JAFZA: "Jebel Ali Free Zone",
  DSO: "Dubai Silicon Oasis",
  DHCC: "Dubai Healthcare City",
  DWC: "Dubai World Central",
  DIC: "Dubai Internet City",
  DMC: "Dubai Media City",
  KV: "Knowledge Village",
  SZR: "Sheikh Zayed Road",
  DAMAC: "DAMAC Hills",
  "DAMAC HILLS": "DAMAC Hills",
  JVC1: "Jumeirah Village Circle",
  JVT: "Jumeirah Village Triangle",
  JI: "Jumeirah Islands",
  JGE: "Jumeirah Golf Estates",
  JH: "Jumeirah Heights",
  DFC: "Dubai Festival City",
  DCC: "Dubai Creek Club",
  DUBAILAND: "Dubailand",
  BUR: "Bur Dubai",
  DEIRA: "Deira",
  KARAMA: "Al Karama",
  QR: "Qusais",
};

/**
 * Compute Levenshtein distance between two strings.
 * Standard DP matrix implementation.
 */
export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  // dp[i][j] = edit distance between a[0..i-1] and b[0..j-1]
  const dp: number[][] = [];
  for (let i = 0; i <= m; i++) {
    dp[i] = [];
    dp[i]![0] = i;
  }
  for (let j = 0; j <= n; j++) {
    dp[0]![j] = j;
  }
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i]![j] = dp[i - 1]![j - 1]!;
      } else {
        dp[i]![j] =
          1 +
          Math.min(
            dp[i - 1]![j]!,     // deletion
            dp[i]![j - 1]!,     // insertion
            dp[i - 1]![j - 1]!  // substitution
          );
      }
    }
  }
  return dp[m]![n]!;
}

/**
 * Get all distinct area names from the database.
 * Combines normalized_monthly areas and area_names table.
 */
function getAllDbAreas(db: Database.Database): string[] {
  const areas = new Set<string>();

  // From normalized_monthly table (actual data areas)
  try {
    const rows = db
      .prepare("SELECT DISTINCT area FROM normalized_monthly WHERE area IS NOT NULL")
      .all() as Array<{ area: string }>;
    for (const row of rows) {
      if (row.area) areas.add(row.area);
    }
  } catch {
    // Table may not exist yet — gracefully skip
  }

  // From area_names table (seeded canonical names)
  try {
    const rows = db
      .prepare("SELECT canonical_name FROM area_names WHERE canonical_name IS NOT NULL")
      .all() as Array<{ canonical_name: string }>;
    for (const row of rows) {
      if (row.canonical_name) areas.add(row.canonical_name);
    }
  } catch {
    // Table may not exist yet — gracefully skip
  }

  return Array.from(areas);
}

/**
 * Resolve user-supplied area input to a canonical area name.
 *
 * @param input - Raw user input (e.g. "JVC", "Jumeirah Village Cirlce", "Dubai Marina")
 * @param db - Database instance for area lookups
 * @returns ResolveResult if found, null if completely unrecognized
 */
export function resolveArea(
  input: string,
  db: Database.Database
): ResolveResult | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // Step 1: Check alias table (uppercase exact match)
  const upper = trimmed.toUpperCase();
  if (ALIASES[upper]) {
    return {
      canonical: ALIASES[upper]!,
      confidence: "alias",
    };
  }

  // Step 2: Case-insensitive exact match against normalized_monthly
  try {
    const row = db
      .prepare(
        "SELECT DISTINCT area FROM normalized_monthly WHERE UPPER(area) = ? LIMIT 1"
      )
      .get(upper) as { area: string } | undefined;
    if (row?.area) {
      return { canonical: row.area, confidence: "exact" };
    }
  } catch {
    // Table may not exist yet
  }

  // Step 3: Case-insensitive exact match via area_names table (getCanonicalArea)
  const areaLookup = getCanonicalArea(db, trimmed);
  if (areaLookup.found && areaLookup.canonicalName) {
    return { canonical: areaLookup.canonicalName, confidence: "exact" };
  }

  // Step 4: Fuzzy match (Levenshtein distance <= 2)
  const allAreas = getAllDbAreas(db);
  const inputLower = trimmed.toLowerCase();

  const candidates: Array<{ area: string; dist: number }> = [];
  for (const area of allAreas) {
    const dist = levenshtein(inputLower, area.toLowerCase());
    if (dist <= 2) {
      candidates.push({ area, dist });
    }
  }

  if (candidates.length === 0) return null;

  // Sort by distance, then alphabetically for determinism
  candidates.sort((a, b) => a.dist - b.dist || a.area.localeCompare(b.area));

  const bestDist = candidates[0]!.dist;
  const bestMatches = candidates.filter((c) => c.dist === bestDist);

  if (bestMatches.length === 1) {
    return {
      canonical: bestMatches[0]!.area,
      confidence: "fuzzy",
      correctedFrom: trimmed,
    };
  }

  // Multiple equally-close matches — return ambiguous result
  const allMatchAreas = candidates.map((c) => c.area);
  return {
    canonical: bestMatches[0]!.area,
    confidence: "fuzzy",
    alternatives: allMatchAreas,
    correctedFrom: trimmed,
  };
}
