# Phase 7: MVP Data Collection (Tier A + DEWA) - Research

**Researched:** 2026-03-11
**Domain:** Web scraping (Playwright), data normalization (pandas), CSV collection, schema validation
**Confidence:** HIGH

## Summary

Phase 7 implements 7 concrete data collectors (DLD sales, Ejari rentals, building permits, ADREC Abu Dhabi, Bayut listings, PropertyFinder listings, DEWA connections) and the Python-based normalization pipeline that transforms raw collected data into monthly time-series stored in SQLite.

The technical stack is well-established: Playwright 1.58.2 (already installed in @lobsec/tools) for browser automation, pandas for time-series normalization, pandera for schema validation, and the existing SourceCollector framework with retry/circuit breaker. Dubai Pulse provides direct CSV downloads via HTTP GET (no API key required for open datasets), ADREC provides CSV export via browser click-to-download, and Bayut/PropertyFinder require direct Playwright scraping.

Key architectural pattern: **two-step pipeline** — collectors write raw files only, then normalization runs as a separate step via Python bridge. This separation allows re-running normalization without re-collecting data, enables source-specific transformation logic in Python, and supports idempotent upsert semantics.

**Primary recommendation:** Reuse existing Playwright from @lobsec/tools package. Build one collector per source extending SourceCollector. Use pandera for schema validation with hard-fail semantics. Store area name mapping as SQLite table (not hardcoded list). Start with Dubai Pulse collectors first (simplest: direct CSV download) before tackling browser automation collectors (ADREC, Bayut, PropertyFinder).

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**ADREC Abu Dhabi (replacing DARI UAE Pass):**
- COLL-04 uses ADREC public dashboards instead of UAE Pass-authenticated DARI portal
- Source: https://adrec.gov.ae/en/property_and_index/adrec-dashboard
- All dashboard sections to be collected: Transactions, Residential Leases, Price Indices, Recent Sales (107K+ rows)
- Export mechanism: Browser JS-triggered CSV download via Playwright click-to-download (not a direct HTTP URL)
- Dashboard has filters (Asset Type, District, Project, Layout, currency, period) — collector exports with broadest filters
- Fields: Asset Type, Property Type, Sale Type (Off-plan/Ready), District, Community, Project, Layout, Registration Date, Sold Area, Plot Area, Rate, Price, Share, Sequence

**Source Access Strategy:**
- Dubai Pulse (DLD, Ejari, permits): Researcher determines exact access method (direct CSV download vs API registration)
- ADREC (Abu Dhabi): Playwright click-to-download from public dashboard, no auth required
- Bayut: Direct Playwright scraping, no Apify cloud dependency
- PropertyFinder: Added as second listings source, scrape simultaneously with Bayut for cross-validation
- DEWA: Press release scraping, researcher evaluates feasibility
- No multi-source fallbacks: Each collector targets one source, fail gracefully with Telegram alert on block/unavailability

**Listings Collection (Bayut + PropertyFinder):**
- Two separate collectors: bayut-listings and propertyfinder-listings registered independently
- Each can fail independently without affecting the other
- Geographic scope: all Dubai areas (comprehensive coverage)
- Core listing metrics per area: active listing count, median asking price, median days on market (DOM), price reduction count

**Normalization Pipeline Architecture:**
- Two-step pipeline: Collectors write raw files → separate normalization step reads raw files, resamples to monthly, inserts to normalized_monthly
- Auto-trigger: Normalization runs automatically after collection completes
- One Python call per source: Each source has its own Python normalization module (e.g., normalize_dld.py, normalize_bayut.py)
- Upsert semantics: Normalization DELETEs existing rows for source+measurement_date range, then INSERTs new (idempotent)
- Gap detection (NORM-03): Runs during normalization, checks for gaps exceeding 2x expected frequency
- Schema validation (NORM-04): Hard error — if raw data fails column/type/range validation, collection marked as failed, no raw file saved, Telegram alert with mismatch details
- Volume validation (NORM-05): Skipped for first N runs (4 successful collections needed), gradually builds rolling average

**Metric Granularity:**
- DLD sales (COLL-01): Aggregated by (area, property_type). Extended metrics: transaction volume (count), median price (AED), median price per sqft, total value (AED), 25th/75th percentile price, YoY change, MoM change
- Ejari rentals (COLL-02): Same (area, property_type) granularity. Rental-specific metrics: renewal_rate, avg_rent_per_sqft, rent_YoY_change
- Building permits (COLL-03): Classified residential vs commercial, track permit withdrawal/expiry
- ADREC Abu Dhabi (COLL-04): Transaction-level data with (district, property_type, sale_type) granularity. Extended metrics matching DLD: volume, median price, rate/sqm, off-plan vs ready split, primary vs secondary. Also collect residential lease data and price indices
- Bayut/PropertyFinder listings (COLL-05): Core metrics per area: active listing count, median asking price, median DOM, price reduction count
- DEWA (COLL-15): Per-area breakdown required — researcher validates whether DEWA publishes area-level data

**Area Name Mapping:**
- Build canonical area name mapping table in Phase 7 (not deferred to Phase 12)
- Static seed list: Ship with curated list of ~100 Dubai areas + ~50 Abu Dhabi districts with canonical names and known aliases (JVC, JBR, DIFC, Al Reem Island, Yas Island, Saadiyat, etc.)
- Normalization uses mapping to standardize area names across all sources
- Extend list as new areas appear in collected data
- QUAL-04 (Phase 12) adds fuzzy matching for Telegram queries — Phase 7 builds underlying mapping data

### Claude's Discretion

- Exact Playwright scraping patterns for ADREC, Bayut, PropertyFinder, and DEWA
- Raw file format per source (CSV, JSON, or HTML snapshots)
- Python normalization module internal structure
- Area seed list compilation (which ~100 areas to include)
- Volume validation threshold (how many runs = "first N")
- Timeout settings per collector type

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| COLL-01 | DLD sales transactions — weekly CSV download from Dubai Pulse | Dubai Pulse direct CSV download confirmed via HTTP GET (no API key for open datasets). Field mapping documented in playbook. |
| COLL-02 | Ejari rental contracts — filtered from same DLD CSV | Same source as COLL-01, filter by trans_group_en=Rent. Shared download step, separate normalization. |
| COLL-03 | Dubai building permits — monthly CSV from Dubai Pulse | Direct CSV download from Dubai Pulse dm_building_permits-open dataset. |
| COLL-04 | ADREC Abu Dhabi — Playwright click-to-download from public dashboard | Playwright download event handling documented. ADREC dashboard confirmed to have CSV export buttons. Browser automation pattern via page.waitForEvent('download'). |
| COLL-05 | Property listings — Bayut + PropertyFinder via Playwright scraping | Bayut unofficial API exists but 2026 sources report anti-bot protection. Direct Playwright scraping required. PropertyFinder same pattern. |
| COLL-15 | DEWA connections/closures — press release scraping | Press release parsing via HTML scraping. Feasibility depends on whether area-level data is published (to be validated). |
| NORM-01 | Monthly normalization — pandas resample('ME').mean() with forward-fill limit=1 | pandas resample('ME') confirmed for month-end frequency. ffill(limit=1) documented for gap filling. |
| NORM-02 | Publication date tracking — store both measurement_date and available_date | Database schema already supports this via normalized_monthly table fields. |
| NORM-03 | Gap detection — flag STALE when gap exceeds 2x expected frequency | Logic implementable in Python normalization modules via date range check. |
| NORM-04 | Schema validation — validate columns, types, ranges; hard error on mismatch | pandera library provides DataFrame schema validation with dtype, column name, and range checks. |
| NORM-05 | Volume validation — compare to rolling 30-day average, alert if <50% | Logic implementable via collection_log queries for rolling average baseline. |

</phase_requirements>

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Playwright | 1.58.2 | Browser automation, file download | Already installed in @lobsec/tools. Industry standard for headless browser automation with native download handling. Microsoft-backed with excellent TypeScript support. |
| pandas | Latest in Python 3.13 venv | Time-series resampling, aggregation, normalization | De facto standard for time-series data manipulation in Python. resample('ME').mean() is the canonical pattern for monthly aggregation. |
| pandera | Latest via pip | DataFrame schema validation | Most comprehensive pandas schema validation library. Supports dtype checking, column name validation, value range constraints, and custom validators. |
| better-sqlite3 | 11.8.0 | Database storage | Already used in uae-re package. Fast, synchronous SQLite bindings with excellent TypeScript types. |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| BeautifulSoup4 (bs4) | Latest via pip | HTML parsing for press releases | Use for DEWA press release scraping if structured HTML tables exist. |
| pdfplumber | Already in venv | PDF text/table extraction | Future use if DEWA publishes PDFs instead of HTML. Not needed for Phase 7. |
| csv (Python stdlib) | Built-in | CSV parsing in Python | Use for parsing Dubai Pulse CSV downloads in normalization modules. |
| node:fs/promises | Node.js stdlib | File I/O for raw data storage | Use for writing raw CSV/JSON files from collectors. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Playwright | Puppeteer | Puppeteer is Chromium-only. Playwright supports Firefox/WebKit and has better download API. Already have Playwright in project. |
| pandera | pandas_schema | pandera has better documentation, active development, and statistical validation features. pandas_schema less actively maintained. |
| Direct CSV download | Dubai Pulse API | API requires registration for key/secret. Open datasets available via direct CSV download without authentication. Direct download is simpler for MVP. |
| Browser automation | Apify cloud scrapers | Apify adds external dependency, cost, and less control. User explicitly rejected Apify dependency for Bayut. Direct Playwright gives full control. |

**Installation:**
```bash
# Playwright already in packages/tools/package.json
# Python packages already in analytics-venv
cd /opt/lobsec/analytics-venv
source bin/activate
pip install pandera beautifulsoup4  # Add these to existing venv
```

## Architecture Patterns

### Recommended Project Structure
```
packages/uae-re/
├── src/
│   ├── collectors/
│   │   ├── base.ts              # SourceCollector abstract class (exists)
│   │   ├── registry.ts          # CollectorRegistry (exists)
│   │   ├── types.ts             # Types (exists)
│   │   ├── dld-sales.ts         # COLL-01 concrete collector
│   │   ├── ejari-rentals.ts     # COLL-02 concrete collector
│   │   ├── building-permits.ts  # COLL-03 concrete collector
│   │   ├── adrec-abu-dhabi.ts   # COLL-04 concrete collector
│   │   ├── bayut-listings.ts    # COLL-05 Bayut collector
│   │   ├── propertyfinder.ts    # COLL-05 PropertyFinder collector
│   │   └── dewa-connections.ts  # COLL-15 concrete collector
│   ├── normalization/
│   │   ├── orchestrator.ts      # Auto-trigger normalization after collection
│   │   ├── types.ts             # Normalization result types
│   │   └── gap-detection.ts     # NORM-03 gap detection logic
│   └── areas/
│       ├── mapping.ts           # Area name normalization functions
│       └── seed-areas.ts        # Static seed list of ~150 areas
├── python/uae_re/
│   ├── normalize_dld.py         # DLD-specific normalization
│   ├── normalize_ejari.py       # Ejari-specific normalization
│   ├── normalize_permits.py     # Building permits normalization
│   ├── normalize_adrec.py       # ADREC normalization
│   ├── normalize_bayut.py       # Bayut normalization
│   ├── normalize_propertyfinder.py  # PropertyFinder normalization
│   ├── normalize_dewa.py        # DEWA normalization
│   ├── schemas/
│   │   ├── dld_schema.py        # pandera schema for DLD validation
│   │   ├── ejari_schema.py      # pandera schema for Ejari
│   │   ├── permits_schema.py    # pandera schema for permits
│   │   ├── adrec_schema.py      # pandera schema for ADREC
│   │   ├── listings_schema.py   # pandera schema for Bayut/PropertyFinder
│   │   └── dewa_schema.py       # pandera schema for DEWA
│   └── utils/
│       ├── area_mapper.py       # Area name standardization
│       └── validators.py        # Volume validation logic
└── /opt/lobsec/data/
    └── raw/
        ├── dld-sales/           # DLD raw CSV files (YYYY-WW.csv)
        ├── ejari-rentals/       # Ejari raw CSV files
        ├── building-permits/    # Permits raw CSV files
        ├── adrec-abu-dhabi/     # ADREC raw CSV files
        ├── bayut-listings/      # Bayut raw JSON files
        ├── propertyfinder/      # PropertyFinder raw JSON files
        └── dewa-connections/    # DEWA raw HTML/JSON files
```

### Pattern 1: CSV Download Collector (Dubai Pulse)

**What:** Concrete SourceCollector that downloads CSV files via HTTP GET and saves to disk.

**When to use:** For DLD sales (COLL-01), Ejari rentals (COLL-02), building permits (COLL-03).

**Example:**
```typescript
// Source: Existing SourceCollector pattern + Dubai Pulse direct CSV download
import { SourceCollector } from "./base.js";
import type { CollectorMetadata } from "./types.js";
import type Database from "better-sqlite3";
import { promises as fs } from "node:fs";
import { resolve } from "node:path";

export class DLDSalesCollector extends SourceCollector {
  constructor(db: Database.Database) {
    super(
      {
        source: "dld-sales",
        frequency: "weekly",
        priority: 1,
        timeout: 60_000, // 1 minute for CSV download
      } satisfies CollectorMetadata,
      db
    );
  }

  async collect(): Promise<{ filePath: string; rowCount: number }> {
    const url = "https://www.dubaipulse.gov.ae/data/dld-transactions/dld_transactions-open";

    // Download CSV
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const csvContent = await response.text();

    // Count rows (minus header)
    const rowCount = csvContent.split('\n').length - 1;

    // Save to raw directory with date-based filename
    const timestamp = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const filePath = resolve("/opt/lobsec/data/raw/dld-sales", `${timestamp}.csv`);

    await fs.mkdir(resolve("/opt/lobsec/data/raw/dld-sales"), { recursive: true });
    await fs.writeFile(filePath, csvContent, "utf-8");

    return { filePath, rowCount };
  }
}
```

### Pattern 2: Playwright Click-to-Download Collector (ADREC)

**What:** Concrete SourceCollector that uses Playwright to navigate dashboard, click export button, and capture downloaded CSV file.

**When to use:** For ADREC Abu Dhabi (COLL-04) where CSV export is JS-triggered via browser click.

**Example:**
```typescript
// Source: Playwright download API docs + ADREC dashboard requirements
import { SourceCollector } from "./base.js";
import type { CollectorMetadata } from "./types.js";
import type Database from "better-sqlite3";
import { chromium } from "playwright";
import { promises as fs } from "node:fs";
import { resolve } from "node:path";

export class ADRECAbuDhabiCollector extends SourceCollector {
  constructor(db: Database.Database) {
    super(
      {
        source: "adrec-abu-dhabi",
        frequency: "monthly",
        priority: 2,
        timeout: 120_000, // 2 minutes for browser automation
      } satisfies CollectorMetadata,
      db
    );
  }

  async collect(): Promise<{ filePath: string; rowCount: number }> {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();

    try {
      // Navigate to ADREC dashboard
      await page.goto("https://adrec.gov.ae/en/property_and_index/adrec-dashboard");

      // Wait for page load
      await page.waitForLoadState("networkidle");

      // Set broadest filters (all asset types, all districts, all time)
      // Specific selectors to be determined during implementation

      // Wait for download event before clicking export button
      const downloadPromise = page.waitForEvent('download');
      await page.click('button:has-text("Export"), button:has-text("Download CSV")');

      const download = await downloadPromise;

      // Save to raw directory
      const timestamp = new Date().toISOString().split('T')[0];
      const filePath = resolve("/opt/lobsec/data/raw/adrec-abu-dhabi", `${timestamp}.csv`);

      await fs.mkdir(resolve("/opt/lobsec/data/raw/adrec-abu-dhabi"), { recursive: true });
      await download.saveAs(filePath);

      // Read file to count rows
      const content = await fs.readFile(filePath, "utf-8");
      const rowCount = content.split('\n').length - 1;

      return { filePath, rowCount };
    } finally {
      await browser.close();
    }
  }
}
```

### Pattern 3: Playwright Scraping Collector (Bayut/PropertyFinder)

**What:** Concrete SourceCollector that uses Playwright to scrape listing data from property portals.

**When to use:** For Bayut (COLL-05) and PropertyFinder (COLL-05) where no API exists or API has anti-bot protection.

**Example:**
```typescript
// Source: Playwright scraping patterns + Bayut anti-bot considerations
import { SourceCollector } from "./base.js";
import type { CollectorMetadata } from "./types.js";
import type Database from "better-sqlite3";
import { chromium } from "playwright";
import { promises as fs } from "node:fs";
import { resolve } from "node:path";

export class BayutListingsCollector extends SourceCollector {
  constructor(db: Database.Database) {
    super(
      {
        source: "bayut-listings",
        frequency: "weekly",
        priority: 3,
        timeout: 300_000, // 5 minutes for comprehensive scrape
      } satisfies CollectorMetadata,
      db
    );
  }

  async collect(): Promise<{ filePath: string; rowCount: number }> {
    const browser = await chromium.launch({
      headless: true,
      // Add stealth options to avoid bot detection
    });
    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36...',
      viewport: { width: 1920, height: 1080 },
    });
    const page = await context.newPage();

    const listings: Array<any> = [];

    try {
      // Iterate through Dubai areas (to be populated from area seed list)
      const areas = ["downtown-dubai", "dubai-marina", "jvc", "jbr"]; // Example

      for (const area of areas) {
        await page.goto(`https://www.bayut.com/for-rent/property/${area}/`);
        await page.waitForLoadState("networkidle");

        // Extract listing data (selectors to be determined)
        const areaListings = await page.evaluate(() => {
          // DOM scraping logic here
          return []; // Array of listing objects
        });

        listings.push(...areaListings);
      }

      // Save as JSON
      const timestamp = new Date().toISOString().split('T')[0];
      const filePath = resolve("/opt/lobsec/data/raw/bayut-listings", `${timestamp}.json`);

      await fs.mkdir(resolve("/opt/lobsec/data/raw/bayut-listings"), { recursive: true });
      await fs.writeFile(filePath, JSON.stringify(listings, null, 2), "utf-8");

      return { filePath, rowCount: listings.length };
    } finally {
      await browser.close();
    }
  }
}
```

### Pattern 4: Python Normalization Module with pandera Validation

**What:** Python module that reads raw CSV/JSON, validates schema with pandera, resamples to monthly, and outputs normalized JSON.

**When to use:** All sources (COLL-01 through COLL-15, NORM-01 through NORM-05).

**Example:**
```python
# Source: pandera documentation + pandas resample patterns
"""
DLD sales normalization module.

Bridge pattern:
- Read JSON input from stdin: {filePath, source, collectedAt}
- Load CSV from filePath
- Validate schema with pandera
- Aggregate by (area, property_type) with extended metrics
- Resample to month-end frequency
- Output normalized records to stdout as JSON
"""

import sys
import json
import pandas as pd
import pandera as pa
from pandera import Column, DataFrameSchema

# Define DLD schema (NORM-04)
dld_schema = DataFrameSchema({
    "trans_group_en": Column(str, pa.Check.isin(["Sales", "Rent"])),
    "actual_worth": Column(float, pa.Check.ge(0)),
    "meter_sale_price": Column(float, pa.Check.ge(0)),
    "prop_type_en": Column(str),
    "area_name_en": Column(str),
    "rooms_en": Column(str, nullable=True),
    "trans_date": Column(str),  # ISO8601 date string
})

def normalize_dld_sales(file_path: str, collected_at: str) -> list[dict]:
    """
    Normalize DLD sales data to monthly metrics.

    Args:
        file_path: Path to raw CSV file
        collected_at: ISO8601 timestamp when data was collected

    Returns:
        List of normalized monthly records
    """
    # Load raw CSV
    df = pd.read_csv(file_path)

    # Validate schema (NORM-04 hard error)
    dld_schema.validate(df, lazy=False)

    # Filter to sales only (trans_group_en == "Sales")
    df = df[df["trans_group_en"] == "Sales"].copy()

    # Parse dates
    df["trans_date"] = pd.to_datetime(df["trans_date"])

    # Aggregate by (area, property_type) per month
    df_grouped = df.groupby([
        pd.Grouper(key="trans_date", freq="ME"),  # Month-end frequency
        "area_name_en",
        "prop_type_en"
    ]).agg({
        "actual_worth": ["count", "median", "sum"],  # volume, median price, total value
        "meter_sale_price": ["median", lambda x: x.quantile(0.25), lambda x: x.quantile(0.75)]
    }).reset_index()

    # Flatten column names
    df_grouped.columns = [
        "measurement_date", "area", "property_type",
        "volume", "median_price", "total_value",
        "price_per_sqft_median", "price_per_sqft_p25", "price_per_sqft_p75"
    ]

    # Add YoY/MoM change (simplified - full implementation would compute deltas)
    df_grouped["yoy_change"] = None  # To be computed with historical data
    df_grouped["mom_change"] = None  # To be computed with historical data

    # Add metadata
    df_grouped["source"] = "dld-sales"
    df_grouped["available_date"] = collected_at

    # Convert to records
    records = df_grouped.to_dict('records')

    # Format dates as ISO8601
    for record in records:
        record["measurement_date"] = record["measurement_date"].isoformat()

    return records

def main():
    """Entry point: read stdin, normalize, write stdout."""
    try:
        # Read input: {filePath, source, collectedAt}
        input_data = json.load(sys.stdin)

        # Normalize
        result = normalize_dld_sales(
            input_data["filePath"],
            input_data["collectedAt"]
        )

        # Write output
        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except pa.errors.SchemaError as e:
        # Schema validation failure (NORM-04 hard error)
        print(f"SCHEMA_ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### Pattern 5: Normalization Orchestrator with Auto-Trigger

**What:** TypeScript orchestrator that runs normalization automatically after collection completes, handles upsert to normalized_monthly table.

**When to use:** After every successful collection run.

**Example:**
```typescript
// Source: Existing runPython bridge + normalization requirements
import { runPython } from "../analytics/bridge.js";
import type Database from "better-sqlite3";
import type { CollectionResult } from "../collectors/types.js";

interface NormalizedRecord {
  source: string;
  measurement_date: string;
  metric_name: string;
  value: number;
  available_date: string;
}

export async function normalizeCollectionResult(
  db: Database.Database,
  source: string,
  result: CollectionResult
): Promise<void> {
  if (!result.success || !result.filePath) {
    throw new Error("Cannot normalize failed collection");
  }

  // Map source to normalization module
  const moduleMap: Record<string, string> = {
    "dld-sales": "normalize_dld",
    "ejari-rentals": "normalize_ejari",
    "building-permits": "normalize_permits",
    "adrec-abu-dhabi": "normalize_adrec",
    "bayut-listings": "normalize_bayut",
    "propertyfinder": "normalize_propertyfinder",
    "dewa-connections": "normalize_dewa",
  };

  const moduleName = moduleMap[source];
  if (!moduleName) {
    throw new Error(`No normalization module for source: ${source}`);
  }

  // Call Python normalization module via bridge
  const pythonResult = await runPython<NormalizedRecord[]>(
    moduleName,
    {
      filePath: result.filePath,
      source,
      collectedAt: new Date().toISOString(),
    }
  );

  if (!pythonResult.success) {
    throw new Error(`Normalization failed: ${pythonResult.error}`);
  }

  const records = pythonResult.data;

  // Upsert to normalized_monthly (DELETE + INSERT for idempotency)
  db.transaction(() => {
    // Delete existing records for this source + date range
    const dates = records.map(r => r.measurement_date);
    const minDate = Math.min(...dates.map(d => new Date(d).getTime()));
    const maxDate = Math.max(...dates.map(d => new Date(d).getTime()));

    db.prepare(`
      DELETE FROM normalized_monthly
      WHERE source = ? AND measurement_date BETWEEN ? AND ?
    `).run(source, new Date(minDate).toISOString(), new Date(maxDate).toISOString());

    // Insert normalized records
    const insert = db.prepare(`
      INSERT INTO normalized_monthly
        (source, measurement_date, metric_name, value, available_date)
      VALUES (?, ?, ?, ?, ?)
    `);

    for (const record of records) {
      insert.run(
        record.source,
        record.measurement_date,
        record.metric_name,
        record.value,
        record.available_date
      );
    }
  })();
}
```

### Anti-Patterns to Avoid

- **Hard-coding area lists in TypeScript:** Area names should live in SQLite area_names table for easy updates. TypeScript collectors query the table, don't embed static lists.
- **Normalization in TypeScript collectors:** Keep collectors focused on data acquisition. All transformation logic belongs in Python normalization modules for pandas/pandera ecosystem.
- **Storing normalized data in raw files:** Raw files are immutable snapshots. Normalized data ONLY lives in normalized_monthly SQLite table for queryability.
- **Ignoring schema validation failures:** NORM-04 requires hard error. Never skip validation or write partial data on schema mismatch.
- **Forward-filling beyond 1 period:** NORM-01 specifies limit=1. Filling larger gaps propagates stale data and violates look-ahead bias prevention.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Browser automation | Custom headless browser wrapper | Playwright | File downloads, click events, wait strategies, anti-bot handling are all built-in. Custom solutions miss edge cases (dialogs, redirects, authentication). |
| DataFrame schema validation | Manual column/type checking with if statements | pandera | Schema validation has complex edge cases: nullable columns, value ranges, cross-column constraints, lazy vs eager validation. pandera handles all of this. |
| Time-series resampling | Manual date bucketing and averaging | pandas resample() | Month-end alignment, leap years, timezone handling, aggregation functions are all built-in. Manual bucketing will have date math bugs. |
| Area name fuzzy matching | Custom Levenshtein distance | SQLite LIKE + manual aliases table | Phase 7 only needs exact matching with known aliases. Fuzzy matching (QUAL-04) deferred to Phase 12. Don't over-engineer now. |
| Circuit breaker / retry | Custom exponential backoff | Existing @lobsec/shared CircuitBreaker + retryWithBackoff | Already integrated into SourceCollector base class. Don't rebuild. |

**Key insight:** Data collection has many subtle failure modes — network timeouts, rate limits, schema drift, encoding issues, timezone bugs. Use battle-tested libraries that have seen production at scale. Custom solutions will miss edge cases that only appear after months of operation.

## Common Pitfalls

### Pitfall 1: Playwright Download Path Race Condition

**What goes wrong:** Calling `download.path()` before download completes returns undefined or throws error.

**Why it happens:** `download.path()` is async and waits for download to finish, but if called in wrong context (e.g., after browser close), it fails.

**How to avoid:** Always call `download.saveAs(path)` immediately after receiving download event. Don't rely on `download.path()` — explicitly control the save location.

**Warning signs:** Intermittent "download failed" errors, empty files in raw directories.

**Source:** [Playwright Downloads API](https://playwright.dev/docs/downloads)

### Pitfall 2: Dubai Pulse API vs Direct CSV Confusion

**What goes wrong:** Wasting time trying to register for API key when direct CSV download works without authentication.

**Why it happens:** Dubai Pulse documentation mentions API access with key/secret, but open datasets are also available via direct HTTP GET.

**How to avoid:** Check if dataset URL has "-open" suffix (e.g., dld_transactions-open). These are publicly accessible via direct download. Only use API for authenticated/private datasets.

**Warning signs:** Spending time on API registration flow for datasets that don't require it.

**Source:** [Dubai Pulse Open Data](https://www.dubaipulse.gov.ae/data/category)

### Pitfall 3: pandas Resample Frequency Code Changes

**What goes wrong:** Using 'M' for month-end frequency throws deprecation warning or error in newer pandas versions.

**Why it happens:** pandas changed frequency codes. 'M' is deprecated, 'ME' (month-end) is the new standard.

**How to avoid:** Always use `resample('ME')` for month-end resampling. Avoid deprecated 'M' code.

**Warning signs:** DeprecationWarning in Python output, unexpected resampling behavior.

**Source:** [pandas DataFrame.resample](https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.resample.html)

### Pitfall 4: Schema Validation on Empty DataFrames

**What goes wrong:** pandera schema validation fails on empty DataFrames even though schema is correct.

**Why it happens:** Some pandera checks (like statistical checks) can't run on empty data.

**How to avoid:** Check `len(df) == 0` before validation. For empty DataFrames, skip normalization and return early with rowCount=0 (which triggers SourceCollector's empty collection error per existing architecture decision).

**Warning signs:** Schema validation errors that only appear when no data is collected, not when data exists.

**Source:** [pandera DataFrame Schemas](https://pandera.readthedocs.io/en/stable/dataframe_schemas.html)

### Pitfall 5: Forward Fill on Non-Datetime Index

**What goes wrong:** `ffill(limit=1)` doesn't work as expected, fills all NaNs or none.

**Why it happens:** Forward fill requires sorted datetime index. If index is not datetime or not sorted, ffill behavior is undefined.

**How to avoid:** Always `df.set_index('date')` after parsing dates with `pd.to_datetime()`, and ensure index is sorted before resampling.

**Warning signs:** NaN values remaining in normalized data, or all gaps filled despite limit=1.

**Source:** [pandas Resampler.fillna](https://pandas.pydata.org/docs/reference/api/pandas.core.resample.Resampler.fillna.html)

### Pitfall 6: Bayut/PropertyFinder Bot Detection

**What goes wrong:** Scraper gets blocked after a few requests, returns empty pages or CAPTCHAs.

**Why it happens:** Property portals have sophisticated anti-bot detection in 2026 including AI-driven behavioral analysis.

**How to avoid:**
- Use realistic user agent strings
- Add random delays between requests (1-3 seconds)
- Rotate through different viewport sizes
- Don't scrape during peak hours (9am-5pm GST)
- Limit to one full scrape per week (COLL-05 frequency)
- Consider adding residential proxy support if blocking persists (deferred to Phase 8+ if needed)

**Warning signs:** HTTP 403 errors, CAPTCHA pages, empty listing arrays.

**Source:** [Scale UAE Real Estate Leads: 2026 Anti-Bot bypass](https://www.actowizsolutions.com/real-estate-lead-extraction-propertyfinder-bayut.php)

### Pitfall 7: Area Name Encoding Issues

**What goes wrong:** Area names with Arabic characters, apostrophes, or special characters cause SQLite insert failures or data corruption.

**Why it happens:** Mixed UTF-8 encoding from different sources, improper escaping.

**How to avoid:**
- Always decode CSV content with explicit `encoding='utf-8'` in pandas
- Use parameterized SQLite queries (already enforced by better-sqlite3)
- Store canonical area names in ASCII-safe format (e.g., "Jumeirah Village Circle" not "JVC") with aliases table for abbreviations

**Warning signs:** SQLite errors on INSERT, garbled characters in area names, queries failing to match areas.

**Source:** Standard UTF-8 handling best practices

## Code Examples

Verified patterns from official sources:

### Playwright File Download with TypeScript
```typescript
// Source: https://playwright.dev/docs/downloads
const browser = await chromium.launch();
const context = await browser.newContext({ acceptDownloads: true });
const page = await context.newPage();

const downloadPromise = page.waitForEvent('download');
await page.click('button#export-csv');
const download = await downloadPromise;

// Save to specific location
await download.saveAs('/opt/lobsec/data/raw/source/file.csv');

// Get suggested filename
const filename = download.suggestedFilename();

await browser.close();
```

### pandas Monthly Resample with Forward Fill
```python
# Source: https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.resample.html
import pandas as pd

df = pd.read_csv('data.csv')
df['date'] = pd.to_datetime(df['date'])
df = df.set_index('date')

# Resample to month-end with mean aggregation
monthly = df.resample('ME').mean()

# Forward-fill missing values (limit to 1 period)
monthly = monthly.ffill(limit=1)

# Convert back to records for JSON output
records = monthly.reset_index().to_dict('records')
```

### pandera Schema Validation
```python
# Source: https://pandera.readthedocs.io/en/stable/dataframe_schemas.html
import pandera as pa
from pandera import Column, DataFrameSchema

schema = DataFrameSchema({
    "price": Column(float, pa.Check.ge(0), nullable=False),
    "area": Column(str, nullable=False),
    "date": Column(str, nullable=False),  # ISO8601 string
})

# Validate DataFrame (lazy=False for hard error on first failure)
try:
    schema.validate(df, lazy=False)
except pa.errors.SchemaError as e:
    print(f"Validation failed: {e}")
    sys.exit(1)
```

### Dubai Pulse Direct CSV Download
```typescript
// Source: https://www.dubaipulse.gov.ae/data/dld-transactions/dld_transactions-open
const url = "https://www.dubaipulse.gov.ae/data/dld-transactions/dld_transactions-open";
const response = await fetch(url);

if (!response.ok) {
  throw new Error(`HTTP ${response.status}`);
}

const csvText = await response.text();
const rowCount = csvText.split('\n').length - 1; // Subtract header

await fs.writeFile('/opt/lobsec/data/raw/dld-sales/2026-03-11.csv', csvText, 'utf-8');
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Apify cloud scrapers | Direct Playwright scraping | 2026 | User decision to avoid external dependency. Self-hosted gives full control over scraping logic, no usage costs, but requires maintaining scraper code and handling anti-bot directly. |
| pandas 'M' frequency | pandas 'ME' frequency | pandas 2.x | Month-end frequency code changed. 'M' deprecated, 'ME' is standard. Code using 'M' will throw warnings. |
| Manual schema validation | pandera declarative schemas | ~2020 onward | pandera became standard for pandas schema validation. Declarative schemas are easier to maintain than imperative if/else validation logic. |
| Puppeteer for browser automation | Playwright | ~2020 onward | Playwright supports multiple browsers (Chromium, Firefox, WebKit) with unified API. Better download handling, better async patterns, better TypeScript support. |

**Deprecated/outdated:**
- **Bayut unofficial API (docs.bayutapi.com):** 2026 sources report anti-bot protection makes API unreliable. Direct Playwright scraping is current approach despite being more fragile.
- **UAE Pass for DARI:** User replaced DARI via UAE Pass with ADREC public dashboards. UAE Pass authentication flow is no longer needed for Abu Dhabi data.

## Open Questions

1. **DEWA area-level granularity availability**
   - What we know: DEWA publishes press releases with connection/disconnection counts
   - What's unclear: Whether press releases include per-area breakdown or only emirate-level aggregates
   - Recommendation: Implement DEWA collector last (after DLD/Ejari/permits/ADREC). If area-level data not available, document limitation and revisit granularity requirement with user. Possible fallback: collect emirate-level only for Phase 7, add area-level if/when DEWA publishes it.

2. **Bayut/PropertyFinder scraping volume limits**
   - What we know: Anti-bot detection exists, weekly scraping frequency is acceptable
   - What's unclear: How many areas can be scraped in one session before triggering blocks
   - Recommendation: Start with top 20 Dubai areas for MVP. Monitor collection_log for failure patterns. If blocking occurs, reduce area count or add delays. Full 100-area coverage can be phased in after validating scraping stability.

3. **ADREC CSV export button selectors**
   - What we know: Dashboard has CSV export functionality confirmed by user
   - What's unclear: Exact button selectors, filter UI structure, export confirmation flows
   - Recommendation: Manual exploration of ADREC dashboard during implementation to identify selectors. Document selectors in collector code comments. Add screenshot-on-failure for debugging if click automation fails.

4. **Area seed list compilation scope**
   - What we know: ~100 Dubai areas + ~50 Abu Dhabi districts needed
   - What's unclear: Which specific 150 areas to include, canonical name format, alias coverage
   - Recommendation: Use TimeOut Dubai, Bayut, PropertyFinder neighborhood guides as primary sources. Cross-reference with DLD transaction data area names. Prioritize high-volume investment areas (Downtown, Marina, JVC, JBR, Business Bay) for initial seed list. Add remaining areas incrementally as they appear in collected data.

5. **Volume validation "first N runs" threshold**
   - What we know: Volume validation skipped until baseline is established
   - What's unclear: Exact N value (how many successful runs needed)
   - Recommendation: N=4 successful collections per source. Rationale: Need minimum 30-day rolling window for monthly collectors, 4 runs gives sufficient variance for meaningful average without delaying validation too long.

## Sources

### Primary (HIGH confidence)

- [Playwright Downloads API](https://playwright.dev/docs/downloads) - File download handling, waitForEvent, saveAs patterns
- [Playwright Download Class API](https://playwright.dev/docs/api/class-download) - Download object methods
- [pandas DataFrame.resample](https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.resample.html) - Month-end frequency, aggregation patterns
- [pandas Resampler.fillna](https://pandas.pydata.org/docs/reference/api/pandas.core.resample.Resampler.fillna.html) - Forward-fill with limit
- [pandera DataFrame Schemas](https://pandera.readthedocs.io/en/stable/dataframe_schemas.html) - Schema validation, column checks, dtype validation
- [Dubai Pulse Open Data](https://www.dubaipulse.gov.ae/data/category) - Direct CSV download for DLD, permits
- [ADREC Dashboards](https://adrec.gov.ae/en/property_and_index/adrec-dashboard) - Abu Dhabi property data dashboards

### Secondary (MEDIUM confidence)

- [How to download files using Playwright](https://www.browserstack.com/guide/playwright-download-file) - Playwright download best practices
- [Playwright file download TypeScript patterns](https://medium.com/@samsuthen1991/how-to-download-files-using-playwright-in-typescript-df85720aa14f) - TypeScript-specific download examples
- [pandas Resample tutorial](https://www.datacamp.com/tutorial/pandas-resample-asfreq) - Time-series resampling patterns
- [pandera Data Validation guide](https://towardsdatascience.com/data-validation-with-pandera-in-python-f07b0f845040/) - pandera usage examples
- [Dubai Pulse API documentation](https://www.digitaldubai.ae/data/get-data) - API vs direct download distinction
- [Bayut API (Unofficial)](https://docs.bayutapi.com/) - Bayut data structure reference
- [Scale UAE Real Estate Leads: 2026 Anti-Bot bypass](https://www.actowizsolutions.com/real-estate-lead-extraction-propertyfinder-bayut.php) - Current state of portal anti-bot measures

### Tertiary (LOW confidence)

- [Dubai neighborhoods guide](https://www.timeoutdubai.com/moving-to-dubai/dubai-neighbourhoods-guide) - Area name reference for seed list compilation
- [Best areas to invest in Dubai 2026](https://www.bhomes.com/en/blog/definitive-guides/best-areas-to-invest-in-dubai) - Top Dubai areas for prioritization
- [Apify Dubai Real Estate Scraper](https://apify.com/redoubtable_bubble/dubai-real-estate-scraper-propertyfinder-bayut-dubizzle/api) - Alternative scraping approach (not used, but documents data structure)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Playwright and pandas are industry-standard, already in project. pandera is well-documented and widely used.
- Architecture: HIGH - Two-step pipeline pattern is proven for ETL workflows. SourceCollector framework already exists and tested in Phase 6.
- Pitfalls: MEDIUM-HIGH - Common pitfalls verified via official docs (download race condition, frequency codes). Anti-bot pitfall based on 2026 industry reports but specific portal behavior may vary.

**Research date:** 2026-03-11
**Valid until:** 2026-04-11 (30 days) — Stable domain (web scraping, pandas) with slow-moving best practices. Portal anti-bot measures may evolve faster; revalidate Bayut/PropertyFinder patterns if scraping failures persist.
