# Phase 6: Foundation & Infrastructure - Research

**Researched:** 2026-03-11
**Domain:** SQLite database, Python analytics environment, TypeScript-Python bridge, collector framework
**Confidence:** HIGH

## Summary

Phase 6 establishes the foundational infrastructure for the UAE Real Estate Intelligence System: a SQLite database with WAL mode for time-series storage, a Python 3.13 analytics environment with pandas/statsmodels/scipy, a TypeScript-to-Python subprocess bridge for JSON I/O, and a collector framework with scheduling and concurrency control. This phase builds plumbing only — no actual data sources are collected yet (that's Phase 7+).

The technical stack is well-established with mature libraries. SQLite with better-sqlite3 provides embedded database capabilities with WAL mode for read/write concurrency. Python 3.13 is already available on the server with statsmodels 0.15+ providing Granger causality, ADF/KPSS stationarity tests, and time-series analysis. The TypeScript-Python bridge follows the proven stdin/stdout JSON pattern. The collector framework will use systemd timers (preferred over cron in 2026) with a single orchestrator service to avoid SQLite write contention.

**Primary recommendation:** Use better-sqlite3 with explicit transactions and prepared statements for bulk inserts, systemd timers with Persistent=true for scheduling, and a priority queue with concurrency limiting (max 3) for the collector orchestrator. Follow existing lobsec patterns: reuse CircuitBreaker and retryWithBackoff from @lobsec/shared, extend FscryptManager for /opt/lobsec/data/ encryption, and model the OpenClaw plugin on packages/tools/src/openclaw-adapter.ts.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Package Layout:**
- New `@lobsec/uae-re` monorepo package at `packages/uae-re/` — separate from existing `@lobsec/tools`
- Two separate OpenClaw plugins: `lobsec-tools` stays as-is, `lobsec-uae-re` registers independently
- Collector framework (SourceCollector base, registry, scheduling) lives inside `@lobsec/uae-re`
- Python subprocess bridge (`runPython()`) lives inside `@lobsec/uae-re`
- Internal structure: subdirectories by concern — `src/collectors/`, `src/analytics/`, `src/tools/`, `src/db/`
- Deployed plugin at `/opt/lobsec/plugins/lobsec-uae-re/` includes Python scripts alongside compiled JS in a `python/` subdirectory
- Standard tsconfig extending `tsconfig.base.json`

**Data File Organization:**
- Raw collected data (CSVs, PDFs, JSON) stored as files on disk at `/opt/lobsec/data/raw/` alongside the SQLite database
- Raw files organized by source name: `raw/dld-sales/2026-W11.csv`, `raw/bayut-listings/2026-03.json`
- Simple create-if-not-exists for SQLite schema — no formal migration system
- Raw file retention: unlimited — keep everything
- fscrypt covers encryption at rest

**Python Code Structure:**
- Modular Python package: `packages/uae-re/python/uae_re/` with `__init__.py`, `normalize.py`, `stationarity.py`, `granger.py`, etc.
- Dependencies pinned in `requirements.txt` with exact versions (e.g., `pandas==2.2.3`) in `packages/uae-re/python/`
- Both pytest (Python unit tests for analytics logic) and Vitest (TypeScript bridge/integration tests)
- Deploy script creates/updates venv automatically

**Collector Error Behavior:**
- Retry 3x with backoff on failure, then log to audit + send Telegram alert
- Source marked STALE
- Other collectors continue unaffected
- Fully independent collectors — one failure doesn't block the other 27
- Concurrency limiter (max 3) only governs simultaneous execution
- Summary logging per run: one audit entry per collector run with source name, status (ok/fail), row count, duration
- Escalating severity: first failure cycle = WARN via Telegram. If still failing after next scheduled run = CRITICAL alert

### Claude's Discretion

- Exact SQLite table schemas (column names, types, indices)
- CollectorRegistry internal scheduling implementation
- Python subprocess bridge error serialization format
- Intelligence cache TTL tuning and eviction strategy
- Deploy script structure and systemd unit file details
- better-sqlite3 vs other SQLite Node.js bindings (better-sqlite3 is the project decision)

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| INFRA-01 | SQLite database (`uae-re.db`) with WAL mode, indexed on `(source, measurement_date)`, stored under fscrypt-encrypted `/opt/lobsec/data/` | better-sqlite3 with WAL pragma, FscryptManager pattern from @lobsec/shared |
| INFRA-02 | Python 3.13 venv at `/opt/lobsec/analytics-venv/` with pandas, statsmodels, scipy, numpy, pdfplumber, vaderSentiment, praw, pytrends | Python 3.13.3 already on server, pinned requirements.txt, venv creation in deploy script |
| INFRA-03 | Collector base class (`SourceCollector`) with abstract `collect()` method, schema validation, and error propagation | Abstract base class pattern, schema validation via JSON Schema or dataclasses |
| INFRA-04 | Collector Registry with frequency-based scheduling, dependency resolution, and controlled concurrency (max 3 concurrent) | Priority queue pattern, typed-scheduler or Bottleneck for concurrency control, systemd timer triggers |
| INFRA-05 | Python subprocess bridge (`runPython()`) with JSON I/O via stdin/stdout, timeout enforcement, and error handling | subprocess.Popen with text mode, JSON serialization, timeout via AbortSignal |
| INFRA-06 | Intelligence cache layer with TTL-based expiry (1hr default), params hash as key, stored in SQLite `intelligence_cache` table | SQLite table with timestamp + TTL check, MD5/SHA-256 hash of params JSON |
| INFRA-07 | `@lobsec/uae-re` package structure deployed as OpenClaw plugin at `/opt/lobsec/plugins/lobsec-uae-re/` | Monorepo package pattern from packages/tools, openclaw-adapter.ts registration model |
| SEC-01 | HSM credential storage — all new API keys in SoftHSM2 | Existing HSM pattern: pkcs11-tool --write-object, chown lobsec:lobsec |
| SEC-02 | fscrypt encryption on `/opt/lobsec/data/` (5th encrypted directory) | FscryptManager from @lobsec/shared, new encryption policy AES-256-XTS |
| SCHED-01 | Single collector orchestrator service (`lobsec-uae-collector.service`) with controlled concurrency and priority queue | systemd service + timer units, priority queue in TypeScript, max 3 concurrent via semaphore |

</phase_requirements>

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| better-sqlite3 | 11.8.0+ | Embedded SQLite with synchronous API | Fastest SQLite binding for Node.js, synchronous API simpler than async wrappers, WAL mode support |
| @types/better-sqlite3 | 7.6.11+ | TypeScript definitions | TypeScript support for better-sqlite3 |
| Python 3.13 | 3.13.3 | Data science runtime | Already on server, latest stable, native venv support |
| pandas | 2.2.3 | Time-series normalization, resampling | De facto standard for time-series data in Python, .resample() with forward fill |
| statsmodels | 0.15.0+ | Granger causality, ADF/KPSS stationarity tests | Standard library for econometric analysis, grangercausalitytests(), adfuller(), kpss() |
| scipy | 1.15.0+ | Cross-correlation, statistical functions | Foundational scientific computing, scipy.stats.pearsonr for lag detection |
| numpy | 2.2.1+ | Numerical operations | Required dependency for pandas/statsmodels/scipy |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pdfplumber | 0.11.4+ | PDF text extraction | Quarterly reports (GDRFA, CBUAE, JLL/CBRE commercial) — Phase 8+ |
| vaderSentiment | 3.3.2+ | Social media sentiment scoring | Reddit r/dubai, r/dubairealestate — Phase 9 |
| praw | 7.8.1+ | Reddit API client | Reddit scraping — Phase 9 |
| pytrends | 4.9.2+ | Google Trends API | Keyword tracking (buy/rent/expat/distress) — Phase 9 |
| pytest | 8.3.0+ | Python unit testing | Analytics module tests (stationarity, Granger, normalization) |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| better-sqlite3 | node-sqlite3 (async) | Async API more complex, slower performance, same WAL support |
| better-sqlite3 | Knex.js query builder | Adds abstraction layer, overkill for simple time-series inserts |
| systemd timers | cron | Cron lacks Persistent=true (run on next boot if missed), worse logging, no service unit separation |
| systemd timers | node-cron / Agenda / BullMQ | In-process schedulers restart with service, systemd timer survives service restarts |
| stdin/stdout bridge | REST API (Flask/FastAPI) | REST API requires separate Python process, port management, auth — overkill for local subprocess |
| subprocess JSON I/O | zeromq / nanomsg | IPC libraries add complexity, JSON over stdio is simpler and sufficient for local calls |

**Installation:**

```bash
# TypeScript packages (monorepo root)
pnpm add -w better-sqlite3 @types/better-sqlite3

# Python dependencies (packages/uae-re/python/requirements.txt)
pandas==2.2.3
statsmodels==0.15.0
scipy==1.15.0
numpy==2.2.1
pdfplumber==0.11.4
vaderSentiment==3.3.2
praw==7.8.1
pytrends==4.9.2
pytest==8.3.0

# Create venv (deploy script)
python3 -m venv /opt/lobsec/analytics-venv
/opt/lobsec/analytics-venv/bin/pip install -r packages/uae-re/python/requirements.txt
```

## Architecture Patterns

### Recommended Project Structure

```
packages/uae-re/
├── src/
│   ├── db/                  # SQLite schema, migrations, queries
│   │   ├── schema.ts        # CREATE TABLE statements
│   │   ├── connection.ts    # Database connection with WAL mode
│   │   └── queries.ts       # Prepared statements for inserts/selects
│   ├── collectors/          # Data collection framework
│   │   ├── base.ts          # SourceCollector abstract base class
│   │   ├── registry.ts      # CollectorRegistry with scheduling
│   │   └── types.ts         # Collector interfaces
│   ├── analytics/           # Python bridge
│   │   ├── bridge.ts        # runPython() subprocess bridge
│   │   └── types.ts         # Analytics function types
│   ├── tools/               # OpenClaw plugin tools
│   │   ├── area-signal.ts   # uae_area_signal tool
│   │   └── collection.ts    # uae_collection_status tool
│   ├── cache/               # Intelligence cache
│   │   ├── manager.ts       # Cache read/write with TTL
│   │   └── types.ts         # Cache entry types
│   └── index.ts             # Plugin entry point (register())
├── python/                  # Python analytics modules
│   └── uae_re/
│       ├── __init__.py
│       ├── normalize.py     # Monthly resampling, forward fill
│       ├── stationarity.py  # ADF, KPSS tests
│       ├── granger.py       # Granger causality
│       └── correlation.py   # Cross-correlation lag detection
├── tests/                   # Vitest TypeScript tests
│   ├── db.test.ts
│   ├── bridge.test.ts
│   └── collectors.test.ts
├── python/tests/            # pytest Python tests
│   ├── test_normalize.py
│   ├── test_stationarity.py
│   └── test_granger.py
├── package.json
├── tsconfig.json
└── python/requirements.txt
```

### Pattern 1: SQLite WAL Mode + Prepared Statements

**What:** Enable WAL mode immediately after opening the connection, use prepared statements for all queries, wrap bulk inserts in explicit transactions.

**When to use:** All SQLite operations in this project.

**Example:**
```typescript
// Source: better-sqlite3 docs + web search findings
import Database from 'better-sqlite3';

const db = new Database('/opt/lobsec/data/uae-re.db');
db.pragma('journal_mode = WAL'); // Enable WAL mode immediately

// Prepared statement for inserts
const insertStmt = db.prepare(`
  INSERT INTO normalized_monthly (source, measurement_date, metric_name, value, available_date)
  VALUES (?, ?, ?, ?, ?)
`);

// Bulk insert in single transaction
function bulkInsert(rows: Array<{source: string, date: string, metric: string, value: number, availDate: string}>) {
  const insertMany = db.transaction((rows) => {
    for (const row of rows) {
      insertStmt.run(row.source, row.date, row.metric, row.value, row.availDate);
    }
  });

  insertMany(rows); // Executes all inserts in single transaction
}
```

**Key insights:**
- WAL mode: readers don't block writers, writers don't block readers
- Prepared statements: compile SQL once, execute many times (eliminates parse overhead)
- Transactions: 23,000+ inserts/sec vs. <100 without transaction wrapping
- Always use parameterized queries (?) to prevent SQL injection

### Pattern 2: Python Subprocess Bridge with JSON I/O

**What:** Spawn Python subprocess with stdin/stdout in text mode, send JSON input via stdin, read JSON output from stdout, enforce timeout via AbortSignal.

**When to use:** All calls to Python analytics functions (normalize, stationarity, Granger).

**Example:**
```typescript
// Source: Web search findings + Node.js subprocess docs pattern
import { spawn } from 'node:child_process';

interface PythonResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

async function runPython<T>(
  script: string,
  input: unknown,
  timeoutMs: number = 30000,
): Promise<PythonResult<T>> {
  return new Promise((resolve, reject) => {
    const proc = spawn('/opt/lobsec/analytics-venv/bin/python3', ['-c', script], {
      stdio: ['pipe', 'pipe', 'pipe'], // stdin, stdout, stderr
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (chunk) => { stdout += chunk; });
    proc.stderr.on('data', (chunk) => { stderr += chunk; });

    const timeout = setTimeout(() => {
      proc.kill('SIGTERM');
      reject(new Error(`Python subprocess timeout after ${timeoutMs}ms`));
    }, timeoutMs);

    proc.on('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        resolve({ success: false, error: stderr || `Exit code ${code}` });
      } else {
        try {
          const data = JSON.parse(stdout);
          resolve({ success: true, data });
        } catch (err) {
          resolve({ success: false, error: `JSON parse error: ${(err as Error).message}` });
        }
      }
    });

    // Send input as JSON via stdin
    proc.stdin.write(JSON.stringify(input));
    proc.stdin.end();
  });
}
```

**Python side pattern:**
```python
# In packages/uae-re/python/uae_re/normalize.py
import sys
import json
import pandas as pd

def main():
    # Read JSON input from stdin
    input_data = json.load(sys.stdin)

    # Process (example: resample to monthly)
    df = pd.DataFrame(input_data['rows'])
    df['date'] = pd.to_datetime(df['date'])
    df.set_index('date', inplace=True)
    monthly = df.resample('ME').mean().fillna(method='ffill', limit=1)

    # Write JSON output to stdout
    result = {
        'rows': monthly.reset_index().to_dict('records'),
        'rowCount': len(monthly),
    }
    print(json.dumps(result))
    sys.stdout.flush()

if __name__ == '__main__':
    main()
```

**Key insights:**
- All log/debug output MUST go to stderr (sys.stderr), never stdout
- Always call sys.stdout.flush() after print to ensure immediate delivery
- JSON over stdio is simple, synchronous, and sufficient for local subprocess calls
- Timeout enforcement prevents hanging on malformed Python code

### Pattern 3: Collector Abstract Base Class + Registry

**What:** Abstract SourceCollector base class with collect() method, schema validation, error propagation. CollectorRegistry maintains frequency metadata and concurrency control.

**When to use:** All data source collectors (28 total across Phases 7-9).

**Example:**
```typescript
// Source: Existing lobsec resilience patterns + web search scheduler findings
import { retryWithBackoff, CircuitBreaker } from '@lobsec/shared';

interface CollectorMetadata {
  source: string;
  frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly';
  priority: number; // 1 = highest
  timeout: number; // milliseconds
}

interface CollectionResult {
  success: boolean;
  rowCount?: number;
  error?: string;
  duration: number;
}

abstract class SourceCollector {
  protected metadata: CollectorMetadata;
  protected circuitBreaker: CircuitBreaker;

  constructor(metadata: CollectorMetadata) {
    this.metadata = metadata;
    this.circuitBreaker = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 30000, halfOpenSuccesses: 1 });
  }

  abstract collect(): Promise<CollectionResult>;

  async run(): Promise<CollectionResult> {
    const start = Date.now();

    const result = await retryWithBackoff(
      () => this.circuitBreaker.execute(() => this.collect()),
      { maxRetries: 3, baseDelayMs: 1000, maxDelayMs: 10000, jitterFactor: 0.2 }
    );

    const duration = Date.now() - start;

    if (result.success && result.value) {
      return { ...result.value, duration };
    } else {
      return { success: false, error: result.lastError, duration };
    }
  }
}

class CollectorRegistry {
  private collectors = new Map<string, SourceCollector>();
  private activeTasks = 0;
  private readonly maxConcurrency = 3;
  private queue: Array<{ collector: SourceCollector; priority: number }> = [];

  register(collector: SourceCollector) {
    this.collectors.set(collector.metadata.source, collector);
  }

  async runAll(): Promise<Map<string, CollectionResult>> {
    const results = new Map<string, CollectionResult>();

    // Sort by priority (1 = highest)
    const sorted = Array.from(this.collectors.values()).sort(
      (a, b) => a.metadata.priority - b.metadata.priority
    );

    for (const collector of sorted) {
      while (this.activeTasks >= this.maxConcurrency) {
        await new Promise((resolve) => setTimeout(resolve, 100)); // Poll
      }

      this.activeTasks++;
      collector.run().then((result) => {
        results.set(collector.metadata.source, result);
        this.activeTasks--;
      });
    }

    // Wait for all to complete
    while (this.activeTasks > 0) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    return results;
  }
}
```

**Key insights:**
- Reuse CircuitBreaker and retryWithBackoff from @lobsec/shared
- Priority queue ensures high-priority sources (DLD, DARI) run first
- Max concurrency of 3 avoids overwhelming SQLite writes or API rate limits
- Each collector is independent — one failure doesn't block others

### Pattern 4: systemd Timer + Service Units

**What:** Separate .timer unit triggers .service unit, Persistent=true ensures missed runs execute on next boot, service unit sources .env for credentials.

**When to use:** All scheduled collection runs (weekly, monthly, quarterly, daily).

**Example:**
```ini
# /etc/systemd/system/lobsec-uae-collector.service
[Unit]
Description=UAE RE Data Collector Orchestrator
After=network-online.target lobsec.service
Requires=network-online.target

[Service]
Type=oneshot
User=lobsec
Group=lobsec
WorkingDirectory=/opt/lobsec
EnvironmentFile=/opt/lobsec/.env
ExecStart=/usr/bin/node /opt/lobsec/plugins/lobsec-uae-re/dist/cli.js run-all
TimeoutStartSec=900
StandardOutput=journal
StandardError=journal
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ReadWritePaths=/opt/lobsec/data /opt/lobsec/logs

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/lobsec-uae-collector.timer
[Unit]
Description=UAE RE Weekly Collection Timer
Requires=lobsec-uae-collector.service

[Timer]
OnCalendar=Mon *-*-* 06:00:00
Persistent=true
Unit=lobsec-uae-collector.service

[Install]
WantedBy=timers.target
```

**Key insights:**
- Persistent=true: if system was off at 06:00 Monday, timer fires on next boot
- Separate timer and service units: can manually run service without waiting for schedule
- EnvironmentFile sources .env for HSM-extracted credentials
- TimeoutStartSec=900 (15 min) for long-running collections
- ReadWritePaths restricts writes to /opt/lobsec/data and /opt/lobsec/logs only

### Anti-Patterns to Avoid

- **Multiple timers for each collector:** Creates SQLite write contention. Use single orchestrator service with internal priority queue.
- **Async better-sqlite3 wrapper:** Adds complexity with no benefit. better-sqlite3's synchronous API is faster and simpler.
- **In-process schedulers (node-cron, Agenda):** Restart with service, can't survive crashes. systemd timers are external and persistent.
- **Subprocess communication via REST API:** Requires separate Python process, port, auth. stdin/stdout JSON is simpler for local calls.
- **Forward fill with no limit:** Propagates stale data indefinitely. Always use limit=1 to fill only one missing period.
- **Running Granger test on non-stationary data:** Produces spurious correlations. Always check ADF/KPSS first.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Concurrency limiting | Custom semaphore with Promise queue | Priority queue pattern with activeTasks counter (shown above) or typed-scheduler library | Edge cases: cancellation, timeout, priority changes. Simple counter + poll loop is sufficient for max 3 concurrency. |
| Time-series resampling | Manual date aggregation logic | pandas.resample('ME').mean().fillna(method='ffill', limit=1) | Handles irregular data, missing periods, timezone-aware dates, multiple aggregation functions. |
| Granger causality test | Manual VAR estimation + F-test | statsmodels.tsa.stattools.grangercausalitytests() | Implements proper lag selection, Bonferroni correction, handles edge cases (singular matrices, insufficient data). |
| Stationarity testing | Manual unit root calculation | statsmodels.tsa.stattools.adfuller() and kpss() | ADF and KPSS have different null hypotheses (non-stationary vs stationary), using both catches edge cases. |
| SQLite query builder | String concatenation or template literals | Prepared statements with ? placeholders | Prevents SQL injection, pre-compiles queries for performance, handles type coercion. |
| Process timeout | setTimeout + manual kill | AbortSignal + setTimeout (Node 22+) or promise race pattern | AbortSignal properly propagates cancellation, avoids orphaned processes. |

**Key insight:** Time-series analysis has subtle edge cases (look-ahead bias, seasonal adjustment, autocorrelation). Using statsmodels ensures you don't miss statistical requirements that would invalidate Granger test results.

## Common Pitfalls

### Pitfall 1: SQLite Write Contention from Multiple Timers

**What goes wrong:** Creating separate systemd timers for each collector (28 timers) results in simultaneous writes to SQLite, causing SQLITE_BUSY errors and failed collections.

**Why it happens:** SQLite WAL mode supports concurrent reads but only ONE writer at a time. Multiple processes attempting to write simultaneously will block and eventually timeout.

**How to avoid:** Single orchestrator service with internal priority queue and max 3 concurrent collectors. Collectors write to SQLite sequentially within the orchestrator process.

**Warning signs:** SQLITE_BUSY errors in logs, collection failures during scheduled runs, database locked timeouts.

### Pitfall 2: Forward Fill Propagating Stale Data

**What goes wrong:** Using pandas forward fill without limit propagates the last known value indefinitely, masking data source failures and creating misleading trends.

**Why it happens:** `fillna(method='ffill')` with no limit will carry forward the last value forever. If a source stops updating, you won't know — the data will look current.

**How to avoid:** Always use `fillna(method='ffill', limit=1)` to fill only one missing period. Track last successful collection per source and flag STALE when gap exceeds 2x expected frequency.

**Warning signs:** Flat lines in time-series charts during periods when source should be updating, no staleness alerts despite source failures.

### Pitfall 3: Look-Ahead Bias from available_date vs measurement_date

**What goes wrong:** Using data based on measurement_date without checking available_date creates look-ahead bias — your model uses information it wouldn't have had in real-time.

**Why it happens:** Data is often published weeks/months after the measurement period (e.g., GDRFA quarterly visa reports published 6 weeks after quarter end). Using measurement_date only gives the model future knowledge.

**How to avoid:** Store both measurement_date and available_date for every data point. When computing intelligence products, filter by available_date <= current_date to simulate real-time constraints.

**Warning signs:** Backtest performance far better than live performance, Granger test showing perfect predictions with zero lag.

### Pitfall 4: Granger Test on Non-Stationary Data

**What goes wrong:** Running Granger causality test on non-stationary time series produces spurious correlations — finding "significant" relationships that don't exist.

**Why it happens:** Granger causality assumes stationarity (constant mean, variance, autocorrelation). Non-stationary series (trends, seasonality) violate this assumption.

**How to avoid:** Always run ADF and KPSS tests before Granger. If non-stationary, apply differencing until both tests confirm stationarity. Hard gate: refuse to run Granger if either test fails.

**Warning signs:** Granger test finds everything is significant, p-values all near 0, results change drastically with small data changes.

### Pitfall 5: Python stdout Contamination

**What goes wrong:** Python script prints debug messages to stdout, breaking JSON parsing in TypeScript bridge. subprocess call fails with "Unexpected token" error.

**Why it happens:** stdout is the communication channel — any non-JSON output (print statements, library warnings, stack traces) corrupts the JSON stream.

**How to avoid:** All Python log/debug output must go to sys.stderr. Use logging.basicConfig(stream=sys.stderr) to redirect logging. Only final JSON result goes to stdout.

**Warning signs:** JSON parse errors in bridge, "Unexpected token P" (from "Processing..."), intermittent failures when Python libraries print warnings.

### Pitfall 6: Missing sys.stdout.flush() in Python

**What goes wrong:** Python script writes JSON to stdout but TypeScript never receives it. Subprocess hangs until timeout.

**Why it happens:** Python buffers stdout by default. Without explicit flush(), the JSON sits in the buffer and never reaches the pipe.

**How to avoid:** Always call sys.stdout.flush() after print() in Python subprocess scripts. Or use print(..., flush=True).

**Warning signs:** Subprocess timeouts, TypeScript receiving empty stdout, works locally but fails in production.

## Code Examples

Verified patterns from official sources and web search findings:

### SQLite Database Initialization with WAL Mode

```typescript
// Source: better-sqlite3 docs + web search best practices
import Database from 'better-sqlite3';
import { join } from 'node:path';

export function initDatabase(dataDir: string): Database.Database {
  const dbPath = join(dataDir, 'uae-re.db');
  const db = new Database(dbPath);

  // Enable WAL mode immediately (HIGH confidence)
  db.pragma('journal_mode = WAL');

  // Optimize for write-heavy workload
  db.pragma('synchronous = NORMAL'); // Safe with WAL
  db.pragma('cache_size = -64000'); // 64MB cache
  db.pragma('temp_store = MEMORY');

  // Create tables if not exist
  db.exec(`
    CREATE TABLE IF NOT EXISTS raw_sources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      file_path TEXT NOT NULL,
      collected_at TEXT NOT NULL,
      row_count INTEGER,
      file_size_bytes INTEGER,
      checksum TEXT
    );

    CREATE TABLE IF NOT EXISTS normalized_monthly (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      measurement_date TEXT NOT NULL,
      metric_name TEXT NOT NULL,
      value REAL,
      available_date TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_normalized_source_date
      ON normalized_monthly(source, measurement_date);

    CREATE TABLE IF NOT EXISTS intelligence_cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cache_key TEXT UNIQUE NOT NULL,
      product TEXT NOT NULL,
      params_hash TEXT NOT NULL,
      result_json TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_cache_key_expiry
      ON intelligence_cache(cache_key, expires_at);

    CREATE TABLE IF NOT EXISTS collection_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      status TEXT NOT NULL,
      row_count INTEGER,
      duration_ms INTEGER,
      error TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_collection_source_timestamp
      ON collection_log(source, timestamp);
  `);

  return db;
}
```

### Bulk Insert with Prepared Statement + Transaction

```typescript
// Source: Web search findings on better-sqlite3 bulk insert performance
import Database from 'better-sqlite3';

interface MonthlyDataPoint {
  source: string;
  measurementDate: string;
  metricName: string;
  value: number;
  availableDate: string;
}

export function bulkInsertNormalized(
  db: Database.Database,
  rows: MonthlyDataPoint[],
): void {
  // Prepare statement once
  const stmt = db.prepare(`
    INSERT INTO normalized_monthly (source, measurement_date, metric_name, value, available_date)
    VALUES (?, ?, ?, ?, ?)
  `);

  // Wrap in transaction (HIGH confidence: 23,000+ inserts/sec)
  const insertMany = db.transaction((rows: MonthlyDataPoint[]) => {
    for (const row of rows) {
      stmt.run(row.source, row.measurementDate, row.metricName, row.value, row.availableDate);
    }
  });

  insertMany(rows);
}
```

### Python Stationarity Check (ADF + KPSS)

```python
# Source: statsmodels docs + web search Granger causality workflow
# In packages/uae-re/python/uae_re/stationarity.py
import sys
import json
from statsmodels.tsa.stattools import adfuller, kpss

def check_stationarity(series):
    """
    Check stationarity using both ADF and KPSS tests.
    Returns dict with test results and recommendation.
    """
    # ADF test: null hypothesis = non-stationary
    adf_result = adfuller(series, autolag='AIC')
    adf_stationary = adf_result[1] < 0.05  # p-value < 0.05 = reject null = stationary

    # KPSS test: null hypothesis = stationary
    kpss_result = kpss(series, regression='c', nlags='auto')
    kpss_stationary = kpss_result[1] >= 0.05  # p-value >= 0.05 = accept null = stationary

    # Both tests must agree
    is_stationary = adf_stationary and kpss_stationary

    return {
        'adf_statistic': adf_result[0],
        'adf_pvalue': adf_result[1],
        'adf_stationary': adf_stationary,
        'kpss_statistic': kpss_result[0],
        'kpss_pvalue': kpss_result[1],
        'kpss_stationary': kpss_stationary,
        'is_stationary': is_stationary,
        'recommendation': 'Stationary' if is_stationary else 'Apply differencing',
    }

def main():
    input_data = json.load(sys.stdin)
    series = input_data['series']

    result = check_stationarity(series)

    print(json.dumps(result), flush=True)

if __name__ == '__main__':
    main()
```

### Collector Abstract Base Class

```typescript
// Source: Existing @lobsec/shared resilience patterns
import { retryWithBackoff, CircuitBreaker, DEFAULT_RETRY_CONFIG } from '@lobsec/shared';
import type Database from 'better-sqlite3';

export interface CollectorMetadata {
  source: string;
  frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly';
  priority: number;
  timeout: number;
}

export interface CollectionResult {
  success: boolean;
  rowCount?: number;
  filePath?: string;
  error?: string;
  duration: number;
}

export abstract class SourceCollector {
  protected metadata: CollectorMetadata;
  protected db: Database.Database;
  protected circuitBreaker: CircuitBreaker;

  constructor(metadata: CollectorMetadata, db: Database.Database) {
    this.metadata = metadata;
    this.db = db;
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 30000,
      halfOpenSuccesses: 1,
    });
  }

  /**
   * Collect data from source. Must be implemented by subclass.
   * Should return file path to raw data + row count.
   */
  abstract collect(): Promise<{ filePath: string; rowCount: number }>;

  /**
   * Run collection with retry + circuit breaker + audit logging.
   */
  async run(): Promise<CollectionResult> {
    const start = Date.now();

    const result = await retryWithBackoff(
      () => this.circuitBreaker.execute(() => this.collect()),
      { ...DEFAULT_RETRY_CONFIG, maxRetries: 3 },
    );

    const duration = Date.now() - start;

    // Log to collection_log table
    const logStmt = this.db.prepare(`
      INSERT INTO collection_log (source, status, row_count, duration_ms, error)
      VALUES (?, ?, ?, ?, ?)
    `);

    if (result.success && result.value) {
      logStmt.run(this.metadata.source, 'success', result.value.rowCount, duration, null);
      return { success: true, ...result.value, duration };
    } else {
      logStmt.run(this.metadata.source, 'failure', null, duration, result.lastError);
      return { success: false, error: result.lastError, duration };
    }
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| cron jobs | systemd timers with Persistent=true | ~2015+ | Missed jobs now run on next boot, better logging via journalctl |
| node-sqlite3 (async) | better-sqlite3 (sync) | 2017+ | Simpler API, 2-3x faster performance for read-heavy workloads |
| Manual forward fill loops | pandas.resample().fillna() | pandas 0.18+ (2016) | Handles irregular data, timezone-aware dates, automatic upsampling/downsampling |
| statsmodels < 0.13 | statsmodels 0.15+ | 2024 | Improved Granger test performance, better handling of singular matrices |
| Python 3.11 | Python 3.13 | October 2024 | 10-15% performance improvement, improved error messages |

**Deprecated/outdated:**
- **cron for system tasks:** systemd timers are standard on all systemd-based distros (Ubuntu, Debian, RHEL, Arch) since ~2015. cron still works but lacks Persistent=true and integrated logging.
- **async SQLite wrappers:** better-sqlite3's synchronous API is simpler and faster for most use cases. Async wrappers add complexity with no benefit for single-server deployments.
- **In-process job schedulers (Agenda, BullMQ) for system tasks:** systemd timers survive process restarts and provide better monitoring. Use in-process schedulers only for application-level jobs (user-triggered, not system-level).

## Validation Architecture

> Skipped — workflow.nyquist_validation is false in .planning/config.json

## Sources

### Primary (HIGH confidence)

- [better-sqlite3 GitHub](https://github.com/WiseLibs/better-sqlite3) - Official repository with WAL mode documentation
- [better-sqlite3 npm](https://www.npmjs.com/package/better-sqlite3) - Version info and installation
- [SQLite WAL Mode Official Docs](https://sqlite.org/wal.html) - Write-Ahead Logging architecture
- [statsmodels Time Series Analysis](https://www.statsmodels.org/dev/tsa.html) - Granger causality, ADF, KPSS
- [Python subprocess docs](https://docs.python.org/3/library/subprocess.html) - Popen stdin/stdout patterns
- [pandas resample documentation](https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.resample.html) - Monthly resampling with forward fill

### Secondary (MEDIUM confidence)

- [How to Use SQLite in Node.js Applications](https://oneuptime.com/blog/post/2026-02-02-sqlite-nodejs/view) - 2026 best practices guide
- [Systemd: The Complete Guide for 2026](https://devtoolbox.dedyn.io/blog/systemd-complete-guide) - Timer vs cron comparison
- [Use systemd timers instead of cronjobs](https://opensource.com/article/20/7/systemd-timers) - Persistent=true benefits
- [Building an Efficient Priority-Task Execution Queue with TypeScript](https://medium.com/@amankrr/building-an-efficient-priority-task-execution-queue-with-javascript-typescript-2bf756f598d4) - Priority queue pattern
- [Comparing the best Node.js schedulers](https://blog.logrocket.com/comparing-best-node-js-schedulers/) - Agenda, BullMQ, Bree comparison
- [How to Perform a Granger-Causality Test in Python](https://www.statology.org/granger-causality-test-in-python/) - Stationarity workflow
- [Granger Causality Test in Python](https://www.machinelearningplus.com/time-series/granger-causality-test-in-python/) - ADF + KPSS before Granger
- [Pandas Resample With resample() and asfreq()](https://www.datacamp.com/tutorial/pandas-resample-asfreq) - Forward fill best practices
- [Inter-process communication between Javascript and Python](https://starbeamrainbowlabs.com/blog/article.php?article=posts/549-js-python-ipc.html) - stdin/stdout JSON pattern
- [How to Improve Bulk Insert Speed in SQLite](https://www.pdq.com/blog/improving-bulk-insert-speed-in-sqlite-a-comparison-of-transactions/) - Transaction wrapping performance
- [Towards Inserting One Billion Rows in SQLite Under A Minute](https://avi.im/blag/2021/fast-sqlite-inserts/) - Prepared statement + transaction benchmarks

### Tertiary (LOW confidence)

- Web search findings on typed-scheduler, Bottleneck (not officially verified via docs)
- Medium articles on subprocess communication (not official Python/Node.js docs)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - better-sqlite3, pandas, statsmodels, scipy are all verified via official docs and current versions confirmed
- Architecture: HIGH - Patterns based on existing @lobsec/shared code, official SQLite/statsmodels docs, and verified web sources
- Pitfalls: MEDIUM-HIGH - Common issues documented in multiple web sources, some confirmed via official docs (WAL single writer), others from community experience (forward fill, look-ahead bias)

**Research date:** 2026-03-11
**Valid until:** ~2026-04-11 (30 days) — Stack is mature and stable (pandas, statsmodels, SQLite, Node.js subprocess). Python 3.14 may release in October 2026 but 3.13 will remain supported. better-sqlite3 v12 may release in 2026 but v11 API is stable.
