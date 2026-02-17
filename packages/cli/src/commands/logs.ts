import { Command } from "commander";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { AuditLogEntry, LogLevel, SecurityLayer } from "@lobsec/shared";
import { meetsLevel } from "@lobsec/shared";
import { output, outputError } from "../output.js";

export interface LogFilter {
  level?: LogLevel;
  component?: string;
  layer?: SecurityLayer;
  traceId?: string;
  since?: string;
  until?: string;
  limit?: number;
}

/** Filter and return matching audit log entries. */
export function filterEntries(
  entries: AuditLogEntry[],
  filter: LogFilter,
): AuditLogEntry[] {
  let result = entries;

  if (filter.level) {
    const minLevel = filter.level;
    result = result.filter((e) => meetsLevel(e.level, minLevel));
  }

  if (filter.component) {
    const comp = filter.component;
    result = result.filter((e) => e.component === comp);
  }

  if (filter.layer) {
    const layer = filter.layer;
    result = result.filter((e) => "layer" in e && e.layer === layer);
  }

  if (filter.traceId) {
    const traceId = filter.traceId;
    result = result.filter((e) => e.traceId === traceId);
  }

  if (filter.since) {
    const since = new Date(filter.since).toISOString();
    result = result.filter((e) => e.ts >= since);
  }

  if (filter.until) {
    const until = new Date(filter.until).toISOString();
    result = result.filter((e) => e.ts <= until);
  }

  if (filter.limit !== undefined && filter.limit > 0) {
    result = result.slice(-filter.limit);
  }

  return result;
}

export function logsCommand(): Command {
  return new Command("logs")
    .description("Query audit logs")
    .option("-d, --dir <path>", "Base directory for lobsec data", "/etc/lobsec")
    .option("--level <level>", "Minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL)")
    .option("--component <name>", "Filter by component")
    .option("--layer <layer>", "Filter by security layer (L1-L9)")
    .option("--trace-id <id>", "Filter by correlation ID")
    .option("--since <date>", "Show logs since date (ISO-8601)")
    .option("--until <date>", "Show logs until date (ISO-8601)")
    .option("-n, --limit <count>", "Show last N entries", parseInt)
    .action(async function (this: Command) {
      const opts = this.opts() as {
        dir: string;
        level?: string;
        component?: string;
        layer?: string;
        traceId?: string;
        since?: string;
        until?: string;
        limit?: number;
      };
      const baseDir = opts.dir;

      try {
        const auditLogPath = join(baseDir, "logs", "audit", "audit.log");
        let content: string;
        try {
          content = await readFile(auditLogPath, "utf8");
        } catch {
          outputError(this, "No audit log found");
          return;
        }

        // Parse NDJSON
        const entries: AuditLogEntry[] = content
          .split("\n")
          .filter((line) => line.trim())
          .map((line) => {
            try {
              return JSON.parse(line) as AuditLogEntry;
            } catch {
              return null;
            }
          })
          .filter((e): e is AuditLogEntry => e !== null);

        const filtered = filterEntries(entries, {
          level: opts.level as LogLevel | undefined,
          component: opts.component,
          layer: opts.layer as SecurityLayer | undefined,
          traceId: opts.traceId,
          since: opts.since,
          until: opts.until,
          limit: opts.limit,
        });

        const data = {
          total: entries.length,
          filtered: filtered.length,
          entries: filtered,
        };

        const humanLines = filtered.map((e) => {
          const ts = e.ts.slice(11, 23);
          const lvl = e.level.padEnd(8);
          const layer = "layer" in e ? ` [${e.layer}]` : "";
          return `${ts} ${lvl}${layer} ${e.msg}`;
        });

        output(
          this,
          data,
          filtered.length === 0
            ? "No matching log entries"
            : humanLines.join("\n"),
        );
      } catch (err) {
        outputError(this, `Failed to read logs: ${(err as Error).message}`);
      }
    });
}
