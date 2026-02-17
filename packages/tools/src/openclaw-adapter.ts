// ── lobsec-tools OpenClaw Plugin Adapter ─────────────────────────────────────
// Registers weather, email, calendar, and contacts as OpenClaw AgentTools.
// Uses JSON Schema (TypeBox-compatible) parameters and AgentToolResult return shape.
// Registration is SYNCHRONOUS (OpenClaw ignores async register() return values).
// Credentials come from environment variables (injected by HSM at startup).

import { getWeather, formatWeather } from "./weather.js";
import { sendEmail, readEmails, formatSendResult, formatEmails } from "./email.js";
import {
  listEvents,
  addEvent,
  listContacts,
  addContact,
  formatEvents,
  formatContacts,
} from "./calendar.js";

import type { WeatherConfig } from "./weather.js";
import type { EmailConfig } from "./email.js";
import type { RadicaleConfig } from "./calendar.js";

// ── OpenClaw type stubs (matches pi-agent-core AgentTool shape) ─────────────

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
    signal?: AbortSignal,
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

// ── Helpers ─────────────────────────────────────────────────────────────────

function textResult(text: string): AgentToolResult {
  return { content: [{ type: "text", text }], details: { text } };
}

function getEnv(key: string): string {
  const val = process.env[key];
  if (!val) throw new Error(`Missing env var: ${key}`);
  return val;
}

function getWeatherConfig(): WeatherConfig {
  return { apiKey: getEnv("TOMORROW_IO_API_KEY") };
}

function getEmailConfig(): EmailConfig {
  return {
    user: getEnv("GMAIL_USER"),
    appPassword: getEnv("GMAIL_APP_PASSWORD"),
  };
}

function getRadicaleConfig(): RadicaleConfig {
  return {
    url: getEnv("RADICALE_URL"),
    user: getEnv("RADICALE_USER"),
    password: getEnv("RADICALE_PASSWORD"),
  };
}

// ── JSON Schema helpers (TypeBox-compatible shapes) ──────────────────────────
// OpenClaw's registerTool accepts TypeBox TSchema, which is just JSON Schema
// with a Symbol brand. Plain JSON Schema objects work identically at runtime.
// We build them directly to keep registration synchronous (OpenClaw ignores
// async register() return values).

const OPTIONAL_MARKER = Symbol("optional");

const Type = {
  Object: (props: Record<string, unknown>, opts?: Record<string, unknown>) => {
    const required = Object.keys(props).filter(
      (k) => !(props[k] && typeof props[k] === "object" && OPTIONAL_MARKER in (props[k] as Record<symbol, unknown>)),
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

// ── Plugin entry point ──────────────────────────────────────────────────────

export default {
  id: "lobsec-tools",

  register(api: PluginApi) {
    const log = api.logger;

    // Weather
    api.registerTool({
      name: "weather",
      label: "Weather",
      description: "Get current weather and 5-day forecast for a location. Uses Tomorrow.io API. Pass a city name like 'London' or coordinates like '51.5,-0.1'.",
      parameters: Type.Object({
        location: Type.String({ description: "City name or coordinates" }),
      }),
      execute: async (_id, params) => {
        const result = await getWeather(params.location as string, getWeatherConfig());
        return textResult(formatWeather(result));
      },
    });

    // Email send
    api.registerTool({
      name: "email_send",
      label: "Send Email",
      description: "Send an email via Gmail SMTP. Specify recipient (to), subject, and body text.",
      parameters: Type.Object({
        to: Type.String({ description: "Recipient email address" }),
        subject: Type.String({ description: "Email subject" }),
        body: Type.String({ description: "Email body text" }),
      }),
      execute: async (_id, params) => {
        const result = await sendEmail(
          { to: params.to as string, subject: params.subject as string, body: params.body as string },
          getEmailConfig(),
        );
        return textResult(formatSendResult(result));
      },
    });

    // Email read
    api.registerTool({
      name: "email_read",
      label: "Read Email",
      description: "Read recent emails from Gmail inbox. Returns the most recent messages with sender, subject, and date.",
      parameters: Type.Object({
        count: Type.Optional(Type.Number({ description: "Number of recent emails to fetch (default: 5)" })),
      }),
      execute: async (_id, params) => {
        const emails = await readEmails((params.count as number) ?? 5, getEmailConfig());
        return textResult(formatEmails(emails));
      },
    });

    // Calendar list
    api.registerTool({
      name: "calendar_list",
      label: "List Calendar",
      description: "List all calendar events from the lobsec CalDAV calendar (Radicale).",
      parameters: Type.Object({}),
      execute: async () => {
        const events = await listEvents(getRadicaleConfig());
        return textResult(formatEvents(events));
      },
    });

    // Calendar add
    api.registerTool({
      name: "calendar_add",
      label: "Add Event",
      description: "Add a calendar event. Use iCalendar datetime format: YYYYMMDDTHHMMSSZ for date+time (e.g., 20260301T150000Z) or YYYYMMDD for all-day events.",
      parameters: Type.Object({
        summary: Type.String({ description: "Event title" }),
        dtstart: Type.String({ description: "Start: YYYYMMDDTHHMMSSZ or YYYYMMDD" }),
        dtend: Type.String({ description: "End: YYYYMMDDTHHMMSSZ or YYYYMMDD" }),
        description: Type.Optional(Type.String({ description: "Event description" })),
        location: Type.Optional(Type.String({ description: "Event location" })),
      }),
      execute: async (_id, params) => {
        const event = await addEvent(
          {
            summary: params.summary as string,
            dtstart: params.dtstart as string,
            dtend: params.dtend as string,
            description: params.description as string | undefined,
            location: params.location as string | undefined,
          },
          getRadicaleConfig(),
        );
        return textResult(`Event created: ${event.summary} (${event.dtstart} – ${event.dtend})`);
      },
    });

    // Contacts list
    api.registerTool({
      name: "contacts_list",
      label: "List Contacts",
      description: "List all contacts from the lobsec CardDAV address book (Radicale).",
      parameters: Type.Object({}),
      execute: async () => {
        const contacts = await listContacts(getRadicaleConfig());
        return textResult(formatContacts(contacts));
      },
    });

    // Contacts add
    api.registerTool({
      name: "contacts_add",
      label: "Add Contact",
      description: "Add a contact to the address book. Only fn (full name) is required; email, tel, and org are optional.",
      parameters: Type.Object({
        fn: Type.String({ description: "Full name" }),
        email: Type.Optional(Type.String({ description: "Email address" })),
        tel: Type.Optional(Type.String({ description: "Phone number" })),
        org: Type.Optional(Type.String({ description: "Organization" })),
      }),
      execute: async (_id, params) => {
        const contact = await addContact(
          {
            fn: params.fn as string,
            email: params.email as string | undefined,
            tel: params.tel as string | undefined,
            org: params.org as string | undefined,
          },
          getRadicaleConfig(),
        );
        return textResult(`Contact created: ${contact.fn}${contact.email ? ` (${contact.email})` : ""}`);
      },
    });

    log.info("[lobsec-tools] registered 7 tools: weather, email_send, email_read, calendar_list, calendar_add, contacts_list, contacts_add");
  },
};
