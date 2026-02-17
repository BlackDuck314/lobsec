// ── Radicale CalDAV/CardDAV Tools ────────────────────────────────────────────
// Calendar and contacts management via Radicale's WebDAV API.

import { randomUUID } from "node:crypto";

export interface RadicaleConfig {
  url: string;
  user: string;
  password: string;
}

export interface CalendarEvent {
  uid: string;
  summary: string;
  dtstart: string;
  dtend: string;
  description?: string;
  location?: string;
}

export interface Contact {
  uid: string;
  fn: string;
  email?: string;
  tel?: string;
  org?: string;
}

function authHeader(config: RadicaleConfig): string {
  return "Basic " + Buffer.from(`${config.user}:${config.password}`).toString("base64");
}

// ── Calendar Operations ─────────────────────────────────────────────────────

export async function listEvents(config: RadicaleConfig): Promise<CalendarEvent[]> {
  const url = `${config.url}/${config.user}/calendar.ics/`;

  const response = await fetch(url, {
    method: "REPORT",
    headers: {
      Authorization: authHeader(config),
      "Content-Type": "application/xml; charset=utf-8",
      Depth: "1",
    },
    body: `<?xml version="1.0" encoding="UTF-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag />
    <C:calendar-data />
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT" />
    </C:comp-filter>
  </C:filter>
</C:calendar-query>`,
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`CalDAV REPORT failed (${response.status}): ${text}`);
  }

  const xml = await response.text();
  return parseEvents(xml);
}

/** Parse VEVENT data from CalDAV XML response. */
export function parseEvents(xml: string): CalendarEvent[] {
  const events: CalendarEvent[] = [];

  // Extract calendar-data blocks
  const calDataRegex = /<(?:C:|cal:)?calendar-data[^>]*>([\s\S]*?)<\/(?:C:|cal:)?calendar-data>/gi;
  let calMatch: RegExpExecArray | null;

  while ((calMatch = calDataRegex.exec(xml)) !== null) {
    const ical = decodeXmlEntities(calMatch[1]!);
    const event = parseVEvent(ical);
    if (event) events.push(event);
  }

  return events;
}

/** Parse a single VEVENT from iCalendar text. */
export function parseVEvent(ical: string): CalendarEvent | null {
  const veventMatch = ical.match(/BEGIN:VEVENT([\s\S]*?)END:VEVENT/);
  if (!veventMatch) return null;

  const block = veventMatch[1]!;

  const uid = extractIcalProp(block, "UID") ?? randomUUID();
  const summary = extractIcalProp(block, "SUMMARY") ?? "(untitled)";
  const dtstart = extractIcalProp(block, "DTSTART") ?? "";
  const dtend = extractIcalProp(block, "DTEND") ?? dtstart;
  const description = extractIcalProp(block, "DESCRIPTION");
  const location = extractIcalProp(block, "LOCATION");

  return { uid, summary, dtstart, dtend, description, location };
}

function extractIcalProp(block: string, prop: string): string | undefined {
  // Handle property with parameters (e.g., DTSTART;VALUE=DATE:20260301)
  const regex = new RegExp(`^${prop}(?:;[^:]*)?:(.+)`, "mi");
  const match = block.match(regex);
  return match?.[1]?.trim();
}

function decodeXmlEntities(text: string): string {
  return text
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

export async function addEvent(
  event: {
    summary: string;
    dtstart: string;
    dtend: string;
    description?: string;
    location?: string;
  },
  config: RadicaleConfig,
): Promise<CalendarEvent> {
  const uid = randomUUID();
  const url = `${config.url}/${config.user}/calendar.ics/${uid}.ics`;

  const now = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+/, "");
  const ical = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//lobsec//tools//EN",
    "BEGIN:VEVENT",
    `UID:${uid}`,
    `DTSTAMP:${now}`,
    `DTSTART:${event.dtstart}`,
    `DTEND:${event.dtend}`,
    `SUMMARY:${event.summary}`,
    ...(event.description ? [`DESCRIPTION:${event.description}`] : []),
    ...(event.location ? [`LOCATION:${event.location}`] : []),
    "END:VEVENT",
    "END:VCALENDAR",
  ].join("\r\n");

  const response = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: authHeader(config),
      "Content-Type": "text/calendar; charset=utf-8",
    },
    body: ical,
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok && response.status !== 201) {
    const text = await response.text().catch(() => "");
    throw new Error(`CalDAV PUT failed (${response.status}): ${text}`);
  }

  return {
    uid,
    summary: event.summary,
    dtstart: event.dtstart,
    dtend: event.dtend,
    description: event.description,
    location: event.location,
  };
}

// ── Contact Operations ──────────────────────────────────────────────────────

export async function listContacts(config: RadicaleConfig): Promise<Contact[]> {
  const url = `${config.url}/${config.user}/contacts.vcf/`;

  const response = await fetch(url, {
    method: "REPORT",
    headers: {
      Authorization: authHeader(config),
      "Content-Type": "application/xml; charset=utf-8",
      Depth: "1",
    },
    body: `<?xml version="1.0" encoding="UTF-8" ?>
<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <D:getetag />
    <CR:address-data />
  </D:prop>
</CR:addressbook-query>`,
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`CardDAV REPORT failed (${response.status}): ${text}`);
  }

  const xml = await response.text();
  return parseContacts(xml);
}

/** Parse vCard data from CardDAV XML response. */
export function parseContacts(xml: string): Contact[] {
  const contacts: Contact[] = [];

  const addrDataRegex = /<(?:CR:|card:)?address-data[^>]*>([\s\S]*?)<\/(?:CR:|card:)?address-data>/gi;
  let match: RegExpExecArray | null;

  while ((match = addrDataRegex.exec(xml)) !== null) {
    const vcard = decodeXmlEntities(match[1]!);
    const contact = parseVCard(vcard);
    if (contact) contacts.push(contact);
  }

  return contacts;
}

/** Parse a single vCard. */
export function parseVCard(vcard: string): Contact | null {
  const block = vcard.match(/BEGIN:VCARD([\s\S]*?)END:VCARD/)?.[1];
  if (!block) return null;

  const uid = extractIcalProp(block, "UID") ?? randomUUID();
  const fn = extractIcalProp(block, "FN") ?? "(unnamed)";
  const email = extractIcalProp(block, "EMAIL");
  const tel = extractIcalProp(block, "TEL");
  const org = extractIcalProp(block, "ORG");

  return { uid, fn, email, tel, org };
}

export async function addContact(
  contact: {
    fn: string;
    email?: string;
    tel?: string;
    org?: string;
  },
  config: RadicaleConfig,
): Promise<Contact> {
  const uid = randomUUID();
  const url = `${config.url}/${config.user}/contacts.vcf/${uid}.vcf`;

  const vcard = [
    "BEGIN:VCARD",
    "VERSION:3.0",
    `UID:${uid}`,
    `FN:${contact.fn}`,
    ...(contact.email ? [`EMAIL:${contact.email}`] : []),
    ...(contact.tel ? [`TEL:${contact.tel}`] : []),
    ...(contact.org ? [`ORG:${contact.org}`] : []),
    `REV:${new Date().toISOString()}`,
    "END:VCARD",
  ].join("\r\n");

  const response = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: authHeader(config),
      "Content-Type": "text/vcard; charset=utf-8",
    },
    body: vcard,
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok && response.status !== 201) {
    const text = await response.text().catch(() => "");
    throw new Error(`CardDAV PUT failed (${response.status}): ${text}`);
  }

  return { uid, fn: contact.fn, email: contact.email, tel: contact.tel, org: contact.org };
}

// ── Formatting Helpers ──────────────────────────────────────────────────────

export function formatEvents(events: CalendarEvent[]): string {
  if (events.length === 0) return "No calendar events found.";
  return events
    .map((e) => {
      const parts = [`${e.summary} (${formatDt(e.dtstart)} – ${formatDt(e.dtend)})`];
      if (e.location) parts.push(`  Location: ${e.location}`);
      if (e.description) parts.push(`  ${e.description}`);
      return parts.join("\n");
    })
    .join("\n\n");
}

export function formatContacts(contacts: Contact[]): string {
  if (contacts.length === 0) return "No contacts found.";
  return contacts
    .map((c) => {
      const parts = [c.fn];
      if (c.email) parts.push(`  Email: ${c.email}`);
      if (c.tel) parts.push(`  Phone: ${c.tel}`);
      if (c.org) parts.push(`  Org: ${c.org}`);
      return parts.join("\n");
    })
    .join("\n\n");
}

function formatDt(dt: string): string {
  // Convert iCal date (20260301T150000Z) to human-readable
  if (dt.length === 8) {
    return `${dt.slice(0, 4)}-${dt.slice(4, 6)}-${dt.slice(6, 8)}`;
  }
  if (dt.includes("T")) {
    const d = dt.slice(0, 8);
    const t = dt.slice(9, 13);
    return `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)} ${t.slice(0, 2)}:${t.slice(2, 4)}`;
  }
  return dt;
}
