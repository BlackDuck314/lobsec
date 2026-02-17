import { describe, it, expect } from "vitest";
import {
  parseVEvent,
  parseEvents,
  parseVCard,
  parseContacts,
  formatEvents,
  formatContacts,
  type CalendarEvent,
  type Contact,
} from "./calendar.js";

describe("Calendar", () => {
  describe("parseVEvent", () => {
    it("parses a simple VEVENT", () => {
      const ical = [
        "BEGIN:VCALENDAR",
        "BEGIN:VEVENT",
        "UID:test-123",
        "SUMMARY:Team Meeting",
        "DTSTART:20260301T150000Z",
        "DTEND:20260301T160000Z",
        "DESCRIPTION:Weekly sync",
        "LOCATION:Room 42",
        "END:VEVENT",
        "END:VCALENDAR",
      ].join("\r\n");

      const event = parseVEvent(ical);
      expect(event).not.toBeNull();
      expect(event!.uid).toBe("test-123");
      expect(event!.summary).toBe("Team Meeting");
      expect(event!.dtstart).toBe("20260301T150000Z");
      expect(event!.dtend).toBe("20260301T160000Z");
      expect(event!.description).toBe("Weekly sync");
      expect(event!.location).toBe("Room 42");
    });

    it("handles DTSTART with VALUE parameter", () => {
      const ical = [
        "BEGIN:VEVENT",
        "UID:date-only",
        "SUMMARY:All Day",
        "DTSTART;VALUE=DATE:20260301",
        "DTEND;VALUE=DATE:20260302",
        "END:VEVENT",
      ].join("\r\n");

      const event = parseVEvent(ical);
      expect(event).not.toBeNull();
      expect(event!.dtstart).toBe("20260301");
      expect(event!.dtend).toBe("20260302");
    });

    it("returns null for non-VEVENT content", () => {
      expect(parseVEvent("BEGIN:VTODO\nEND:VTODO")).toBeNull();
    });

    it("handles missing optional fields", () => {
      const ical = "BEGIN:VEVENT\nUID:min\nSUMMARY:Min\nDTSTART:20260301\nEND:VEVENT";
      const event = parseVEvent(ical);
      expect(event).not.toBeNull();
      expect(event!.description).toBeUndefined();
      expect(event!.location).toBeUndefined();
    });
  });

  describe("parseEvents", () => {
    it("extracts events from CalDAV XML", () => {
      const xml = `<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/lobsec/calendar.ics/test.ics</href>
    <propstat><prop>
      <C:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:xml-test
SUMMARY:From XML
DTSTART:20260301T100000Z
DTEND:20260301T110000Z
END:VEVENT
END:VCALENDAR</C:calendar-data>
    </prop></propstat>
  </response>
</multistatus>`;

      const events = parseEvents(xml);
      expect(events).toHaveLength(1);
      expect(events[0]!.uid).toBe("xml-test");
      expect(events[0]!.summary).toBe("From XML");
    });

    it("handles XML entities", () => {
      const xml = `<C:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:entity-test
SUMMARY:Meeting &amp; Lunch
DTSTART:20260301T120000Z
DTEND:20260301T130000Z
END:VEVENT
END:VCALENDAR</C:calendar-data>`;

      const events = parseEvents(xml);
      expect(events).toHaveLength(1);
      expect(events[0]!.summary).toBe("Meeting & Lunch");
    });
  });

  describe("formatEvents", () => {
    it("formats event list", () => {
      const events: CalendarEvent[] = [
        {
          uid: "1",
          summary: "Test Event",
          dtstart: "20260301T150000Z",
          dtend: "20260301T160000Z",
          location: "Office",
        },
      ];
      const text = formatEvents(events);
      expect(text).toContain("Test Event");
      expect(text).toContain("2026-03-01 15:00");
      expect(text).toContain("Office");
    });

    it("returns message for empty list", () => {
      expect(formatEvents([])).toBe("No calendar events found.");
    });

    it("formats date-only events", () => {
      const events: CalendarEvent[] = [
        { uid: "2", summary: "Holiday", dtstart: "20260301", dtend: "20260302" },
      ];
      const text = formatEvents(events);
      expect(text).toContain("2026-03-01");
    });
  });
});

describe("Contacts", () => {
  describe("parseVCard", () => {
    it("parses a simple vCard", () => {
      const vcard = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        "UID:contact-123",
        "FN:John Doe",
        "EMAIL:john@example.com",
        "TEL:+351912345678",
        "ORG:ACME Corp",
        "END:VCARD",
      ].join("\r\n");

      const contact = parseVCard(vcard);
      expect(contact).not.toBeNull();
      expect(contact!.uid).toBe("contact-123");
      expect(contact!.fn).toBe("John Doe");
      expect(contact!.email).toBe("john@example.com");
      expect(contact!.tel).toBe("+351912345678");
      expect(contact!.org).toBe("ACME Corp");
    });

    it("handles minimal vCard", () => {
      const vcard = "BEGIN:VCARD\nFN:Jane\nEND:VCARD";
      const contact = parseVCard(vcard);
      expect(contact).not.toBeNull();
      expect(contact!.fn).toBe("Jane");
      expect(contact!.email).toBeUndefined();
    });

    it("returns null for non-vCard", () => {
      expect(parseVCard("not a vcard")).toBeNull();
    });
  });

  describe("parseContacts", () => {
    it("extracts contacts from CardDAV XML", () => {
      const xml = `<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">
  <response>
    <href>/lobsec/contacts.vcf/test.vcf</href>
    <propstat><prop>
      <CR:address-data>BEGIN:VCARD
VERSION:3.0
UID:xml-contact
FN:XML Person
EMAIL:xml@test.com
END:VCARD</CR:address-data>
    </prop></propstat>
  </response>
</multistatus>`;

      const contacts = parseContacts(xml);
      expect(contacts).toHaveLength(1);
      expect(contacts[0]!.fn).toBe("XML Person");
      expect(contacts[0]!.email).toBe("xml@test.com");
    });
  });

  describe("formatContacts", () => {
    it("formats contact list", () => {
      const contacts: Contact[] = [
        { uid: "1", fn: "Alice", email: "alice@test.com", tel: "+1234567890" },
      ];
      const text = formatContacts(contacts);
      expect(text).toContain("Alice");
      expect(text).toContain("alice@test.com");
      expect(text).toContain("+1234567890");
    });

    it("returns message for empty list", () => {
      expect(formatContacts([])).toBe("No contacts found.");
    });
  });
});
