import { describe, it, expect } from "vitest";
import { formatSendResult, formatEmails, type SendEmailResult, type EmailMessage } from "./email.js";

describe("Email", () => {
  describe("formatSendResult", () => {
    it("formats a send result", () => {
      const result: SendEmailResult = {
        messageId: "<abc123@mail.example.com>",
        to: "test@example.com",
        subject: "Hello",
      };
      const text = formatSendResult(result);
      expect(text).toContain("test@example.com");
      expect(text).toContain("Hello");
      expect(text).toContain("abc123@mail.example.com");
    });
  });

  describe("formatEmails", () => {
    it("formats email list", () => {
      const emails: EmailMessage[] = [
        {
          uid: 1,
          from: "sender@test.com",
          to: "user@example.com",
          subject: "Test Subject",
          date: "Thu, 27 Feb 2026 10:00:00 +0000",
          snippet: "",
        },
      ];
      const text = formatEmails(emails);
      expect(text).toContain("sender@test.com");
      expect(text).toContain("Test Subject");
      expect(text).toContain("27 Feb 2026");
    });

    it("returns message for empty list", () => {
      expect(formatEmails([])).toBe("No emails found.");
    });

    it("handles missing fields gracefully", () => {
      const emails: EmailMessage[] = [
        { uid: 1, from: "", to: "", subject: "", date: "", snippet: "" },
      ];
      const text = formatEmails(emails);
      expect(text).toContain("From:");
    });
  });
});
