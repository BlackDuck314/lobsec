// ── Gmail Email Tools ────────────────────────────────────────────────────────
// Send and read email via Gmail SMTP/IMAP.

import { createTransport, type Transporter } from "nodemailer";

export interface EmailConfig {
  user: string;
  appPassword: string;
  smtpHost?: string;
  smtpPort?: number;
  imapHost?: string;
  imapPort?: number;
}

export interface SendEmailParams {
  to: string;
  subject: string;
  body: string;
  html?: boolean;
}

export interface SendEmailResult {
  messageId: string;
  to: string;
  subject: string;
}

export interface EmailMessage {
  uid: number;
  from: string;
  to: string;
  subject: string;
  date: string;
  snippet: string;
}

let transporter: Transporter | null = null;

function getTransporter(config: EmailConfig): Transporter {
  if (!transporter) {
    transporter = createTransport({
      host: config.smtpHost ?? "smtp.gmail.com",
      port: config.smtpPort ?? 587,
      secure: false,
      auth: {
        user: config.user,
        pass: config.appPassword,
      },
      tls: {
        rejectUnauthorized: true,
      },
    });
  }
  return transporter;
}

export async function sendEmail(
  params: SendEmailParams,
  config: EmailConfig,
): Promise<SendEmailResult> {
  const transport = getTransporter(config);

  const info = await transport.sendMail({
    from: `lobsec <${config.user}>`,
    to: params.to,
    subject: params.subject,
    [params.html ? "html" : "text"]: params.body,
  });

  return {
    messageId: info.messageId,
    to: params.to,
    subject: params.subject,
  };
}

export function formatSendResult(result: SendEmailResult): string {
  return `Email sent to ${result.to}\nSubject: ${result.subject}\nMessage-ID: ${result.messageId}`;
}

// IMAP reading via raw socket (avoid heavy imap library dependency)
// Uses Node.js built-in tls module for IMAP IDLE/FETCH

export interface ImapConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  tls: boolean;
}

/**
 * Read recent emails from Gmail IMAP.
 * Uses a minimal IMAP implementation to avoid heavy dependencies.
 */
export async function readEmails(
  count: number,
  config: EmailConfig,
): Promise<EmailMessage[]> {
  const { connect } = await import("node:tls");

  const host = config.imapHost ?? "imap.gmail.com";
  const port = config.imapPort ?? 993;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error("IMAP timeout after 15s"));
    }, 15_000);

    const socket = connect({ host, port, rejectUnauthorized: true });
    let buffer = "";
    let tagNum = 0;
    const messages: EmailMessage[] = [];
    let phase: "greeting" | "login" | "select" | "search" | "fetch" | "logout" = "greeting";
    let uids: string[] = [];
    let currentMsg: Partial<EmailMessage> = {};

    function tag(): string {
      return `A${++tagNum}`;
    }

    function send(cmd: string): void {
      socket.write(cmd + "\r\n");
    }

    socket.on("data", (data: Buffer) => {
      buffer += data.toString();

      // Process complete lines
      while (buffer.includes("\r\n")) {
        const idx = buffer.indexOf("\r\n");
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        processLine(line);
      }
    });

    function processLine(line: string): void {
      if (phase === "greeting" && line.startsWith("* OK")) {
        phase = "login";
        send(`${tag()} LOGIN "${config.user}" "${config.appPassword}"`);
        return;
      }

      if (phase === "login" && line.includes("OK") && line.startsWith(`A${tagNum}`)) {
        phase = "select";
        send(`${tag()} SELECT INBOX`);
        return;
      }

      if (phase === "select" && line.startsWith(`A${tagNum}`) && line.includes("OK")) {
        phase = "search";
        send(`${tag()} UID SEARCH ALL`);
        return;
      }

      if (phase === "search") {
        if (line.startsWith("* SEARCH")) {
          uids = line.replace("* SEARCH", "").trim().split(/\s+/).filter(Boolean);
          return;
        }
        if (line.startsWith(`A${tagNum}`) && line.includes("OK")) {
          // Fetch last N messages
          const fetchUids = uids.slice(-count);
          if (fetchUids.length === 0) {
            phase = "logout";
            send(`${tag()} LOGOUT`);
            return;
          }
          phase = "fetch";
          send(`${tag()} UID FETCH ${fetchUids.join(",")} (UID BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE)])`);
          return;
        }
      }

      if (phase === "fetch") {
        // Parse FETCH responses
        const uidMatch = line.match(/UID (\d+)/);
        if (uidMatch) {
          if (currentMsg.uid !== undefined) {
            messages.push(currentMsg as EmailMessage);
          }
          currentMsg = { uid: parseInt(uidMatch[1]!, 10), snippet: "" };
        }

        const fromMatch = line.match(/^From:\s*(.+)/i);
        if (fromMatch) currentMsg.from = fromMatch[1]!.trim();

        const toMatch = line.match(/^To:\s*(.+)/i);
        if (toMatch) currentMsg.to = toMatch[1]!.trim();

        const subjectMatch = line.match(/^Subject:\s*(.+)/i);
        if (subjectMatch) currentMsg.subject = subjectMatch[1]!.trim();

        const dateMatch = line.match(/^Date:\s*(.+)/i);
        if (dateMatch) currentMsg.date = dateMatch[1]!.trim();

        if (line.startsWith(`A${tagNum}`) && line.includes("OK")) {
          if (currentMsg.uid !== undefined) {
            messages.push(currentMsg as EmailMessage);
          }
          phase = "logout";
          send(`${tag()} LOGOUT`);
          return;
        }
      }

      if (phase === "logout" && (line.includes("BYE") || line.startsWith(`A${tagNum}`))) {
        clearTimeout(timeout);
        socket.destroy();
        resolve(messages.reverse());
      }
    }

    socket.on("error", (err: Error) => {
      clearTimeout(timeout);
      reject(new Error(`IMAP error: ${err.message}`));
    });

    socket.on("close", () => {
      clearTimeout(timeout);
      resolve(messages.reverse());
    });
  });
}

export function formatEmails(emails: EmailMessage[]): string {
  if (emails.length === 0) return "No emails found.";
  return emails
    .map((e) =>
      `From: ${e.from ?? "unknown"}\nTo: ${e.to ?? "unknown"}\nSubject: ${e.subject ?? "(no subject)"}\nDate: ${e.date ?? "unknown"}\n`,
    )
    .join("\n---\n");
}
