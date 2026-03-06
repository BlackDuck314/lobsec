// ── lobsec-tools OpenClaw Plugin ─────────────────────────────────────────────
// Registers tool integrations: weather, email, calendar, contacts.
// Tools read credentials from environment (injected by HSM extraction).

export {
  getWeather,
  formatWeather,
  describeWeatherCode,
  type WeatherConfig,
  type WeatherResult,
} from "./weather.js";

export {
  sendEmail,
  readEmails,
  formatSendResult,
  formatEmails,
  type EmailConfig,
  type SendEmailParams,
  type SendEmailResult,
  type EmailMessage,
} from "./email.js";

export {
  listEvents,
  addEvent,
  listContacts,
  addContact,
  formatEvents,
  formatContacts,
  parseEvents,
  parseVEvent,
  parseContacts,
  parseVCard,
  type RadicaleConfig,
  type CalendarEvent,
  type Contact,
} from "./calendar.js";

export {
  githubAction,
  type GitHubConfig,
  type GitHubAction,
  type GitHubParams,
  type GitHubResult,
} from "./github.js";

export {
  runExamyTest,
  loadPersonas,
  type PersonaConfig,
  type TestConfig,
  type TestResult,
  type PersonaResult,
} from "./examy.js";
