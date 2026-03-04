# TOOLS.md - Available Tools & How to Use Them

## CRITICAL: Always use tools — never fake results

You have real, working tools. When the user asks you to do something that a tool can handle, you MUST call the tool. Never pretend to have results. Never fabricate data. Never describe what you "would" do — actually do it by calling the tool.

If a tool call fails, tell the user what went wrong. That's always better than making something up.

## Available Custom Tools

### weather
Get real weather data for any location.
- Use when: user asks about weather, temperature, forecast
- IMPORTANT: Always include the country in the location — use "Lisbon, Portugal" not just "Lisbon"
- Example: user says "what's the weather in Lisbon" → call `weather` with location "Lisbon, Portugal"

### email_send
Send a real email via Gmail.
- Use when: user asks to send/compose/write an email
- Parameters: to, subject, body (plain text or HTML)

### email_read
Check the inbox for recent emails.
- Use when: user asks about their email, inbox, or recent messages

### calendar_list
List calendar events from Radicale CalDAV.
- Use when: user asks about their schedule, meetings, upcoming events

### calendar_add
Create a new calendar event.
- Use when: user asks to schedule something, add a meeting, set a reminder

### contacts_list
List contacts from Radicale CardDAV.
- Use when: user asks about their contacts

### contacts_add
Add a new contact.
- Use when: user asks to save/add a contact

## Built-in Tools

### web_search
Search the web for current information (powered by Perplexity Sonar).
- Use when: user asks about current events, prices, news, facts you don't know, or anything requiring up-to-date information
- Examples: stock/commodity prices, sports scores, latest news, "what happened today", product comparisons
- This is a native OpenClaw tool — just call `web_search` with a query

### web_fetch
Fetch and read the content of a specific URL.
- Use when: user gives you a URL to read or you need to check a specific web page

## Tool Calling Rules

1. **Always call the tool** — do not simulate, imagine, or hallucinate tool results
2. **Call tools first, talk second** — get the real data, then compose your response
3. **NEVER call tools in parallel when one depends on another** — if you need weather data to compose an email, call `weather` FIRST, wait for the result, THEN call `email_send` with the actual weather data in the body. Do NOT use placeholders like "[Weather Information]".
4. **Report errors honestly** — if a tool fails, say so
5. **NEVER use `exec` or shell commands for tasks the tools above can handle** — do NOT use curl, wget, jq, or any shell command to fetch weather, send email, or manage calendar/contacts. The sandbox does not have curl or jq. Use the named tools above instead. For weather, call `weather`. For email, call `email_send`. For calendar, call `calendar_add`. These tools work — shell commands do not.
6. **Do not plan or describe — just act** — when asked to do something, call the tool immediately. Do not say "I will now..." or "Let me..." — just call it.
