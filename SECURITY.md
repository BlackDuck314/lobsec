# Security Policy

## Scope

This policy covers the **lobsec** security wrapper only. Vulnerabilities in
upstream OpenClaw should be reported to the
[OpenClaw project](https://github.com/openclaw/openclaw) directly.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of the following channels:

- **GitHub Security Advisories** (preferred): Open a private advisory at
  [github.com/BlackDuck314/lobsec/security/advisories](https://github.com/BlackDuck314/lobsec/security/advisories)
- **Email**: `blackduck314@users.noreply.github.com`

Include as much detail as you can: steps to reproduce, affected versions,
potential impact, and any suggested fix.

## What Counts as a Security Issue

- Authentication or authorization bypasses
- Remote code execution, command injection, or container escapes
- Credential or secret exposure
- Denial of service against security-critical components
- Regressions in any CVE mitigation (CVE-2026-25253, CVE-2026-25157, CVE-2026-24763)

## Response Timeline

- **Acknowledgment**: Within 48 hours of report receipt.
- **Initial assessment**: Within 5 business days.
- **Fix or mitigation**: Best effort within 30 days for confirmed issues,
  faster for critical severity.

## Disclosure

We follow coordinated disclosure. We will work with you on a timeline before
any public announcement. We will not pursue legal action against researchers
acting in good faith.

## Credit

Reporters who follow responsible disclosure will be credited in the release
notes and changelog unless they prefer to remain anonymous.
