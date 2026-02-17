# Contributing to lobsec

Thank you for your interest in improving lobsec. This guide covers everything
you need to get started.

## Prerequisites

- **Node.js 22 LTS** or later
- **pnpm** (strict dependency resolution is required)
- **OpenClaw** installed locally for integration testing
- **Docker** (rootless mode recommended) for container-related work

## Development Setup

```bash
git clone https://github.com/BlackDuck314/lobsec.git
cd lobsec
pnpm install
pnpm test
pnpm typecheck
```

## Code Style

- TypeScript with `strict: true` -- no exceptions.
- **No `any` type** unless wrapped in a branded type with runtime validation.
- All external input must pass through a validation layer (e.g., `zod`).
- Lint with **oxlint** before committing. Fix all warnings.
- Keep functions small and testable. Prefer pure functions where possible.

## Pull Request Process

1. Branch from `main`. Use a descriptive branch name (e.g., `fix/websocket-auth`).
2. Include tests for every change. Untested code will not be merged.
3. Run the full check suite before opening a PR:
   ```bash
   pnpm test && pnpm typecheck
   ```
4. Fill out the security impact assessment in the PR template.
5. Keep PRs focused. One logical change per PR.
6. Update documentation if your change affects requirements, architecture, or
   security posture.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): short description

Body explaining WHY this change was made.
References: REQ-XXX-NNN
```

Valid types: `feat`, `fix`, `security`, `docs`, `test`, `refactor`, `build`,
`ci`, `chore`.

Always include a **why** in the body and reference requirement IDs when
applicable.

## Security-Sensitive Changes

Changes touching `src/security/`, `docker/`, or network configuration require
additional scrutiny:

- Update `docs/security-design.md` before the PR is merged.
- Evaluate impact against tracked CVEs (see `docs/CVE_ANALYSIS.md`).
- Expect a longer review cycle for these changes.

If you discover a vulnerability, please follow the process in `SECURITY.md`
instead of opening a public issue.

## Questions

Open a GitHub Discussion or reach out to the maintainers. When in doubt,
document your assumptions and ask for review.
