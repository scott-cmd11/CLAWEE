# Contributing

## Development setup

1. Install Node.js 20+.
2. Install dependencies:
   - `npm ci`
3. Build:
   - `npm run build`
4. Run full security smoke:
   - `npm run smoke:security`

## Pull request requirements

- Keep security controls fail-closed by default.
- Add/update tests for any behavior or policy change.
- Avoid adding outbound dependencies that break air-gapped use.
- Keep changes scoped and documented in `README.md` when user-facing.

## Commit guidance

- Use clear, imperative commit messages.
- Include affected modules in the PR description.
- Note any config/env changes explicitly.

## Reporting issues

- Use the issue templates.
- For sensitive vulnerabilities, do not open a public issue; follow `SECURITY.md`.
