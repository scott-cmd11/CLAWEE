# Security Policy

## Supported versions

Security updates are applied to the latest main branch.

## Reporting a vulnerability

- Do not create a public GitHub issue for vulnerabilities.
- Contact maintainers privately with:
  - impact summary
  - reproduction steps
  - affected files/endpoints
  - suggested mitigation (if available)

## Hardening principles

- Default-deny and fail-closed behavior for high-risk paths.
- Signed policy/config catalogs for control-plane integrity.
- Tamper-evident audit + approval attestation chains.
- Replay protection on ingress and approval consumption.
