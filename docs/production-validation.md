# Production Validation Guide

This guide defines how Claw-EE is validated for production readiness.

## Objective

Prove that the current control-plane implementation is stable, fail-closed, and operationally auditable under realistic service conditions.

## Validation Profiles

- `quick`: fast gate for local pre-push checks.
- `staging`: default production-readiness gate.
- `soak`: longer flake/stability run for release hardening.

## Required Environment

Strict replay validation requires shared replay backends:

- `REPLAY_REDIS_URL`
- `REPLAY_POSTGRES_URL`

Recommended:

- `REPLAY_POSTGRES_SCHEMA=clawee`
- `REPLAY_POSTGRES_TABLE_PREFIX=replay_`
- `REPLAY_POSTGRES_CONNECT_TIMEOUT_MS=10000`
- `REPLAY_POSTGRES_SSL_MODE=disable` (or enterprise SSL mode in real deployments)

## Commands

```powershell
npm run validate:production:quick
npm run validate:production
npm run validate:production:soak
```

Each run writes a machine-readable report to:

- `artifacts/production-validation/report-<timestamp>.json`

## Stage Gates (Pass Criteria)

1. Build and static checks
- `npm run build` exits `0`
- `npm run repo:check` exits `0`

2. Security strict smoke
- `npm run smoke:security:strict` exits `0`
- No replay-backend skips are allowed in strict mode

3. Flake loop stability (`staging`/`soak`)
- `tests/gate-integration-smoke.mjs` passes for all configured iterations
- `tests/initiative-smoke.mjs` passes for all configured iterations
- Failure budget: `0` failed loop iterations

4. Evidence artifact produced
- Validation report JSON exists and indicates `summary.success=true`

## Suggested Release Policy

- Merge gate: `validate:production:quick`
- Pre-release gate: `validate:production`
- Release-candidate gate: `validate:production:soak`

## Known Limits of Current Validation

- Does not yet validate VDI computer-use runtime.
- Does not yet validate live meeting-presence stack (STT/WebRTC/TTS loop).
- Does not yet measure long-horizon strategic task quality, only control-plane correctness and resilience.
