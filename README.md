# Claw-EE

**Claw-EE** is a security and governance add-on (a "sidecar") for OpenClaw. It acts as a protective shield that sits exactly between OpenClaw and the models or tools it interacts with.

## What is this project?

OpenClaw is a powerful AI tool that can execute real, meaningful work. However, when companies want to use AI to work autonomously, they can't just let it run wild. They need strict rules, safety checks, and clear records of everything the AI does. 

Claw-EE solves this problem. It provides an "enterprise control-plane" without needing to alter any of the core code in OpenClaw. Think of it as a strict but helpful manager that oversees the OpenClaw worker. It checks all actions against your company's policies before any real work gets executed.

## Why should you care?

If you want to deploy autonomous AI agents like OpenClaw safely in a business, you need guarantees. Claw-EE prevents the AI from overspending, stops it from executing dangerous commands, protects it against malicious prompts, and records an unchangeable audit trail of its decisions.

Claw-EE gives you the confidence to roll out OpenClaw securely by providing:

- **Enforceable Rules:** Strict policy gates that block risky actions before they happen.
- **Human-in-the-loop Approvals:** Pauses sensitive AI actions until a human reviews and approves them.
- **Budget Circuit Breakers:** Dollar caps (e.g., hourly or daily limits) so the AI doesn't accidentally run up a massive bill.
- **Tamper-Proof Audit Trails:** A clear, verifiable history of exactly what the AI did and why, ensuring accountability.
- **Security & Abuse Protection:** Heavy defenses against unauthorized access and replay attacks.
- **Proactive Work Tasks:** An "Initiative Engine" that lets the AI safely work through queues of tasks (like pulling from Jira or PagerDuty).

## How does it work?

Normally, OpenClaw talks directly to external models and tools. With Claw-EE, the architecture looks like this:

```text
OpenClaw ➔ Claw-EE (Risk/Budget/Approval Safety Gateway) ➔ Upstream Model/Tool
```

---

## Quickstart (10 minutes)

1. Create your environment file:
   ```powershell
   Copy-Item .env.example .env
   ```

2. Set the minimum required values in `.env`:
   - `UPSTREAM_BASE_URL`
   - `INTERNAL_INFERENCE_BASE_URL`
   - `INTERNAL_INFERENCE_API_KEY`
   - `CONTROL_API_TOKEN`
   
   *(Note: Catalog signing keys are required by config and have defaults in `.env.example`. Replace defaults for real deployments.)*

3. Install dependencies and start the gateway:
   ```powershell
   npm install
   npm run build
   npm run start
   ```

4. Verify it's working by running the security smoke checks:
   ```powershell
   npm run smoke:security
   npm run repo:check
   ```
   *(Windows fallback if `npm.ps1` is blocked: `npm.cmd run smoke:security`)*

5. **Optional:** Enable proactive initiative execution in `.env`:
   - `INITIATIVE_ENGINE_ENABLED=true`
   - `INITIATIVE_POLL_SECONDS=15`

---

## Technical Features at a Glance

| What are you worried about? | How Claw-EE fixes it | How to verify it |
| --- | --- | --- |
| **Dangerous tool use** | Risk gates & approval workflows | `/_clawee/control/status`, audit ledger |
| **Abuse & spam** | HMAC validation & replay protection databases | `/_clawee/control/metrics` |
| **Runaway cloud costs** | Economic circuit breakers (`HOURLY_USD_CAP`) | Budget state in metrics |
| **Independent task execution** | The Initiative Engine (task queue, retries) | `/_clawee/control/initiatives*` |
| **Changing AI models** | Signed model registry & policy catalogs | Catalog fingerprints |
| **Lack of accountability** | Hash-chained audits & signed attestations | Attestation export endpoints |

*(For full details on API endpoints, strict CI validation, specialized deployment modes (Local, Enterprise, Air-gapped), and advanced configuration, please refer to the `openapi/` and `docs/` folders in this repository.)*
