# Security Key Rotation Runbook

This runbook rotates signing keys for Claw-EE signed catalogs and attestation/conformance outputs without disabling guardrails.

## Scope

- Control token catalog (`CONTROL_TOKENS_*`)
- Policy catalog (`POLICY_CATALOG_*`)
- Capability catalog (`CAPABILITY_CATALOG_*`)
- Approval policy catalog (`APPROVAL_POLICY_CATALOG_*`)
- Model registry (`MODEL_REGISTRY_*`)
- Attestation/conformance signing (`APPROVAL_ATTESTATION_*`, `AUDIT_ATTESTATION_*`, `SECURITY_CONFORMANCE_*`)

## 1. Prepare keyring file

Create a keyring JSON with old + new keys and set `active_kid` to the new key:

```json
{
  "version": "v1",
  "active_kid": "k2",
  "keys": {
    "k1": "old-secret",
    "k2": "new-secret"
  }
}
```

## 2. Re-sign catalogs with keyring signatures

Use built-in tooling where available:

```powershell
node scripts/security-tools.mjs sign-control-catalog-keyring .\config\control-tokens.v1.example.json .\secrets\control-keyring.json
node scripts/security-tools.mjs sign-capability-catalog-keyring .\config\capability-catalog.v1.json .\secrets\capability-keyring.json
node scripts/security-tools.mjs sign-approval-policy-catalog-keyring .\config\approval-policy-catalog.v1.json .\secrets\approval-policy-keyring.json
```

For policy catalog and model registry, produce `signature_v2` using the same canonical payload logic verified in `tests/security-smoke.mjs`.

## 3. Deploy keyring path + reload

Set/roll keyring environment vars:

- `CONTROL_TOKENS_SIGNING_KEYRING_PATH`
- `POLICY_CATALOG_SIGNING_KEYRING_PATH`
- `CAPABILITY_CATALOG_SIGNING_KEYRING_PATH`
- `APPROVAL_POLICY_CATALOG_SIGNING_KEYRING_PATH`
- `MODEL_REGISTRY_SIGNING_KEYRING_PATH`
- `APPROVAL_ATTESTATION_SIGNING_KEYRING_PATH`
- `AUDIT_ATTESTATION_SIGNING_KEYRING_PATH`
- `SECURITY_CONFORMANCE_SIGNING_KEYRING_PATH`

Reload at runtime (control API):

- `POST /_clawee/control/reload/control-tokens`
- `POST /_clawee/control/reload/policies`
- `POST /_clawee/control/reload/capability-policy`
- `POST /_clawee/control/reload/approval-policy`
- `POST /_clawee/control/reload/model-registry`
- `POST /_clawee/control/reload/approval-attestation-signing`
- `POST /_clawee/control/reload/audit-attestation-signing`
- `POST /_clawee/control/reload/security-conformance-signing`

## 4. Verify post-rotation

- Check `/_clawee/control/status` and confirm signing mode is `keyring` with new `active_kid`.
- Run:

```powershell
npm run smoke:security
npm run repo:check
```

- Verify latest attestation and conformance chains:
  - `POST /_clawee/control/approvals/attestation/verify`
  - `POST /_clawee/control/audit/attestation/verify`
  - `POST /_clawee/control/security/conformance/verify`

## 5. Retire old key

After all nodes accept the new key and verification is green:

1. Remove old key from keyring.
2. Keep `active_kid` on current key.
3. Re-deploy keyring and rerun reload/verification steps.
