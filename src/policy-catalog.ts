import crypto from "node:crypto";
import fs from "node:fs";
import {
  loadHmacKeyring,
  type HmacKeyring,
  verifyWithAnyKey,
  verifyWithKeyring,
} from "./hmac-keyring";
import type { PolicyEngineOptions } from "./policy-engine";
import { stableStringify } from "./utils";

interface PolicyCatalogFile {
  version: string;
  high_risk_tools: string[];
  critical_patterns: string[];
  high_risk_patterns: string[];
  signature?: string;
  signature_v2?: {
    kid: string;
    sig: string;
  };
}

function normalize(values: string[]): string[] {
  return values.map((value) => value.trim()).filter(Boolean);
}

export interface PolicyCatalogLoadResult {
  policyOptions: PolicyEngineOptions;
  fingerprint: string;
}

export function loadSignedPolicyCatalog(
  pathValue: string,
  signingKey: string,
  signingKeyringPath = "",
): PolicyCatalogLoadResult {
  const raw = fs.readFileSync(pathValue, "utf8");
  const parsed = JSON.parse(raw) as PolicyCatalogFile;

  const canonicalPayload = {
    version: parsed.version,
    high_risk_tools: normalize(parsed.high_risk_tools || []),
    critical_patterns: normalize(parsed.critical_patterns || []),
    high_risk_patterns: normalize(parsed.high_risk_patterns || []),
  };
  const canonicalText = stableStringify(canonicalPayload);

  let keyring: HmacKeyring | null = null;
  if (signingKeyringPath.trim()) {
    keyring = loadHmacKeyring(signingKeyringPath.trim());
  }
  if (keyring) {
    if (parsed.signature_v2 && typeof parsed.signature_v2 === "object") {
      const ok = verifyWithKeyring(canonicalText, parsed.signature_v2, keyring);
      if (!ok) {
        throw new Error("Policy catalog signature_v2 mismatch.");
      }
    } else {
      if (!parsed.signature || !parsed.signature.trim()) {
        throw new Error("Policy catalog signature missing for keyring verification.");
      }
      const legacy = verifyWithAnyKey(canonicalText, parsed.signature, keyring);
      if (!legacy.valid) {
        throw new Error("Policy catalog legacy signature mismatch under keyring.");
      }
    }
  } else {
    if (!parsed.signature || !parsed.signature.trim()) {
      throw new Error("Policy catalog signature missing.");
    }
    const expectedSignature = crypto
      .createHmac("sha256", signingKey)
      .update(canonicalText)
      .digest("hex");

    if (expectedSignature !== parsed.signature) {
      throw new Error("Policy catalog signature mismatch.");
    }
  }

  const fingerprint = crypto
    .createHash("sha256")
    .update(canonicalText)
    .digest("hex");

  return {
    policyOptions: {
      highRiskTools: canonicalPayload.high_risk_tools,
      criticalPatterns: canonicalPayload.critical_patterns,
      highRiskPatterns: canonicalPayload.high_risk_patterns,
    },
    fingerprint,
  };
}
