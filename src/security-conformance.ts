import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  hmacSha256Hex,
  loadHmacKeyring,
  type HmacKeyring,
  signWithKeyring,
  verifyWithAnyKey,
  verifyWithKeyring,
} from "./hmac-keyring";
import type {
  SecurityInvariantRuntimeState,
  SecurityInvariantSummary,
} from "./security-invariants";
import { stableStringify } from "./utils";

const GENESIS_HASH = "0".repeat(64);

export interface SecurityConformancePayload {
  schema_version: "security-conformance.v1";
  generated_at: string;
  service: "claw-ee";
  code_fingerprint: string;
  invariant_catalog_hash: string;
  summary: SecurityInvariantSummary;
  invariants: SecurityInvariantRuntimeState[];
  runtime: Record<string, unknown>;
  signature: string | null;
  signature_kid: string | null;
}

export interface SecurityConformanceChainEntry {
  sealed_at: string;
  report_path: string;
  report_hash: string;
  previous_hash: string;
  current_hash: string;
  generated_at: string;
  signature: string | null;
  signature_kid: string | null;
}

export interface SecurityConformanceSnapshotVerification {
  valid: boolean;
  reason: string | null;
  signature_valid: boolean | null;
  generated_at: string;
  report_hash: string;
}

export interface SecurityConformanceChainVerification {
  valid: boolean;
  reason: string | null;
  entries: number;
  last_hash: string;
}

function canonicalPayload(input: Omit<SecurityConformancePayload, "signature" | "signature_kid">): string {
  return stableStringify(input);
}

function reportHash(payload: SecurityConformancePayload): string {
  return crypto.createHash("sha256").update(stableStringify(payload)).digest("hex");
}

function sealHash(input: {
  sealedAt: string;
  reportPath: string;
  reportHashValue: string;
  previousHash: string;
  generatedAt: string;
  signature: string | null;
  signatureKid: string | null;
}): string {
  return crypto
    .createHash("sha256")
    .update(
      stableStringify({
        sealed_at: input.sealedAt,
        report_path: input.reportPath,
        report_hash: input.reportHashValue,
        previous_hash: input.previousHash,
        generated_at: input.generatedAt,
        signature: input.signature,
        signature_kid: input.signatureKid,
      }),
    )
    .digest("hex");
}

export class SecurityConformanceService {
  private readonly defaultExportPath: string;
  private readonly codeFingerprint: string;
  private readonly runtimeContext: Record<string, unknown>;
  private signingKey: string;
  private signingKeyringPath: string;
  private signingKeyring: HmacKeyring | null = null;

  constructor(options: {
    defaultExportPath: string;
    codeFingerprint: string;
    runtimeContext: Record<string, unknown>;
    signingKey: string;
    signingKeyringPath?: string;
  }) {
    this.defaultExportPath = options.defaultExportPath;
    this.codeFingerprint = options.codeFingerprint;
    this.runtimeContext = options.runtimeContext;
    this.signingKey = options.signingKey.trim();
    this.signingKeyringPath = (options.signingKeyringPath || "").trim();
    this.reloadSigningKeys();
  }

  reloadSigningKeys(): {
    signing_mode: "none" | "static" | "keyring";
    active_kid: string | null;
    key_count: number;
  } {
    this.signingKeyring = this.signingKeyringPath ? loadHmacKeyring(this.signingKeyringPath) : null;
    return this.getSigningState();
  }

  getSigningState(): {
    signing_mode: "none" | "static" | "keyring";
    active_kid: string | null;
    key_count: number;
  } {
    if (this.signingKeyring) {
      return {
        signing_mode: "keyring",
        active_kid: this.signingKeyring.activeKid,
        key_count: Object.keys(this.signingKeyring.keys).length,
      };
    }
    if (this.signingKey) {
      return {
        signing_mode: "static",
        active_kid: null,
        key_count: 0,
      };
    }
    return {
      signing_mode: "none",
      active_kid: null,
      key_count: 0,
    };
  }

  generate(input: {
    invariantCatalogHash: string;
    summary: SecurityInvariantSummary;
    invariants: SecurityInvariantRuntimeState[];
  }): SecurityConformancePayload {
    const unsignedPayload: Omit<SecurityConformancePayload, "signature" | "signature_kid"> = {
      schema_version: "security-conformance.v1",
      generated_at: new Date().toISOString(),
      service: "claw-ee",
      code_fingerprint: this.codeFingerprint,
      invariant_catalog_hash: input.invariantCatalogHash,
      summary: input.summary,
      invariants: input.invariants,
      runtime: this.runtimeContext,
    };
    const canonical = canonicalPayload(unsignedPayload);
    if (this.signingKeyring) {
      const sig = signWithKeyring(canonical, this.signingKeyring);
      return {
        ...unsignedPayload,
        signature: sig.sig,
        signature_kid: sig.kid,
      };
    }
    if (this.signingKey) {
      return {
        ...unsignedPayload,
        signature: hmacSha256Hex(this.signingKey, canonical),
        signature_kid: null,
      };
    }
    return {
      ...unsignedPayload,
      signature: null,
      signature_kid: null,
    };
  }

  exportSealedSnapshot(
    payload: SecurityConformancePayload,
    options?: { reportPath?: string; chainPath?: string },
  ): {
    report_path: string;
    chain_path: string;
    report_hash: string;
    previous_hash: string;
    current_hash: string;
    generated_at: string;
  } {
    const reportPath = (options?.reportPath || "").trim() || this.defaultExportPath;
    const chainPath = (options?.chainPath || "").trim() || `${reportPath}.chain.jsonl`;
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.mkdirSync(path.dirname(chainPath), { recursive: true });
    fs.writeFileSync(reportPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
    const reportHashValue = reportHash(payload);
    const previousHash = this.readLastChainHash(chainPath);
    const sealedAt = new Date().toISOString();
    const currentHash = sealHash({
      sealedAt,
      reportPath,
      reportHashValue,
      previousHash,
      generatedAt: payload.generated_at,
      signature: payload.signature,
      signatureKid: payload.signature_kid,
    });
    const entry: SecurityConformanceChainEntry = {
      sealed_at: sealedAt,
      report_path: reportPath,
      report_hash: reportHashValue,
      previous_hash: previousHash,
      current_hash: currentHash,
      generated_at: payload.generated_at,
      signature: payload.signature,
      signature_kid: payload.signature_kid,
    };
    fs.appendFileSync(chainPath, `${JSON.stringify(entry)}\n`, "utf8");
    return {
      report_path: reportPath,
      chain_path: chainPath,
      report_hash: reportHashValue,
      previous_hash: previousHash,
      current_hash: currentHash,
      generated_at: payload.generated_at,
    };
  }

  verifySnapshotFile(reportPath: string): SecurityConformanceSnapshotVerification {
    const raw = fs.readFileSync(reportPath, "utf8");
    const payload = JSON.parse(raw) as SecurityConformancePayload;
    const canonical = canonicalPayload({
      schema_version: payload.schema_version,
      generated_at: payload.generated_at,
      service: payload.service,
      code_fingerprint: payload.code_fingerprint,
      invariant_catalog_hash: payload.invariant_catalog_hash,
      summary: payload.summary,
      invariants: payload.invariants,
      runtime: payload.runtime,
    });
    let valid = true;
    let reason: string | null = null;
    let signatureValid: boolean | null = null;
    if (payload.schema_version !== "security-conformance.v1") {
      valid = false;
      reason = "Unsupported schema_version.";
    }
    if (this.signingKeyring) {
      if (payload.signature && payload.signature_kid) {
        signatureValid = verifyWithKeyring(
          canonical,
          {
            kid: payload.signature_kid,
            sig: payload.signature,
          },
          this.signingKeyring,
        );
      } else if (payload.signature) {
        signatureValid = verifyWithAnyKey(canonical, payload.signature, this.signingKeyring).valid;
      } else {
        signatureValid = false;
      }
      if (!signatureValid && valid) {
        valid = false;
        reason = "Conformance signature mismatch (keyring).";
      }
    } else if (this.signingKey) {
      signatureValid = payload.signature === hmacSha256Hex(this.signingKey, canonical);
      if (!signatureValid && valid) {
        valid = false;
        reason = "Conformance signature mismatch.";
      }
    }
    return {
      valid,
      reason,
      signature_valid: signatureValid,
      generated_at: payload.generated_at,
      report_hash: reportHash(payload),
    };
  }

  verifySealedChain(
    chainPath: string,
    options?: { verifySnapshots?: boolean },
  ): SecurityConformanceChainVerification {
    if (!fs.existsSync(chainPath)) {
      return {
        valid: false,
        reason: "Chain file does not exist.",
        entries: 0,
        last_hash: GENESIS_HASH,
      };
    }
    const verifySnapshots = options?.verifySnapshots !== false;
    const lines = fs
      .readFileSync(chainPath, "utf8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    let previous = GENESIS_HASH;
    for (let i = 0; i < lines.length; i += 1) {
      let parsed: SecurityConformanceChainEntry;
      try {
        parsed = JSON.parse(lines[i]) as SecurityConformanceChainEntry;
      } catch {
        return {
          valid: false,
          reason: `Invalid JSON in chain line ${i + 1}.`,
          entries: i,
          last_hash: previous,
        };
      }
      if (parsed.previous_hash !== previous) {
        return {
          valid: false,
          reason: `Chain previous hash mismatch at line ${i + 1}.`,
          entries: i,
          last_hash: previous,
        };
      }
      if (verifySnapshots) {
        if (!fs.existsSync(parsed.report_path)) {
          return {
            valid: false,
            reason: `Report file missing at chain line ${i + 1}.`,
            entries: i,
            last_hash: previous,
          };
        }
        const verification = this.verifySnapshotFile(parsed.report_path);
        if (!verification.valid) {
          return {
            valid: false,
            reason: `Report verification failed at line ${i + 1}: ${verification.reason}`,
            entries: i,
            last_hash: previous,
          };
        }
        if (verification.report_hash !== parsed.report_hash) {
          return {
            valid: false,
            reason: `Report hash mismatch at chain line ${i + 1}.`,
            entries: i,
            last_hash: previous,
          };
        }
        const expectedSeal = sealHash({
          sealedAt: parsed.sealed_at,
          reportPath: parsed.report_path,
          reportHashValue: parsed.report_hash,
          previousHash: parsed.previous_hash,
          generatedAt: parsed.generated_at,
          signature: parsed.signature,
          signatureKid: parsed.signature_kid,
        });
        if (expectedSeal !== parsed.current_hash) {
          return {
            valid: false,
            reason: `Seal hash mismatch at chain line ${i + 1}.`,
            entries: i,
            last_hash: previous,
          };
        }
      }
      previous = parsed.current_hash;
    }
    return {
      valid: true,
      reason: null,
      entries: lines.length,
      last_hash: previous,
    };
  }

  private readLastChainHash(chainPath: string): string {
    if (!fs.existsSync(chainPath)) {
      return GENESIS_HASH;
    }
    const lines = fs
      .readFileSync(chainPath, "utf8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (lines.length === 0) {
      return GENESIS_HASH;
    }
    const parsed = JSON.parse(lines[lines.length - 1]) as Partial<SecurityConformanceChainEntry>;
    const hash = String(parsed.current_hash || "").trim();
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return GENESIS_HASH;
    }
    return hash;
  }
}
