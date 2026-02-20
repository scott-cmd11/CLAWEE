import crypto from "node:crypto";
import fs from "node:fs";
import {
  loadHmacKeyring,
  type HmacKeyring,
  verifyWithAnyKey,
  verifyWithKeyring,
} from "./hmac-keyring";

export type ModelModality = "text" | "vision" | "audio" | "safety" | "embedding";

export interface ModelRegistryEntry {
  model_id: string;
  modality: ModelModality;
  artifact_digest: string;
  approved: boolean;
  valid_from?: string;
  valid_to?: string;
  signature: string;
  signature_v2?: {
    kid: string;
    sig: string;
  };
}

interface ModelRegistryFile {
  version: string;
  entries: ModelRegistryEntry[];
}

export interface ModelPolicyResult {
  allowed: boolean;
  reason: string;
}

function stablePayload(entry: Omit<ModelRegistryEntry, "signature">): string {
  return JSON.stringify({
    model_id: entry.model_id,
    modality: entry.modality,
    artifact_digest: entry.artifact_digest,
    approved: entry.approved,
    valid_from: entry.valid_from || "",
    valid_to: entry.valid_to || "",
  });
}

function signPayload(payload: string, signingKey: string): string {
  return crypto.createHmac("sha256", signingKey).update(payload).digest("hex");
}

function nowIso(): string {
  return new Date().toISOString();
}

export class ModelRegistry {
  private filePath: string;
  private signingKey: string;
  private signingKeyringPath: string;
  private signingKeyring: HmacKeyring | null = null;
  private entries = new Map<string, ModelRegistryEntry[]>();
  private registryFingerprint = "";

  constructor(filePath: string, signingKey: string, signingKeyringPath = "") {
    this.filePath = filePath;
    this.signingKey = signingKey;
    this.signingKeyringPath = signingKeyringPath.trim();
  }

  init(): void {
    this.signingKeyring = this.signingKeyringPath
      ? loadHmacKeyring(this.signingKeyringPath)
      : null;
    const raw = fs.readFileSync(this.filePath, "utf8");
    const parsed = JSON.parse(raw) as ModelRegistryFile;

    if (!Array.isArray(parsed.entries) || parsed.entries.length === 0) {
      throw new Error("Model registry has no entries.");
    }

    this.entries.clear();
    const canonicalForFingerprint: Array<Omit<ModelRegistryEntry, "signature">> = [];

    for (const entry of parsed.entries) {
      this.validateEntry(entry);
      this.validateSignature(entry);
      canonicalForFingerprint.push({
        model_id: entry.model_id,
        modality: entry.modality,
        artifact_digest: entry.artifact_digest,
        approved: entry.approved,
        valid_from: entry.valid_from,
        valid_to: entry.valid_to,
      });
      const key = entry.model_id.trim().toLowerCase();
      const existing = this.entries.get(key) || [];
      existing.push(entry);
      this.entries.set(key, existing);
    }

    const canonical = JSON.stringify(
      canonicalForFingerprint.sort((a, b) => {
        const left = `${a.model_id}:${a.modality}:${a.artifact_digest}`;
        const right = `${b.model_id}:${b.modality}:${b.artifact_digest}`;
        return left.localeCompare(right);
      }),
    );
    this.registryFingerprint = crypto.createHash("sha256").update(canonical).digest("hex");
  }

  getFingerprint(): string {
    return this.registryFingerprint;
  }

  assertAllowed(modelId: string, modality: ModelModality): void {
    const result = this.evaluate(modelId, modality);
    if (!result.allowed) {
      throw new Error(result.reason);
    }
  }

  evaluate(modelId: string, modality: ModelModality): ModelPolicyResult {
    const key = modelId.trim().toLowerCase();
    const now = nowIso();
    const candidates = [...(this.entries.get(key) || []), ...(this.entries.get("*") || [])];

    if (candidates.length === 0) {
      return {
        allowed: false,
        reason: `Model "${modelId}" is not present in registry.`,
      };
    }

    const matchingModality = candidates.filter((entry) => entry.modality === modality);
    if (matchingModality.length === 0) {
      return {
        allowed: false,
        reason: `Model "${modelId}" is not approved for modality "${modality}".`,
      };
    }

    for (const entry of matchingModality) {
      if (!entry.approved) {
        continue;
      }
      if (entry.valid_from && now < entry.valid_from) {
        continue;
      }
      if (entry.valid_to && now > entry.valid_to) {
        continue;
      }
      return {
        allowed: true,
        reason: "Approved model entry matched.",
      };
    }

    return {
      allowed: false,
      reason: `Model "${modelId}" has no currently valid approved entry for modality "${modality}".`,
    };
  }

  private validateEntry(entry: ModelRegistryEntry): void {
    if (!entry.model_id || !entry.model_id.trim()) {
      throw new Error("Registry entry missing model_id.");
    }
    if (!entry.modality || !entry.modality.trim()) {
      throw new Error(`Registry entry "${entry.model_id}" missing modality.`);
    }
    if (!entry.artifact_digest || !entry.artifact_digest.trim()) {
      throw new Error(`Registry entry "${entry.model_id}" missing artifact_digest.`);
    }
    if ((!entry.signature || !entry.signature.trim()) && !entry.signature_v2) {
      throw new Error(`Registry entry "${entry.model_id}" missing signature.`);
    }
  }

  private validateSignature(entry: ModelRegistryEntry): void {
    const payload = stablePayload({
      model_id: entry.model_id,
      modality: entry.modality,
      artifact_digest: entry.artifact_digest,
      approved: entry.approved,
      valid_from: entry.valid_from,
      valid_to: entry.valid_to,
    });
    if (this.signingKeyring) {
      if (entry.signature_v2 && typeof entry.signature_v2 === "object") {
        const ok = verifyWithKeyring(payload, entry.signature_v2, this.signingKeyring);
        if (!ok) {
          throw new Error(
            `Registry signature_v2 mismatch for model "${entry.model_id}" (${entry.modality}).`,
          );
        }
        return;
      }
      const legacy = verifyWithAnyKey(payload, entry.signature, this.signingKeyring);
      if (!legacy.valid) {
        throw new Error(
          `Registry legacy signature mismatch under keyring for model "${entry.model_id}" (${entry.modality}).`,
        );
      }
      return;
    }

    const expected = signPayload(payload, this.signingKey);
    if (expected !== entry.signature) {
      throw new Error(
        `Registry signature mismatch for model "${entry.model_id}" (${entry.modality}).`,
      );
    }
  }
}
