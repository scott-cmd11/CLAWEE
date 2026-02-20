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
import type { ApprovalRecord, ApprovalService } from "./approval-service";
import { stableStringify } from "./utils";

const GENESIS_HASH = "0".repeat(64);

export interface ApprovalAttestationEntry {
  id: string;
  created_at: string;
  expires_at: string;
  status: string;
  required_approvals: number;
  max_uses: number;
  use_count: number;
  last_used_at: string | null;
  approval_actors: string[];
  required_roles: string[];
  approval_actor_roles: Record<string, string>;
  request_fingerprint: string;
  reason: string;
  resolved_by: string | null;
  resolved_at: string | null;
  metadata: unknown;
  previous_hash: string;
  entry_hash: string;
}

export interface ApprovalAttestationPayload {
  generated_at: string;
  since: string | null;
  count: number;
  entries: ApprovalAttestationEntry[];
  final_hash: string;
  signature: string | null;
  signature_kid: string | null;
}

export interface ApprovalAttestationSealEntry {
  sealed_at: string;
  snapshot_path: string;
  payload_hash: string;
  previous_snapshot_hash: string;
  current_snapshot_hash: string;
  count: number;
  final_hash: string;
  signature: string | null;
  signature_kid: string | null;
}

export interface ApprovalAttestationVerification {
  valid: boolean;
  reason: string | null;
  count: number;
  computed_final_hash: string;
  stored_final_hash: string;
  signature_valid: boolean | null;
  payload_hash: string;
  generated_at: string;
}

export interface ApprovalAttestationChainVerification {
  valid: boolean;
  reason: string | null;
  entries: number;
  last_snapshot_hash: string;
}

function parseMetadata(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return { parse_error: true, raw };
  }
}

function parseApprovalActors(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map((value) => String(value || "").trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function parseRequiredRoles(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean)
      .sort();
  } catch {
    return [];
  }
}

function parseApprovalActorRoles(raw: string): Record<string, string> {
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    const out: Record<string, string> = {};
    for (const [actor, role] of Object.entries(parsed as Record<string, unknown>)) {
      const actorKey = String(actor || "").trim();
      const roleValue = String(role || "").trim().toLowerCase();
      if (!actorKey || !roleValue) {
        continue;
      }
      out[actorKey] = roleValue;
    }
    return out;
  } catch {
    return {};
  }
}

function normalizeRequiredApprovals(value: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 1;
  }
  return Math.min(5, Math.max(1, Math.floor(numeric)));
}

function normalizeMaxUses(value: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 1;
  }
  return Math.min(100, Math.max(1, Math.floor(numeric)));
}

function normalizeUseCount(value: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0;
  }
  return Math.max(0, Math.floor(numeric));
}

function entryHash(input: {
  previousHash: string;
  record: ApprovalRecord;
  metadata: unknown;
}): string {
  return crypto
    .createHash("sha256")
    .update(
      stableStringify({
        previous_hash: input.previousHash,
        id: input.record.id,
        created_at: input.record.created_at,
        expires_at: input.record.expires_at,
        status: input.record.status,
        required_approvals: normalizeRequiredApprovals(input.record.required_approvals),
        max_uses: normalizeMaxUses(input.record.max_uses),
        use_count: normalizeUseCount(input.record.use_count),
        last_used_at: input.record.last_used_at,
        approval_actors: parseApprovalActors(input.record.approval_actors),
        required_roles: parseRequiredRoles(input.record.required_roles),
        approval_actor_roles: parseApprovalActorRoles(input.record.approval_actor_roles),
        request_fingerprint: input.record.request_fingerprint,
        reason: input.record.reason,
        resolved_by: input.record.resolved_by,
        resolved_at: input.record.resolved_at,
        metadata: input.metadata,
      }),
    )
    .digest("hex");
}

function payloadHash(payload: ApprovalAttestationPayload): string {
  return crypto.createHash("sha256").update(stableStringify(payload)).digest("hex");
}

function sealHash(input: {
  sealedAt: string;
  snapshotPath: string;
  payloadHashValue: string;
  previousSnapshotHash: string;
  count: number;
  finalHash: string;
  signature: string | null;
  signatureKid: string | null;
  generatedAt: string;
}): string {
  return crypto
    .createHash("sha256")
    .update(
      stableStringify({
        sealed_at: input.sealedAt,
        snapshot_path: input.snapshotPath,
        payload_hash: input.payloadHashValue,
        previous_snapshot_hash: input.previousSnapshotHash,
        count: input.count,
        final_hash: input.finalHash,
        signature: input.signature,
        signature_kid: input.signatureKid,
        generated_at: input.generatedAt,
      }),
    )
    .digest("hex");
}

export class ApprovalAttestationService {
  private approvalService: ApprovalService;
  private defaultExportPath: string;
  private signingKey: string;
  private signingKeyringPath: string;
  private signingKeyring: HmacKeyring | null = null;

  constructor(
    approvalService: ApprovalService,
    defaultExportPath: string,
    signingKey: string,
    signingKeyringPath = "",
  ) {
    this.approvalService = approvalService;
    this.defaultExportPath = defaultExportPath;
    this.signingKey = signingKey.trim();
    this.signingKeyringPath = signingKeyringPath.trim();
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

  generate(limit = 1000, since = ""): ApprovalAttestationPayload {
    const rows = this.approvalService.listForAttestation(limit, since);
    let previousHash = GENESIS_HASH;
    const entries: ApprovalAttestationEntry[] = [];

    for (const row of rows) {
      const metadata = parseMetadata(row.metadata);
      const hash = entryHash({
        previousHash,
        record: row,
        metadata,
      });
      const entry: ApprovalAttestationEntry = {
        id: row.id,
        created_at: row.created_at,
        expires_at: row.expires_at,
        status: row.status,
        required_approvals: normalizeRequiredApprovals(row.required_approvals),
        max_uses: normalizeMaxUses(row.max_uses),
        use_count: normalizeUseCount(row.use_count),
        last_used_at: row.last_used_at,
        approval_actors: parseApprovalActors(row.approval_actors),
        required_roles: parseRequiredRoles(row.required_roles),
        approval_actor_roles: parseApprovalActorRoles(row.approval_actor_roles),
        request_fingerprint: row.request_fingerprint,
        reason: row.reason,
        resolved_by: row.resolved_by,
        resolved_at: row.resolved_at,
        metadata,
        previous_hash: previousHash,
        entry_hash: hash,
      };
      entries.push(entry);
      previousHash = hash;
    }

    const unsigned: ApprovalAttestationPayload = {
      generated_at: new Date().toISOString(),
      since: since.trim() || null,
      count: entries.length,
      entries,
      final_hash: previousHash,
      signature: null,
      signature_kid: null,
    };

    const canonical = stableStringify({
      generated_at: unsigned.generated_at,
      since: unsigned.since,
      count: unsigned.count,
      entries: unsigned.entries,
      final_hash: unsigned.final_hash,
    });

    if (this.signingKeyring) {
      const v2 = signWithKeyring(canonical, this.signingKeyring);
      return {
        ...unsigned,
        signature: v2.sig,
        signature_kid: v2.kid,
      };
    }
    if (this.signingKey) {
      return {
        ...unsigned,
        signature: hmacSha256Hex(this.signingKey, canonical),
        signature_kid: null,
      };
    }
    return unsigned;
  }

  exportToFile(options?: { path?: string; limit?: number; since?: string }): {
    output_path: string;
    count: number;
    final_hash: string;
    signature: string | null;
    signature_kid: string | null;
  } {
    const outPath = (options?.path || "").trim() || this.defaultExportPath;
    const payload = this.generate(options?.limit ?? 1000, options?.since ?? "");
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
    return {
      output_path: outPath,
      count: payload.count,
      final_hash: payload.final_hash,
      signature: payload.signature,
      signature_kid: payload.signature_kid,
    };
  }

  exportSealedSnapshot(options?: {
    snapshotPath?: string;
    chainPath?: string;
    limit?: number;
    since?: string;
  }): {
    snapshot_path: string;
    chain_path: string;
    count: number;
    final_hash: string;
    signature: string | null;
    signature_kid: string | null;
    current_snapshot_hash: string;
    previous_snapshot_hash: string;
    payload_hash: string;
    generated_at: string;
  } {
    const snapshotPath = (options?.snapshotPath || "").trim() || this.defaultExportPath;
    const chainPath = (options?.chainPath || "").trim() || `${snapshotPath}.chain.jsonl`;
    const payload = this.generate(options?.limit ?? 1000, options?.since ?? "");

    fs.mkdirSync(path.dirname(snapshotPath), { recursive: true });
    fs.mkdirSync(path.dirname(chainPath), { recursive: true });
    fs.writeFileSync(snapshotPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

    const payloadHashValue = payloadHash(payload);
    const previousSnapshotHash = this.readLastSnapshotHash(chainPath);
    const sealedAt = new Date().toISOString();
    const currentSnapshotHash = sealHash({
      sealedAt,
      snapshotPath,
      payloadHashValue,
      previousSnapshotHash,
      count: payload.count,
      finalHash: payload.final_hash,
      signature: payload.signature,
      signatureKid: payload.signature_kid,
      generatedAt: payload.generated_at,
    });

    const sealEntry: ApprovalAttestationSealEntry = {
      sealed_at: sealedAt,
      snapshot_path: snapshotPath,
      payload_hash: payloadHashValue,
      previous_snapshot_hash: previousSnapshotHash,
      current_snapshot_hash: currentSnapshotHash,
      count: payload.count,
      final_hash: payload.final_hash,
      signature: payload.signature,
      signature_kid: payload.signature_kid,
    };
    fs.appendFileSync(chainPath, `${JSON.stringify(sealEntry)}\n`, "utf8");

    return {
      snapshot_path: snapshotPath,
      chain_path: chainPath,
      count: payload.count,
      final_hash: payload.final_hash,
      signature: payload.signature,
      signature_kid: payload.signature_kid,
      current_snapshot_hash: currentSnapshotHash,
      previous_snapshot_hash: previousSnapshotHash,
      payload_hash: payloadHashValue,
      generated_at: payload.generated_at,
    };
  }

  verifyPayload(payload: ApprovalAttestationPayload): ApprovalAttestationVerification {
    let previousHash = GENESIS_HASH;
    let reason: string | null = null;
    let valid = true;

    if (!Array.isArray(payload.entries)) {
      valid = false;
      reason = "Payload entries must be an array.";
    }

    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    if (valid && payload.count !== entries.length) {
      valid = false;
      reason = "Payload count does not match entries length.";
    }

    for (const entry of entries) {
      if (!valid) {
        break;
      }
      if (entry.previous_hash !== previousHash) {
        valid = false;
        reason = "Entry previous_hash mismatch.";
        break;
      }
      const expected = entryHash({
        previousHash,
        record: {
          id: entry.id,
          created_at: entry.created_at,
          expires_at: entry.expires_at,
          status: entry.status as ApprovalRecord["status"],
          required_approvals: normalizeRequiredApprovals(
            Number((entry as Partial<ApprovalAttestationEntry>).required_approvals ?? 1),
          ),
          max_uses: normalizeMaxUses(
            Number((entry as Partial<ApprovalAttestationEntry>).max_uses ?? 1),
          ),
          use_count: normalizeUseCount(
            Number((entry as Partial<ApprovalAttestationEntry>).use_count ?? 0),
          ),
          last_used_at:
            (entry as Partial<ApprovalAttestationEntry>).last_used_at == null
              ? null
              : String((entry as Partial<ApprovalAttestationEntry>).last_used_at),
          required_roles: JSON.stringify(
            Array.isArray((entry as Partial<ApprovalAttestationEntry>).required_roles)
              ? (entry as Partial<ApprovalAttestationEntry>).required_roles
              : [],
          ),
          approval_actors: JSON.stringify(
            Array.isArray((entry as Partial<ApprovalAttestationEntry>).approval_actors)
              ? (entry as Partial<ApprovalAttestationEntry>).approval_actors
              : [],
          ),
          approval_actor_roles: JSON.stringify(
            (entry as Partial<ApprovalAttestationEntry>).approval_actor_roles &&
              typeof (entry as Partial<ApprovalAttestationEntry>).approval_actor_roles === "object"
              ? (entry as Partial<ApprovalAttestationEntry>).approval_actor_roles
              : {},
          ),
          request_fingerprint: entry.request_fingerprint,
          reason: entry.reason,
          metadata: JSON.stringify(entry.metadata ?? {}),
          resolved_by: entry.resolved_by,
          resolved_at: entry.resolved_at,
        },
        metadata: entry.metadata,
      });
      if (expected !== entry.entry_hash) {
        valid = false;
        reason = "Entry hash mismatch.";
        break;
      }
      previousHash = entry.entry_hash;
    }

    if (valid && payload.final_hash !== previousHash) {
      valid = false;
      reason = "Final hash mismatch.";
    }

    let signatureValid: boolean | null = null;
    const canonical = stableStringify({
      generated_at: payload.generated_at,
      since: payload.since,
      count: payload.count,
      entries: payload.entries,
      final_hash: payload.final_hash,
    });
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
      } else if (payload.signature && !payload.signature_kid) {
        signatureValid = verifyWithAnyKey(canonical, payload.signature, this.signingKeyring).valid;
      } else {
        signatureValid = false;
      }
      if (!signatureValid && valid) {
        valid = false;
        reason = "Attestation keyring signature mismatch.";
      }
    } else if (this.signingKey) {
      const expectedSignature = hmacSha256Hex(this.signingKey, canonical);
      signatureValid = payload.signature === expectedSignature;
      if (!signatureValid && valid) {
        valid = false;
        reason = "Attestation signature mismatch.";
      }
    }

    return {
      valid,
      reason,
      count: entries.length,
      computed_final_hash: previousHash,
      stored_final_hash: payload.final_hash,
      signature_valid: signatureValid,
      payload_hash: payloadHash(payload),
      generated_at: payload.generated_at,
    };
  }

  verifySnapshotFile(snapshotPath: string): ApprovalAttestationVerification {
    const raw = fs.readFileSync(snapshotPath, "utf8");
    const payload = JSON.parse(raw) as ApprovalAttestationPayload;
    return this.verifyPayload(payload);
  }

  verifySealedChain(
    chainPath: string,
    options?: { verifySnapshots?: boolean },
  ): ApprovalAttestationChainVerification {
    if (!fs.existsSync(chainPath)) {
      return {
        valid: false,
        reason: "Chain file does not exist.",
        entries: 0,
        last_snapshot_hash: GENESIS_HASH,
      };
    }

    const verifySnapshots = options?.verifySnapshots !== false;
    const raw = fs.readFileSync(chainPath, "utf8");
    const lines = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    let previous = GENESIS_HASH;
    for (let i = 0; i < lines.length; i += 1) {
      let parsed: ApprovalAttestationSealEntry;
      try {
        parsed = JSON.parse(lines[i]) as ApprovalAttestationSealEntry;
      } catch {
        return {
          valid: false,
          reason: `Invalid JSON in chain line ${i + 1}.`,
          entries: i,
          last_snapshot_hash: previous,
        };
      }

      if (parsed.previous_snapshot_hash !== previous) {
        return {
          valid: false,
          reason: `Chain previous hash mismatch at line ${i + 1}.`,
          entries: i,
          last_snapshot_hash: previous,
        };
      }

      if (verifySnapshots) {
        if (!fs.existsSync(parsed.snapshot_path)) {
          return {
            valid: false,
            reason: `Snapshot file missing for chain line ${i + 1}.`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
        const snapshotRaw = fs.readFileSync(parsed.snapshot_path, "utf8");
        const snapshotPayload = JSON.parse(snapshotRaw) as ApprovalAttestationPayload;
        const verification = this.verifyPayload(snapshotPayload);
        if (!verification.valid) {
          return {
            valid: false,
            reason: `Snapshot verification failed at line ${i + 1}: ${verification.reason}`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
        if (verification.payload_hash !== parsed.payload_hash) {
          return {
            valid: false,
            reason: `Payload hash mismatch at chain line ${i + 1}.`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
        const expectedSealHash = sealHash({
          sealedAt: parsed.sealed_at,
          snapshotPath: parsed.snapshot_path,
          payloadHashValue: parsed.payload_hash,
          previousSnapshotHash: parsed.previous_snapshot_hash,
          count: parsed.count,
          finalHash: parsed.final_hash,
          signature: parsed.signature,
          signatureKid: parsed.signature_kid,
          generatedAt: verification.generated_at,
        });
        if (expectedSealHash !== parsed.current_snapshot_hash) {
          return {
            valid: false,
            reason: `Seal hash mismatch at chain line ${i + 1}.`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
      }

      previous = parsed.current_snapshot_hash;
    }

    return {
      valid: true,
      reason: null,
      entries: lines.length,
      last_snapshot_hash: previous,
    };
  }

  private readLastSnapshotHash(chainPath: string): string {
    if (!fs.existsSync(chainPath)) {
      return GENESIS_HASH;
    }
    const raw = fs.readFileSync(chainPath, "utf8");
    const lines = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (lines.length === 0) {
      return GENESIS_HASH;
    }
    const last = JSON.parse(lines[lines.length - 1]) as Partial<ApprovalAttestationSealEntry>;
    const hash = String(last.current_snapshot_hash || "").trim();
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return GENESIS_HASH;
    }
    return hash;
  }
}
