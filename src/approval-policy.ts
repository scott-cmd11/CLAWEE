import crypto from "node:crypto";
import fs from "node:fs";
import {
  loadHmacKeyring,
  type HmacKeyring,
  verifyWithAnyKey,
  verifyWithKeyring,
} from "./hmac-keyring";
import type { PolicyDecision } from "./policy-engine";
import { stableStringify } from "./utils";

interface ApprovalRequirementFile {
  required_approvals?: number;
  required_roles?: string[];
}

interface ApprovalPolicyCatalogFile {
  version?: string;
  defaults?: ApprovalRequirementFile;
  risk_class_overrides?: Record<string, ApprovalRequirementFile>;
  tool_overrides?: Record<string, ApprovalRequirementFile>;
  channel_action_overrides?: Record<string, ApprovalRequirementFile>;
  signature?: string;
  signature_v2?: {
    kid: string;
    sig: string;
  };
}

export interface ApprovalRequirement {
  requiredApprovals: number;
  requiredRoles: string[];
}

export interface ApprovalPolicyState {
  version: string;
  fingerprint: string;
  signing_mode: "none" | "static" | "keyring";
  keyring_active_kid: string | null;
  keyring_key_count: number;
}

export interface ApprovalPolicyContext {
  policyDecision: PolicyDecision;
  channel?: string;
  action?: string;
  toolNames?: string[];
}

interface ApprovalPolicyLoadResult {
  version: string;
  fingerprint: string;
  signing_mode: "none" | "static" | "keyring";
  keyring_active_kid: string | null;
  keyring_key_count: number;
  defaults: ApprovalRequirement;
  riskClassOverrides: Map<string, ApprovalRequirement>;
  toolOverrides: Map<string, ApprovalRequirement>;
  channelActionOverrides: Map<string, ApprovalRequirement>;
}

function normalizeRequiredApprovals(value: number | undefined): number {
  const numeric = Number(value ?? 1);
  if (!Number.isFinite(numeric)) {
    return 1;
  }
  return Math.min(5, Math.max(1, Math.floor(numeric)));
}

function normalizeRoles(values: string[] | undefined): string[] {
  const normalized = (values || [])
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  return [...new Set(normalized)].sort();
}

function normalizeRequirement(fileReq: ApprovalRequirementFile | undefined): ApprovalRequirement {
  return {
    requiredApprovals: normalizeRequiredApprovals(fileReq?.required_approvals),
    requiredRoles: normalizeRoles(fileReq?.required_roles),
  };
}

function canonicalPayload(parsed: ApprovalPolicyCatalogFile): {
  version: string;
  defaults: { required_approvals: number; required_roles: string[] };
  risk_class_overrides: Record<string, { required_approvals: number; required_roles: string[] }>;
  tool_overrides: Record<string, { required_approvals: number; required_roles: string[] }>;
  channel_action_overrides: Record<string, { required_approvals: number; required_roles: string[] }>;
} {
  const defaults = normalizeRequirement(parsed.defaults);
  const normalizeMap = (
    source: Record<string, ApprovalRequirementFile> | undefined,
  ): Record<string, { required_approvals: number; required_roles: string[] }> => {
    const out: Record<string, { required_approvals: number; required_roles: string[] }> = {};
    for (const [keyRaw, req] of Object.entries(source || {})) {
      const key = String(keyRaw || "").trim().toLowerCase();
      if (!key) {
        continue;
      }
      const normalized = normalizeRequirement(req);
      out[key] = {
        required_approvals: normalized.requiredApprovals,
        required_roles: normalized.requiredRoles,
      };
    }
    return out;
  };

  return {
    version: String(parsed.version || "v1"),
    defaults: {
      required_approvals: defaults.requiredApprovals,
      required_roles: defaults.requiredRoles,
    },
    risk_class_overrides: normalizeMap(parsed.risk_class_overrides),
    tool_overrides: normalizeMap(parsed.tool_overrides),
    channel_action_overrides: normalizeMap(parsed.channel_action_overrides),
  };
}

function verifySignature(
  parsed: ApprovalPolicyCatalogFile,
  canonicalText: string,
  signingKey: string,
  keyring: HmacKeyring | null,
): {
  signing_mode: "none" | "static" | "keyring";
  keyring_active_kid: string | null;
  keyring_key_count: number;
} {
  if (keyring) {
    if (parsed.signature_v2 && typeof parsed.signature_v2 === "object") {
      const ok = verifyWithKeyring(canonicalText, parsed.signature_v2, keyring);
      if (!ok) {
        throw new Error("Approval policy signature_v2 mismatch.");
      }
    } else {
      const signature = String(parsed.signature || "").trim().toLowerCase();
      if (!signature) {
        throw new Error("Approval policy signature missing for keyring verification.");
      }
      const legacy = verifyWithAnyKey(canonicalText, signature, keyring);
      if (!legacy.valid) {
        throw new Error("Approval policy legacy signature mismatch under keyring.");
      }
    }
    return {
      signing_mode: "keyring",
      keyring_active_kid: keyring.activeKid,
      keyring_key_count: Object.keys(keyring.keys).length,
    };
  }
  if (!signingKey.trim()) {
    return {
      signing_mode: "none",
      keyring_active_kid: null,
      keyring_key_count: 0,
    };
  }
  const signature = String(parsed.signature || "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(signature)) {
    throw new Error("Approval policy signature missing or invalid format.");
  }
  const expected = crypto
    .createHmac("sha256", signingKey.trim())
    .update(canonicalText)
    .digest("hex");
  if (signature !== expected) {
    throw new Error("Approval policy signature mismatch.");
  }
  return {
    signing_mode: "static",
    keyring_active_kid: null,
    keyring_key_count: 0,
  };
}

export function loadSignedApprovalPolicyCatalog(
  catalogPath: string,
  signingKey: string,
  signingKeyringPath = "",
): ApprovalPolicyLoadResult {
  const raw = fs.readFileSync(catalogPath, "utf8");
  const parsed = JSON.parse(raw) as ApprovalPolicyCatalogFile;
  const canonical = canonicalPayload(parsed);
  const canonicalText = stableStringify(canonical);
  const keyring = signingKeyringPath.trim() ? loadHmacKeyring(signingKeyringPath.trim()) : null;
  const signatureState = verifySignature(parsed, canonicalText, signingKey, keyring);
  const toMap = (
    source: Record<string, { required_approvals: number; required_roles: string[] }>,
  ): Map<string, ApprovalRequirement> => {
    const out = new Map<string, ApprovalRequirement>();
    for (const [key, value] of Object.entries(source)) {
      out.set(key, {
        requiredApprovals: normalizeRequiredApprovals(value.required_approvals),
        requiredRoles: normalizeRoles(value.required_roles),
      });
    }
    return out;
  };

  return {
    version: canonical.version,
    fingerprint: crypto.createHash("sha256").update(canonicalText).digest("hex"),
    signing_mode: signatureState.signing_mode,
    keyring_active_kid: signatureState.keyring_active_kid,
    keyring_key_count: signatureState.keyring_key_count,
    defaults: {
      requiredApprovals: canonical.defaults.required_approvals,
      requiredRoles: canonical.defaults.required_roles,
    },
    riskClassOverrides: toMap(canonical.risk_class_overrides),
    toolOverrides: toMap(canonical.tool_overrides),
    channelActionOverrides: toMap(canonical.channel_action_overrides),
  };
}

export class ApprovalPolicyEngine {
  private state: ApprovalPolicyState = {
    version: "v1",
    fingerprint: "",
    signing_mode: "none",
    keyring_active_kid: null,
    keyring_key_count: 0,
  };

  private defaults: ApprovalRequirement = {
    requiredApprovals: 1,
    requiredRoles: [],
  };
  private riskClassOverrides = new Map<string, ApprovalRequirement>();
  private toolOverrides = new Map<string, ApprovalRequirement>();
  private channelActionOverrides = new Map<string, ApprovalRequirement>();

  updateRules(loaded: ApprovalPolicyLoadResult): void {
    this.state = {
      version: loaded.version,
      fingerprint: loaded.fingerprint,
      signing_mode: loaded.signing_mode,
      keyring_active_kid: loaded.keyring_active_kid,
      keyring_key_count: loaded.keyring_key_count,
    };
    this.defaults = { ...loaded.defaults };
    this.riskClassOverrides = new Map(loaded.riskClassOverrides);
    this.toolOverrides = new Map(loaded.toolOverrides);
    this.channelActionOverrides = new Map(loaded.channelActionOverrides);
  }

  getState(): ApprovalPolicyState {
    return { ...this.state };
  }

  evaluate(context: ApprovalPolicyContext): ApprovalRequirement {
    const merged: ApprovalRequirement = {
      requiredApprovals: this.defaults.requiredApprovals,
      requiredRoles: [...this.defaults.requiredRoles],
    };
    const mergeIn = (req: ApprovalRequirement | undefined) => {
      if (!req) {
        return;
      }
      merged.requiredApprovals = Math.max(merged.requiredApprovals, req.requiredApprovals);
      merged.requiredRoles = [...new Set([...merged.requiredRoles, ...req.requiredRoles])].sort();
    };

    const riskClass = context.policyDecision.riskClass.toLowerCase();
    mergeIn(this.riskClassOverrides.get(riskClass));
    for (const toolRaw of context.toolNames || []) {
      const tool = String(toolRaw || "").trim().toLowerCase();
      if (!tool) {
        continue;
      }
      mergeIn(this.toolOverrides.get(tool));
    }
    const channel = String(context.channel || "").trim().toLowerCase();
    const action = String(context.action || "").trim().toLowerCase();
    if (channel && action) {
      mergeIn(this.channelActionOverrides.get(`${channel}:${action}`));
    }

    return {
      requiredApprovals: normalizeRequiredApprovals(merged.requiredApprovals),
      requiredRoles: normalizeRoles(merged.requiredRoles),
    };
  }
}
