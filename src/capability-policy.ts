import crypto from "node:crypto";
import fs from "node:fs";
import {
  loadHmacKeyring,
  type HmacKeyring,
  verifyWithAnyKey,
  verifyWithKeyring,
} from "./hmac-keyring";
import { stableStringify } from "./utils";

export type CapabilityMode = "allow" | "deny";
export type CapabilityAction = "tool.execute" | "channel.ingest" | "channel.send";

interface CapabilityRuleFile {
  mode?: string;
  allow_tools?: string[];
  deny_tools?: string[];
  allow_actions?: string[];
  deny_actions?: string[];
}

interface CapabilityCatalogFile {
  version?: string;
  defaults?: CapabilityRuleFile;
  channels?: Record<string, CapabilityRuleFile>;
  signature?: string;
  signature_v2?: {
    kid: string;
    sig: string;
  };
}

export interface CapabilityRules {
  mode: CapabilityMode;
  allowTools: string[];
  denyTools: string[];
  allowActions: string[];
  denyActions: string[];
}

export interface CapabilityCatalogLoadResult {
  version: string;
  defaults: CapabilityRules;
  channels: Record<string, CapabilityRules>;
  fingerprint: string;
  signing_mode: "none" | "static" | "keyring";
  keyring_active_kid: string | null;
  keyring_key_count: number;
}

export interface CapabilityDecision {
  allowed: boolean;
  reason: string;
  matchedSignals: string[];
}

const DEFAULT_RULES: CapabilityRules = {
  mode: "allow",
  allowTools: [],
  denyTools: [],
  allowActions: [],
  denyActions: [],
};

function normalizeMode(value: string | undefined): CapabilityMode {
  return String(value || "").trim().toLowerCase() === "deny" ? "deny" : "allow";
}

function normalizeList(values: string[] | undefined): string[] {
  const uniq = new Set<string>();
  for (const value of values || []) {
    const normalized = String(value || "").trim().toLowerCase();
    if (!normalized) {
      continue;
    }
    uniq.add(normalized);
  }
  return [...uniq].sort();
}

function normalizeRules(fileRules: CapabilityRuleFile | undefined): CapabilityRules {
  if (!fileRules || typeof fileRules !== "object") {
    return { ...DEFAULT_RULES };
  }
  return {
    mode: normalizeMode(fileRules.mode),
    allowTools: normalizeList(fileRules.allow_tools),
    denyTools: normalizeList(fileRules.deny_tools),
    allowActions: normalizeList(fileRules.allow_actions),
    denyActions: normalizeList(fileRules.deny_actions),
  };
}

function canonicalPayload(parsed: CapabilityCatalogFile): {
  version: string;
  defaults: {
    mode: CapabilityMode;
    allow_tools: string[];
    deny_tools: string[];
    allow_actions: string[];
    deny_actions: string[];
  };
  channels: Record<
    string,
    {
      mode: CapabilityMode;
      allow_tools: string[];
      deny_tools: string[];
      allow_actions: string[];
      deny_actions: string[];
    }
  >;
} {
  const defaults = normalizeRules(parsed.defaults);
  const channels: Record<
    string,
    {
      mode: CapabilityMode;
      allow_tools: string[];
      deny_tools: string[];
      allow_actions: string[];
      deny_actions: string[];
    }
  > = {};
  for (const [channelRaw, channelRules] of Object.entries(parsed.channels || {})) {
    const channel = String(channelRaw || "").trim().toLowerCase();
    if (!channel) {
      continue;
    }
    const normalized = normalizeRules(channelRules);
    channels[channel] = {
      mode: normalized.mode,
      allow_tools: normalized.allowTools,
      deny_tools: normalized.denyTools,
      allow_actions: normalized.allowActions,
      deny_actions: normalized.denyActions,
    };
  }

  return {
    version: String(parsed.version || "v1"),
    defaults: {
      mode: defaults.mode,
      allow_tools: defaults.allowTools,
      deny_tools: defaults.denyTools,
      allow_actions: defaults.allowActions,
      deny_actions: defaults.denyActions,
    },
    channels,
  };
}

function verifyCatalogSignature(
  canonicalText: string,
  parsed: CapabilityCatalogFile,
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
        throw new Error("Capability catalog signature_v2 mismatch.");
      }
    } else {
      const legacySig = String(parsed.signature || "").trim().toLowerCase();
      if (!legacySig) {
        throw new Error("Capability catalog signature missing for keyring verification.");
      }
      const legacy = verifyWithAnyKey(canonicalText, legacySig, keyring);
      if (!legacy.valid) {
        throw new Error("Capability catalog legacy signature mismatch under keyring.");
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
    throw new Error("Capability catalog signature missing or invalid format.");
  }
  const expected = crypto
    .createHmac("sha256", signingKey.trim())
    .update(canonicalText)
    .digest("hex");
  if (signature !== expected) {
    throw new Error("Capability catalog signature mismatch.");
  }
  return {
    signing_mode: "static",
    keyring_active_kid: null,
    keyring_key_count: 0,
  };
}

export function loadSignedCapabilityCatalog(
  catalogPath: string,
  signingKey: string,
  signingKeyringPath = "",
): CapabilityCatalogLoadResult {
  const raw = fs.readFileSync(catalogPath, "utf8");
  const parsed = JSON.parse(raw) as CapabilityCatalogFile;
  const canonical = canonicalPayload(parsed);
  const canonicalText = stableStringify(canonical);
  const keyring = signingKeyringPath.trim() ? loadHmacKeyring(signingKeyringPath.trim()) : null;
  const signatureState = verifyCatalogSignature(canonicalText, parsed, signingKey, keyring);

  const defaults = normalizeRules(parsed.defaults);
  const channels: Record<string, CapabilityRules> = {};
  for (const [channelRaw, channelRules] of Object.entries(parsed.channels || {})) {
    const channel = String(channelRaw || "").trim().toLowerCase();
    if (!channel) {
      continue;
    }
    channels[channel] = normalizeRules(channelRules);
  }

  return {
    version: canonical.version,
    defaults,
    channels,
    fingerprint: crypto.createHash("sha256").update(canonicalText).digest("hex"),
    signing_mode: signatureState.signing_mode,
    keyring_active_kid: signatureState.keyring_active_kid,
    keyring_key_count: signatureState.keyring_key_count,
  };
}

function decisionFromRule(
  value: string,
  mode: CapabilityMode,
  allowSet: Set<string>,
  denySet: Set<string>,
  valueType: "tool" | "action",
): CapabilityDecision {
  const signals: string[] = [];
  if (denySet.has(value)) {
    signals.push(`${valueType}-deny:${value}`);
    return {
      allowed: false,
      reason: `${valueType} denied by capability policy.`,
      matchedSignals: signals,
    };
  }

  if (allowSet.size > 0) {
    if (allowSet.has(value)) {
      signals.push(`${valueType}-allow:${value}`);
      return {
        allowed: true,
        reason: `${valueType} allowed by capability allowlist.`,
        matchedSignals: signals,
      };
    }
    signals.push(`${valueType}-allow-miss:${value}`);
    return {
      allowed: false,
      reason: `${valueType} not present in capability allowlist.`,
      matchedSignals: signals,
    };
  }

  if (mode === "deny") {
    signals.push(`${valueType}-default-deny:${value}`);
    return {
      allowed: false,
      reason: `${valueType} denied by default-deny capability mode.`,
      matchedSignals: signals,
    };
  }

  signals.push(`${valueType}-default-allow:${value}`);
  return {
    allowed: true,
    reason: `${valueType} allowed by default capability mode.`,
    matchedSignals: signals,
  };
}

export class CapabilityPolicyEngine {
  private defaults: CapabilityRules = { ...DEFAULT_RULES };
  private channels = new Map<string, CapabilityRules>();
  private version = "v1";
  private fingerprint = "";
  private signingMode: "none" | "static" | "keyring" = "none";
  private keyringActiveKid: string | null = null;
  private keyringKeyCount = 0;

  updateRules(catalog: CapabilityCatalogLoadResult): void {
    this.version = catalog.version;
    this.defaults = { ...catalog.defaults };
    this.channels = new Map<string, CapabilityRules>(
      Object.entries(catalog.channels).map(([channel, rules]) => [channel, { ...rules }]),
    );
    this.fingerprint = catalog.fingerprint;
    this.signingMode = catalog.signing_mode;
    this.keyringActiveKid = catalog.keyring_active_kid;
    this.keyringKeyCount = catalog.keyring_key_count;
  }

  evaluateToolExecution(toolNames: string[], channelHint = ""): CapabilityDecision {
    const normalizedTools = normalizeList(toolNames);
    if (normalizedTools.length === 0) {
      return {
        allowed: true,
        reason: "No tool execution requested.",
        matchedSignals: [],
      };
    }
    const rules = this.resolveRules(channelHint);
    const actionDecision = decisionFromRule(
      "tool.execute",
      rules.mode,
      new Set(rules.allowActions),
      new Set(rules.denyActions),
      "action",
    );
    if (!actionDecision.allowed) {
      return {
        allowed: false,
        reason: actionDecision.reason,
        matchedSignals: actionDecision.matchedSignals,
      };
    }

    const allowTools = new Set(rules.allowTools);
    const denyTools = new Set(rules.denyTools);
    for (const tool of normalizedTools) {
      const decision = decisionFromRule(tool, rules.mode, allowTools, denyTools, "tool");
      if (!decision.allowed) {
        return {
          allowed: false,
          reason: decision.reason,
          matchedSignals: decision.matchedSignals,
        };
      }
    }
    return {
      allowed: true,
      reason: "Tool execution allowed by capability policy.",
      matchedSignals: normalizedTools.map((tool) => `tool-allowed:${tool}`),
    };
  }

  evaluateChannelAction(action: CapabilityAction, channel: string): CapabilityDecision {
    const normalizedChannel = String(channel || "").trim().toLowerCase();
    const rules = this.resolveRules(normalizedChannel);
    return decisionFromRule(
      action,
      rules.mode,
      new Set(rules.allowActions),
      new Set(rules.denyActions),
      "action",
    );
  }

  getState(): {
    version: string;
    fingerprint: string;
    channels_count: number;
    signing_mode: "none" | "static" | "keyring";
    keyring_active_kid: string | null;
    keyring_key_count: number;
  } {
    return {
      version: this.version,
      fingerprint: this.fingerprint,
      channels_count: this.channels.size,
      signing_mode: this.signingMode,
      keyring_active_kid: this.keyringActiveKid,
      keyring_key_count: this.keyringKeyCount,
    };
  }

  private resolveRules(channel: string): CapabilityRules {
    const normalizedChannel = String(channel || "").trim().toLowerCase();
    if (!normalizedChannel) {
      return { ...this.defaults };
    }
    return this.channels.get(normalizedChannel) || { ...this.defaults };
  }
}
