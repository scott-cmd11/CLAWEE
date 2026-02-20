import crypto from "node:crypto";
import fs from "node:fs";
import { stableStringify } from "./utils";

type DestinationMode = "allow" | "deny";

interface DestinationRuleFile {
  mode?: DestinationMode;
  allow_patterns?: string[];
  deny_patterns?: string[];
}

interface DestinationRuleNormalized {
  mode: DestinationMode;
  allow_patterns: string[];
  deny_patterns: string[];
}

interface DestinationRuleCompiled extends DestinationRuleNormalized {
  allow_regex: RegExp[];
  deny_regex: RegExp[];
}

interface DestinationPolicyFile {
  version?: string;
  defaults?: DestinationRuleFile;
  channels?: Record<string, DestinationRuleFile>;
  signature?: string;
}

export interface DestinationPolicyEvaluation {
  allowed: boolean;
  reason: string;
  matched_pattern: string | null;
  source: string;
}

export interface DestinationPolicyState {
  fingerprint: string;
  signed: boolean;
  version: string;
}

function normalizePatterns(values: string[] | undefined): string[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return values.map((value) => String(value).trim()).filter(Boolean);
}

function normalizeRule(input: DestinationRuleFile | undefined): DestinationRuleNormalized {
  return {
    mode: input?.mode === "deny" ? "deny" : "allow",
    allow_patterns: normalizePatterns(input?.allow_patterns),
    deny_patterns: normalizePatterns(input?.deny_patterns),
  };
}

function compilePatterns(patterns: string[]): RegExp[] {
  return patterns.map((pattern) => {
    try {
      return new RegExp(pattern);
    } catch (error) {
      throw new Error(
        `Invalid destination policy regex pattern "${pattern}": ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  });
}

function compileRule(rule: DestinationRuleNormalized): DestinationRuleCompiled {
  return {
    ...rule,
    allow_regex: compilePatterns(rule.allow_patterns),
    deny_regex: compilePatterns(rule.deny_patterns),
  };
}

interface LoadedPolicy {
  state: DestinationPolicyState;
  defaults: DestinationRuleCompiled;
  channels: Record<string, DestinationRuleCompiled>;
}

function loadPolicy(pathValue: string, signingKey: string): LoadedPolicy {
  const raw = fs.readFileSync(pathValue, "utf8");
  const parsed = JSON.parse(raw) as DestinationPolicyFile;
  const canonical = {
    version: String(parsed.version || "v1"),
    defaults: normalizeRule(parsed.defaults),
    channels: Object.fromEntries(
      Object.entries(parsed.channels || {}).map(([channel, rule]) => [channel.trim().toLowerCase(), normalizeRule(rule)]),
    ),
  };

  const normalizedSigningKey = signingKey.trim();
  if (normalizedSigningKey) {
    const signature = String(parsed.signature || "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(signature)) {
      throw new Error("Destination policy signature missing or invalid format.");
    }
    const expected = crypto
      .createHmac("sha256", normalizedSigningKey)
      .update(stableStringify(canonical))
      .digest("hex");
    if (signature !== expected) {
      throw new Error("Destination policy signature mismatch.");
    }
  }

  const fingerprint = crypto.createHash("sha256").update(stableStringify(canonical)).digest("hex");
  const channels: Record<string, DestinationRuleCompiled> = {};
  for (const [channel, rule] of Object.entries(canonical.channels)) {
    channels[channel] = compileRule(rule);
  }

  return {
    state: {
      fingerprint,
      signed: normalizedSigningKey.length > 0,
      version: canonical.version,
    },
    defaults: compileRule(canonical.defaults),
    channels,
  };
}

function matchAny(regexes: RegExp[], value: string, patterns: string[]): string | null {
  for (let i = 0; i < regexes.length; i += 1) {
    if (regexes[i].test(value)) {
      return patterns[i] || null;
    }
  }
  return null;
}

export class ChannelDestinationPolicy {
  private policyPath: string;
  private signingKey: string;
  private defaults: DestinationRuleCompiled = compileRule(normalizeRule(undefined));
  private channels: Record<string, DestinationRuleCompiled> = {};
  private state: DestinationPolicyState = {
    fingerprint: "",
    signed: false,
    version: "v1",
  };

  constructor(policyPath: string, signingKey: string) {
    this.policyPath = policyPath;
    this.signingKey = signingKey;
  }

  reload(): DestinationPolicyState {
    const loaded = loadPolicy(this.policyPath, this.signingKey);
    this.defaults = loaded.defaults;
    this.channels = loaded.channels;
    this.state = loaded.state;
    return this.getState();
  }

  getState(): DestinationPolicyState {
    return { ...this.state };
  }

  evaluate(channel: string, destination: string): DestinationPolicyEvaluation {
    const normalizedChannel = channel.trim().toLowerCase();
    const rule = this.channels[normalizedChannel] || this.defaults;
    const source = this.channels[normalizedChannel] ? `channel:${normalizedChannel}` : "defaults";
    const destinationValue = destination.trim();

    const denyMatch = matchAny(rule.deny_regex, destinationValue, rule.deny_patterns);
    if (denyMatch) {
      return {
        allowed: false,
        reason: "Destination denied by explicit deny pattern.",
        matched_pattern: denyMatch,
        source,
      };
    }

    const allowMatch = matchAny(rule.allow_regex, destinationValue, rule.allow_patterns);
    if (rule.mode === "deny") {
      if (!allowMatch) {
        return {
          allowed: false,
          reason: "Destination denied by default-deny policy.",
          matched_pattern: null,
          source,
        };
      }
      return {
        allowed: true,
        reason: "Destination allowlisted under default-deny policy.",
        matched_pattern: allowMatch,
        source,
      };
    }

    if (rule.allow_patterns.length > 0 && !allowMatch) {
      return {
        allowed: false,
        reason: "Destination not in allowlist for channel.",
        matched_pattern: null,
        source,
      };
    }

    return {
      allowed: true,
      reason: allowMatch
        ? "Destination matched allow pattern."
        : "Destination allowed by default-allow policy.",
      matched_pattern: allowMatch,
      source,
    };
  }
}
