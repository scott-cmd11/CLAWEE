import type { ModelModality } from "./model-registry";
import type { ToolIntent } from "./inference-provider";

export type PolicyDecisionType = "allow" | "require_approval" | "block";

export interface PolicyInput {
  path: string;
  method: string;
  body: unknown;
  model: string;
  modality: ModelModality;
  intent: ToolIntent;
}

export interface PolicyDecision {
  decision: PolicyDecisionType;
  reason: string;
  riskClass: "low" | "medium" | "high" | "critical";
  matchedSignals: string[];
}

export interface PolicyEngineOptions {
  highRiskTools: string[];
  criticalPatterns: string[];
  highRiskPatterns: string[];
}

const DEFAULT_HIGH_RISK_TOOLS = [
  "execute_bash",
  "shell",
  "terminal",
  "write_file",
  "delete_file",
  "execute_sql",
  "run_sql",
  "database_query",
  "browser_control",
];

const DEFAULT_CRITICAL_PATTERNS = [
  "drop table",
  "truncate table",
  "rm -rf",
  "delete from",
  "format c:",
  "powershell -encodedcommand",
];

const DEFAULT_HIGH_RISK_PATTERNS = [
  "prod",
  "production",
  "secret",
  "token",
  "password",
  "api key",
  "exfiltrate",
  "export data",
];

function normalize(values: string[]): Set<string> {
  return new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean));
}

function toText(payload: unknown): string {
  try {
    return JSON.stringify(payload).toLowerCase();
  } catch {
    return "";
  }
}

export class PolicyEngine {
  private highRiskTools: Set<string>;
  private criticalPatterns: Set<string>;
  private highRiskPatterns: Set<string>;

  constructor(options?: Partial<PolicyEngineOptions>) {
    this.highRiskTools = new Set<string>();
    this.criticalPatterns = new Set<string>();
    this.highRiskPatterns = new Set<string>();
    this.updateRules(options);
  }

  updateRules(options?: Partial<PolicyEngineOptions>): void {
    this.highRiskTools = normalize(options?.highRiskTools || DEFAULT_HIGH_RISK_TOOLS);
    this.criticalPatterns = normalize(options?.criticalPatterns || DEFAULT_CRITICAL_PATTERNS);
    this.highRiskPatterns = normalize(options?.highRiskPatterns || DEFAULT_HIGH_RISK_PATTERNS);
  }

  evaluate(input: PolicyInput): PolicyDecision {
    const signals: string[] = [];
    const bodyText = toText(input.body);
    const lowerPath = input.path.toLowerCase();
    const lowerMethod = input.method.toLowerCase();

    for (const name of input.intent.toolNames) {
      const normalized = name.toLowerCase();
      if (this.highRiskTools.has(normalized)) {
        signals.push(`high-risk-tool:${normalized}`);
      }
    }

    for (const pattern of this.criticalPatterns) {
      if (bodyText.includes(pattern)) {
        signals.push(`critical-pattern:${pattern}`);
      }
    }

    for (const pattern of this.highRiskPatterns) {
      if (bodyText.includes(pattern)) {
        signals.push(`high-risk-pattern:${pattern}`);
      }
    }

    if ((lowerPath.includes("admin") || lowerPath.includes("system")) && lowerMethod !== "get") {
      signals.push("high-risk-path:admin-system");
    }

    if (input.modality === "audio" || input.modality === "vision") {
      signals.push(`modality:${input.modality}`);
    }

    const hasCritical = signals.some((signal) => signal.startsWith("critical-pattern"));
    const hasHighRisk = signals.some((signal) => signal.startsWith("high-risk"));

    if (hasCritical) {
      return {
        decision: "block",
        reason: "Critical destructive pattern detected.",
        riskClass: "critical",
        matchedSignals: signals,
      };
    }

    if (hasHighRisk) {
      return {
        decision: "require_approval",
        reason: "High-risk action requires approval.",
        riskClass: "high",
        matchedSignals: signals,
      };
    }

    return {
      decision: "allow",
      reason: "No high-risk policy signals detected.",
      riskClass: "low",
      matchedSignals: signals,
    };
  }
}
