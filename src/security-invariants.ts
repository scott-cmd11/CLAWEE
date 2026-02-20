import { sha256Hex, stableStringify } from "./utils";

export interface SecurityInvariantDefinition {
  id: string;
  title: string;
  description: string;
  severity: "high" | "critical";
}

export interface SecurityInvariantRuntimeState extends SecurityInvariantDefinition {
  passes: number;
  failures: number;
  last_status: "pass" | "fail" | "unknown";
  last_checked_at: string | null;
  last_failure_reason: string | null;
  last_failure_context: Record<string, unknown> | null;
}

export interface SecurityInvariantCheckInput {
  id: string;
  passed: boolean;
  reason?: string;
  context?: Record<string, unknown>;
}

export interface SecurityInvariantSummary {
  total: number;
  passing: number;
  failing: number;
  unknown: number;
  last_updated_at: string | null;
}

const DEFAULT_INVARIANTS: SecurityInvariantDefinition[] = [
  {
    id: "INV-001-RUNTIME-EGRESS-GATE",
    title: "Runtime Egress Gate",
    description: "Outbound request forwarding must pass runtime egress policy checks.",
    severity: "critical",
  },
  {
    id: "INV-002-CAPABILITY-GATE",
    title: "Capability Gate",
    description: "Tool and channel actions must pass capability policy before execution.",
    severity: "critical",
  },
  {
    id: "INV-003-POLICY-GATE",
    title: "Policy Gate",
    description: "High-risk actions must be evaluated by policy engine before forwarding.",
    severity: "critical",
  },
  {
    id: "INV-004-APPROVAL-GATE",
    title: "Approval Gate",
    description: "Actions requiring approval must be blocked until quorum and token checks pass.",
    severity: "critical",
  },
  {
    id: "INV-005-BUDGET-GATE",
    title: "Budget Gate",
    description: "Forwarding must be blocked when compute budget suspension is active.",
    severity: "high",
  },
  {
    id: "INV-006-MODEL-REGISTRY-GATE",
    title: "Model Registry Gate",
    description: "Requests must use approved model/modality combinations.",
    severity: "critical",
  },
  {
    id: "INV-007-CHANNEL-DESTINATION-GATE",
    title: "Channel Destination Gate",
    description: "Outbound channel destinations must pass destination policy.",
    severity: "high",
  },
  {
    id: "INV-008-INGRESS-AUTH-GATE",
    title: "Ingress Auth Gate",
    description: "Ingress signature/replay controls must gate accepted inbound channel traffic.",
    severity: "high",
  },
];

export class SecurityInvariantRegistry {
  private readonly definitions: Map<string, SecurityInvariantDefinition>;
  private readonly states: Map<string, SecurityInvariantRuntimeState>;
  private lastUpdatedAt: string | null = null;

  constructor(definitions = DEFAULT_INVARIANTS) {
    this.definitions = new Map(definitions.map((entry) => [entry.id, entry]));
    this.states = new Map(
      definitions.map((entry) => [
        entry.id,
        {
          ...entry,
          passes: 0,
          failures: 0,
          last_status: "unknown",
          last_checked_at: null,
          last_failure_reason: null,
          last_failure_context: null,
        },
      ]),
    );
  }

  check(input: SecurityInvariantCheckInput): SecurityInvariantRuntimeState {
    const state = this.states.get(input.id);
    if (!state) {
      throw new Error(`Unknown security invariant id: ${input.id}`);
    }
    const now = new Date().toISOString();
    if (input.passed) {
      state.passes += 1;
      state.last_status = "pass";
      state.last_checked_at = now;
    } else {
      state.failures += 1;
      state.last_status = "fail";
      state.last_checked_at = now;
      state.last_failure_reason = input.reason || "unspecified";
      state.last_failure_context = input.context || null;
    }
    this.lastUpdatedAt = now;
    return { ...state };
  }

  list(): SecurityInvariantRuntimeState[] {
    return [...this.states.values()].map((entry) => ({ ...entry }));
  }

  summary(): SecurityInvariantSummary {
    const states = this.list();
    let passing = 0;
    let failing = 0;
    let unknown = 0;
    for (const state of states) {
      if (state.last_status === "pass") {
        passing += 1;
      } else if (state.last_status === "fail") {
        failing += 1;
      } else {
        unknown += 1;
      }
    }
    return {
      total: states.length,
      passing,
      failing,
      unknown,
      last_updated_at: this.lastUpdatedAt,
    };
  }

  definitionHash(): string {
    const catalog = [...this.definitions.values()].sort((a, b) => a.id.localeCompare(b.id));
    return sha256Hex(stableStringify(catalog));
  }
}

export function defaultSecurityInvariants(): SecurityInvariantDefinition[] {
  return DEFAULT_INVARIANTS.map((entry) => ({ ...entry }));
}
