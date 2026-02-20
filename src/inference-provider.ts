import OpenAI from "openai";
import http from "node:http";

export interface ToolIntent {
  hasToolIntent: boolean;
  toolNames: string[];
}

export interface RiskEvaluation {
  confidence_score: number;
  reason: string;
  recommended_action: "allow" | "warn";
}

export interface RiskEvaluator {
  evaluateRisk(
    model: string,
    requestPath: string,
    method: string,
    payload: unknown,
    intent: ToolIntent,
  ): Promise<RiskEvaluation>;
}

const RISK_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["confidence_score", "reason", "recommended_action"],
  properties: {
    confidence_score: { type: "number", minimum: 0, maximum: 1 },
    reason: { type: "string" },
    recommended_action: { type: "string", enum: ["allow", "warn"] },
  },
} as const;

function normalizeRiskEvaluation(raw: unknown): RiskEvaluation {
  if (!raw || typeof raw !== "object") {
    throw new Error("Risk evaluator returned a non-object response.");
  }

  const obj = raw as Record<string, unknown>;
  const confidence = typeof obj.confidence_score === "number" ? obj.confidence_score : Number.NaN;
  const reason = typeof obj.reason === "string" ? obj.reason : "";
  const action = obj.recommended_action === "warn" ? "warn" : "allow";

  if (Number.isNaN(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("Risk evaluator returned an invalid confidence score.");
  }

  if (!reason) {
    throw new Error("Risk evaluator returned an empty reason.");
  }

  return {
    confidence_score: confidence,
    reason,
    recommended_action: action,
  };
}

export class InternalGatewayRiskEvaluator implements RiskEvaluator {
  private client: OpenAI;
  private preflight: (() => Promise<void>) | null;

  constructor(
    baseURL: string,
    apiKey: string,
    preflight?: () => Promise<void>,
    httpAgent?: http.Agent,
  ) {
    this.client = new OpenAI({
      baseURL,
      apiKey,
      httpAgent,
    });
    this.preflight = preflight || null;
  }

  async evaluateRisk(
    model: string,
    requestPath: string,
    method: string,
    payload: unknown,
    intent: ToolIntent,
  ): Promise<RiskEvaluation> {
    if (this.preflight) {
      await this.preflight();
    }

    const response = await this.client.responses.create({
      model,
      input: [
        {
          role: "system",
          content:
            "You are a strict enterprise action risk evaluator. Score operational certainty for a proposed tool request. Prefer lower scores when the intent is ambiguous, destructive, or lacks validation details.",
        },
        {
          role: "user",
          content: JSON.stringify({
            request_path: requestPath,
            method,
            detected_tool_intent: intent,
            payload,
          }),
        },
      ],
      text: {
        format: {
          type: "json_schema",
          name: "risk_evaluation",
          schema: RISK_SCHEMA,
          strict: true,
        },
      },
      max_output_tokens: 180,
    });

    if (!response.output_text || !response.output_text.trim()) {
      throw new Error("Risk evaluator returned empty output_text.");
    }

    const parsed = JSON.parse(response.output_text) as unknown;
    return normalizeRiskEvaluation(parsed);
  }
}
