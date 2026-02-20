import crypto from "node:crypto";

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`);
  return `{${parts.join(",")}}`;
}

export function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

const SENSITIVE_KEY_PATTERNS = [
  "token",
  "secret",
  "password",
  "api_key",
  "apikey",
  "authorization",
  "cookie",
  "private_key",
];

function isSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  return SENSITIVE_KEY_PATTERNS.some((pattern) => lower.includes(pattern));
}

function redactString(value: string): string {
  if (value.length <= 6) {
    return "***";
  }
  return `${value.slice(0, 3)}***${value.slice(-2)}`;
}

export function redactSensitive(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === "string") {
    // Preserve short, low-risk strings; redact long bearer-like values.
    if (value.length > 24 && /[A-Za-z0-9_\-]{12,}/.test(value)) {
      return redactString(value);
    }
    return value;
  }

  if (typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitive(item));
  }

  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    if (isSensitiveKey(key)) {
      out[key] = typeof val === "string" ? redactString(val) : "***";
    } else {
      out[key] = redactSensitive(val);
    }
  }
  return out;
}
