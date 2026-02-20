import crypto from "node:crypto";
import fs from "node:fs";
import { stableStringify } from "./utils";

export interface ChannelConnectorConfig {
  webhook_url: string;
  auth_header?: string;
  timeout_ms?: number;
  hmac_secret?: string;
}

export interface ChannelConnectorCatalog {
  version?: string;
  default_timeout_ms?: number;
  channels: Record<string, ChannelConnectorConfig>;
  signature?: string;
}

export interface ChannelConnectorLoadResult {
  catalog: {
    default_timeout_ms: number;
    channels: Record<string, ChannelConnectorConfig>;
  };
  fingerprint: string;
  signed: boolean;
}

export function loadChannelConnectorCatalog(
  pathValue: string,
  signingKey: string,
): ChannelConnectorLoadResult {
  const raw = fs.readFileSync(pathValue, "utf8");
  const parsed = JSON.parse(raw) as ChannelConnectorCatalog;

  const canonicalPayload = {
    version: String(parsed.version || "v1"),
    default_timeout_ms: Number(parsed.default_timeout_ms || 10000),
    channels: parsed.channels || {},
  };

  const normalizedKey = signingKey.trim();
  if (normalizedKey) {
    const signature = String(parsed.signature || "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(signature)) {
      throw new Error("Connector catalog signature missing or invalid format.");
    }
    const expected = crypto
      .createHmac("sha256", normalizedKey)
      .update(stableStringify(canonicalPayload))
      .digest("hex");
    if (signature !== expected) {
      throw new Error("Connector catalog signature mismatch.");
    }
  }

  const fingerprint = crypto
    .createHash("sha256")
    .update(stableStringify(canonicalPayload))
    .digest("hex");

  return {
    catalog: {
      default_timeout_ms: canonicalPayload.default_timeout_ms,
      channels: canonicalPayload.channels,
    },
    fingerprint,
    signed: normalizedKey.length > 0,
  };
}
