import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { OutboundInternetPolicy } from "./config";

interface EndpointCheck {
  name: string;
  url: string;
  host: string;
  allowed: boolean;
  reason: string;
}

export interface AirgapPolicyInput {
  outboundInternetPolicy: OutboundInternetPolicy;
  allowedOutboundHosts: string[];
  airgapAttestationPath: string;
  endpoints: Array<{
    name: string;
    url: string;
  }>;
}

export interface AirgapAttestation {
  timestamp: string;
  host_id: string;
  outbound_policy: OutboundInternetPolicy;
  allowed_outbound_hosts: string[];
  policy_hash: string;
  endpoints: EndpointCheck[];
}

export class AirgapPolicyError extends Error {
  violations: EndpointCheck[];

  constructor(message: string, violations: EndpointCheck[]) {
    super(message);
    this.name = "AirgapPolicyError";
    this.violations = violations;
  }
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase();
}

function isLoopback(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function isPrivateIPv4(host: string): boolean {
  const parts = host.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return false;
  }

  const [a, b] = parts;
  if (a === 10) {
    return true;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  if (a === 169 && b === 254) {
    return true;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }
  return false;
}

function isPrivateIPv6(host: string): boolean {
  const value = host.toLowerCase();
  if (value === "::1") {
    return true;
  }
  if (value.startsWith("fc") || value.startsWith("fd")) {
    return true;
  }
  if (value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb")) {
    return true;
  }
  return false;
}

function isPrivateHostname(host: string): boolean {
  return (
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".corp") ||
    host.endsWith(".lan")
  );
}

function isPrivateOrInternalHost(host: string): boolean {
  if (isLoopback(host)) {
    return true;
  }
  if (isPrivateIPv4(host) || isPrivateIPv6(host)) {
    return true;
  }
  if (isPrivateHostname(host)) {
    return true;
  }
  return false;
}

function evaluateEndpoint(
  endpoint: { name: string; url: string },
  policy: OutboundInternetPolicy,
  allowlist: Set<string>,
): EndpointCheck {
  const parsed = new URL(endpoint.url);
  const host = normalizeHost(parsed.hostname);

  if (policy === "allow") {
    return {
      name: endpoint.name,
      url: endpoint.url,
      host,
      allowed: true,
      reason: "Outbound internet policy allows all configured destinations.",
    };
  }

  if (allowlist.has(host)) {
    return {
      name: endpoint.name,
      url: endpoint.url,
      host,
      allowed: true,
      reason: "Host is explicitly allowlisted.",
    };
  }

  if (isPrivateOrInternalHost(host)) {
    return {
      name: endpoint.name,
      url: endpoint.url,
      host,
      allowed: true,
      reason: "Host is private/internal.",
    };
  }

  return {
    name: endpoint.name,
    url: endpoint.url,
    host,
    allowed: false,
    reason: "Host appears internet-routable and is not allowlisted under deny policy.",
  };
}

function computePolicyHash(attestation: Omit<AirgapAttestation, "policy_hash">): string {
  const payload = JSON.stringify(attestation);
  return crypto.createHash("sha256").update(payload).digest("hex");
}

export function enforceAndAttestAirgapPolicy(input: AirgapPolicyInput): AirgapAttestation {
  const allowlist = new Set(input.allowedOutboundHosts.map((host) => normalizeHost(host)));
  const endpoints = input.endpoints.map((endpoint) =>
    evaluateEndpoint(endpoint, input.outboundInternetPolicy, allowlist),
  );
  const violations = endpoints.filter((endpoint) => !endpoint.allowed);

  const baseAttestation: Omit<AirgapAttestation, "policy_hash"> = {
    timestamp: new Date().toISOString(),
    host_id: os.hostname(),
    outbound_policy: input.outboundInternetPolicy,
    allowed_outbound_hosts: [...allowlist].sort(),
    endpoints,
  };

  const attestation: AirgapAttestation = {
    ...baseAttestation,
    policy_hash: computePolicyHash(baseAttestation),
  };

  fs.mkdirSync(path.dirname(input.airgapAttestationPath), { recursive: true });
  fs.writeFileSync(input.airgapAttestationPath, JSON.stringify(attestation, null, 2), "utf8");

  if (violations.length > 0) {
    throw new AirgapPolicyError(
      `Air-gap policy violation detected for ${violations.length} endpoint(s).`,
      violations,
    );
  }

  return attestation;
}
