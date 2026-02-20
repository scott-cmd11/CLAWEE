import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";

function parsePins(raw: string): Set<string> {
  if (!raw.trim()) {
    return new Set<string>();
  }
  return new Set(
    raw
      .split(",")
      .map((value) => value.trim().replace(/:/g, "").toLowerCase())
      .filter(Boolean),
  );
}

function optionalFile(pathValue: string): Buffer | undefined {
  const trimmed = pathValue.trim();
  if (!trimmed) {
    return undefined;
  }
  return fs.readFileSync(trimmed);
}

export interface TargetTransportConfig {
  targetName: string;
  targetUrl: string;
  enforceTls: boolean;
  tlsPinsSha256: string;
  caCertPath: string;
  clientCertPath: string;
  clientKeyPath: string;
}

export interface TransportAgents {
  upstreamAgent?: http.Agent;
  inferenceAgent?: http.Agent;
  summary: Array<{
    target: string;
    protocol: string;
    tls_enforced: boolean;
    pin_count: number;
    mtls_enabled: boolean;
  }>;
}

function buildAgent(config: TargetTransportConfig): { agent?: http.Agent; meta: TransportAgents["summary"][number] } {
  const url = new URL(config.targetUrl);
  const protocol = url.protocol.toLowerCase();
  const pins = parsePins(config.tlsPinsSha256);

  if (protocol === "http:") {
    if (config.enforceTls || pins.size > 0) {
      throw new Error(
        `${config.targetName}: TLS is required/pinned but target URL is plain HTTP (${config.targetUrl}).`,
      );
    }
    return {
      agent: new http.Agent({ keepAlive: true }),
      meta: {
        target: config.targetName,
        protocol,
        tls_enforced: false,
        pin_count: 0,
        mtls_enabled: false,
      },
    };
  }

  if (protocol !== "https:") {
    throw new Error(`${config.targetName}: unsupported protocol "${protocol}".`);
  }

  if (config.enforceTls && pins.size === 0) {
    throw new Error(
      `${config.targetName}: TLS enforcement requires at least one SHA256 pin in *_TLS_PIN_SHA256.`,
    );
  }

  const ca = optionalFile(config.caCertPath);
  const cert = optionalFile(config.clientCertPath);
  const key = optionalFile(config.clientKeyPath);
  const mtlsEnabled = Boolean(cert && key);

  if ((cert && !key) || (!cert && key)) {
    throw new Error(`${config.targetName}: both client cert and key are required for mTLS.`);
  }

  const agent = new https.Agent({
    keepAlive: true,
    rejectUnauthorized: true,
    ca,
    cert,
    key,
    checkServerIdentity: (hostname, certValue) => {
      const defaultValidation = tls.checkServerIdentity(hostname, certValue);
      if (defaultValidation) {
        return defaultValidation;
      }
      if (pins.size > 0) {
        const fingerprint = (certValue.fingerprint256 || "").replace(/:/g, "").toLowerCase();
        if (!pins.has(fingerprint)) {
          return new Error(
            `${config.targetName}: TLS pin mismatch for host "${hostname}". fingerprint256=${certValue.fingerprint256}`,
          );
        }
      }
      return undefined;
    },
  });

  return {
    agent,
    meta: {
      target: config.targetName,
      protocol,
      tls_enforced: config.enforceTls,
      pin_count: pins.size,
      mtls_enabled: mtlsEnabled,
    },
  };
}

export function buildTransportAgents(
  upstream: TargetTransportConfig,
  inference: TargetTransportConfig,
): TransportAgents {
  const upstreamBuilt = buildAgent(upstream);
  const inferenceBuilt = buildAgent(inference);
  return {
    upstreamAgent: upstreamBuilt.agent,
    inferenceAgent: inferenceBuilt.agent,
    summary: [upstreamBuilt.meta, inferenceBuilt.meta],
  };
}
