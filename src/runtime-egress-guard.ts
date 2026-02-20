import dns from "node:dns/promises";
import net from "node:net";
import type { OutboundInternetPolicy } from "./config";

export interface RuntimeEgressTarget {
  name: string;
  url: string;
}

export interface RuntimeEgressGuardOptions {
  policy: OutboundInternetPolicy;
  allowlistedHosts: string[];
  revalidationIntervalMs: number;
  targets: RuntimeEgressTarget[];
}

export interface RuntimeEgressCheckResult {
  target: string;
  host: string;
  addresses: string[];
  allowed: boolean;
  reason: string;
  checked_at: string;
}

interface CacheEntry {
  checkedAtMs: number;
  result: RuntimeEgressCheckResult;
}

export class RuntimeEgressPolicyError extends Error {
  result: RuntimeEgressCheckResult;

  constructor(message: string, result: RuntimeEgressCheckResult) {
    super(message);
    this.name = "RuntimeEgressPolicyError";
    this.result = result;
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
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateIPv6(host: string): boolean {
  const value = host.toLowerCase();
  if (value === "::1") return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  if (value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb")) {
    return true;
  }
  return false;
}

function isPrivateIp(ip: string): boolean {
  if (net.isIP(ip) === 4) {
    return isPrivateIPv4(ip);
  }
  if (net.isIP(ip) === 6) {
    return isPrivateIPv6(ip);
  }
  return false;
}

export class RuntimeEgressGuard {
  private policy: OutboundInternetPolicy;
  private allowlist: Set<string>;
  private ttlMs: number;
  private targets = new Map<string, URL>();
  private cache = new Map<string, CacheEntry>();

  constructor(options: RuntimeEgressGuardOptions) {
    this.policy = options.policy;
    this.allowlist = new Set(options.allowlistedHosts.map((host) => normalizeHost(host)));
    this.ttlMs = Math.max(1000, options.revalidationIntervalMs);

    for (const target of options.targets) {
      this.targets.set(target.name, new URL(target.url));
    }
  }

  async assertAllowed(targetName: string): Promise<RuntimeEgressCheckResult> {
    const target = this.targets.get(targetName);
    if (!target) {
      throw new Error(`Unknown runtime egress target: ${targetName}`);
    }

    if (this.policy === "allow") {
      const result: RuntimeEgressCheckResult = {
        target: targetName,
        host: normalizeHost(target.hostname),
        addresses: [],
        allowed: true,
        reason: "Policy allows outbound internet.",
        checked_at: new Date().toISOString(),
      };
      return result;
    }

    const cached = this.cache.get(targetName);
    if (cached && Date.now() - cached.checkedAtMs <= this.ttlMs) {
      if (!cached.result.allowed) {
        throw new RuntimeEgressPolicyError("Runtime egress policy violation (cached).", cached.result);
      }
      return cached.result;
    }

    const result = await this.evaluateTarget(targetName, target);
    this.cache.set(targetName, {
      checkedAtMs: Date.now(),
      result,
    });

    if (!result.allowed) {
      throw new RuntimeEgressPolicyError("Runtime egress policy violation.", result);
    }
    return result;
  }

  async assertUrlAllowed(targetName: string, url: string): Promise<RuntimeEgressCheckResult> {
    const parsed = new URL(url);
    const cacheKey = `dynamic:${targetName}:${normalizeHost(parsed.hostname)}`;

    if (this.policy === "allow") {
      return {
        target: targetName,
        host: normalizeHost(parsed.hostname),
        addresses: [],
        allowed: true,
        reason: "Policy allows outbound internet.",
        checked_at: new Date().toISOString(),
      };
    }

    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.checkedAtMs <= this.ttlMs) {
      if (!cached.result.allowed) {
        throw new RuntimeEgressPolicyError("Runtime egress policy violation (cached).", cached.result);
      }
      return cached.result;
    }

    const result = await this.evaluateTarget(targetName, parsed);
    this.cache.set(cacheKey, {
      checkedAtMs: Date.now(),
      result,
    });

    if (!result.allowed) {
      throw new RuntimeEgressPolicyError("Runtime egress policy violation.", result);
    }
    return result;
  }

  private async evaluateTarget(targetName: string, target: URL): Promise<RuntimeEgressCheckResult> {
    const host = normalizeHost(target.hostname);
    const checkedAt = new Date().toISOString();

    if (this.allowlist.has(host)) {
      return {
        target: targetName,
        host,
        addresses: [host],
        allowed: true,
        reason: "Host is explicitly allowlisted.",
        checked_at: checkedAt,
      };
    }

    if (isLoopback(host)) {
      return {
        target: targetName,
        host,
        addresses: [host],
        allowed: true,
        reason: "Loopback host is allowed.",
        checked_at: checkedAt,
      };
    }

    const ipVersion = net.isIP(host);
    if (ipVersion > 0) {
      const allowed = isPrivateIp(host);
      return {
        target: targetName,
        host,
        addresses: [host],
        allowed,
        reason: allowed
          ? "Direct IP is private."
          : "Direct IP is internet-routable and not allowlisted.",
        checked_at: checkedAt,
      };
    }

    let records: Array<{ address: string; family: number }> = [];
    try {
      records = await dns.lookup(host, { all: true, verbatim: true });
    } catch (error) {
      return {
        target: targetName,
        host,
        addresses: [],
        allowed: false,
        reason: `DNS lookup failed: ${error instanceof Error ? error.message : String(error)}`,
        checked_at: checkedAt,
      };
    }

    const addresses = [...new Set(records.map((record) => record.address))];
    if (addresses.length === 0) {
      return {
        target: targetName,
        host,
        addresses,
        allowed: false,
        reason: "No resolved addresses returned by DNS.",
        checked_at: checkedAt,
      };
    }

    const allPrivate = addresses.every((ip) => isPrivateIp(ip));
    return {
      target: targetName,
      host,
      addresses,
      allowed: allPrivate,
      reason: allPrivate
        ? "All resolved addresses are private."
        : "Resolved address set includes internet-routable IPs.",
      checked_at: checkedAt,
    };
  }
}
