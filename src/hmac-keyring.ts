import crypto from "node:crypto";
import fs from "node:fs";

export interface HmacKeyring {
  activeKid: string;
  keys: Record<string, string>;
}

interface HmacKeyringFile {
  version?: string;
  active_kid?: string;
  keys?: Record<string, string>;
}

export interface HmacSignatureV2 {
  kid: string;
  sig: string;
}

export function hmacSha256Hex(secret: string, payload: string): string {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function normalizeHex(value: string): string {
  return value.trim().toLowerCase();
}

function constantTimeHexEquals(aHex: string, bHex: string): boolean {
  const a = normalizeHex(aHex);
  const b = normalizeHex(bHex);
  if (a.length !== b.length || a.length === 0 || a.length % 2 !== 0) {
    return false;
  }
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length !== right.length || left.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

export function loadHmacKeyring(pathValue: string): HmacKeyring {
  const raw = fs.readFileSync(pathValue, "utf8");
  const parsed = JSON.parse(raw) as HmacKeyringFile;
  const keysInput = parsed.keys || {};
  const keys: Record<string, string> = {};
  for (const [kidRaw, keyRaw] of Object.entries(keysInput)) {
    const kid = String(kidRaw).trim();
    const key = String(keyRaw || "").trim();
    if (!kid || !key) {
      continue;
    }
    keys[kid] = key;
  }
  const activeKid = String(parsed.active_kid || "").trim();
  if (!activeKid) {
    throw new Error("HMAC keyring missing active_kid.");
  }
  if (!keys[activeKid]) {
    throw new Error(`HMAC keyring active_kid "${activeKid}" not found in keys.`);
  }
  return {
    activeKid,
    keys,
  };
}

export function signWithKeyring(payloadCanonical: string, keyring: HmacKeyring): HmacSignatureV2 {
  const secret = keyring.keys[keyring.activeKid];
  return {
    kid: keyring.activeKid,
    sig: hmacSha256Hex(secret, payloadCanonical),
  };
}

export function verifyWithKeyring(
  payloadCanonical: string,
  signature: HmacSignatureV2,
  keyring: HmacKeyring,
): boolean {
  const kid = String(signature.kid || "").trim();
  const sig = String(signature.sig || "").trim().toLowerCase();
  if (!kid || !/^[a-f0-9]{64}$/.test(sig)) {
    return false;
  }
  const secret = keyring.keys[kid];
  if (!secret) {
    return false;
  }
  const expected = hmacSha256Hex(secret, payloadCanonical);
  return constantTimeHexEquals(expected, sig);
}

export function verifyWithAnyKey(
  payloadCanonical: string,
  signatureHex: string,
  keyring: HmacKeyring,
): { valid: boolean; kid: string | null } {
  const sig = String(signatureHex || "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(sig)) {
    return { valid: false, kid: null };
  }
  for (const [kid, secret] of Object.entries(keyring.keys)) {
    const expected = hmacSha256Hex(secret, payloadCanonical);
    if (constantTimeHexEquals(expected, sig)) {
      return { valid: true, kid };
    }
  }
  return { valid: false, kid: null };
}
